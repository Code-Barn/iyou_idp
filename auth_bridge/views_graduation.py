# Copyright (C) 2026 David Byers dba Byers Brands
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Identity Graduation protocol: atomic export-and-shred of managed Ed25519
key material, transitioning Level 1 Managed identities to Level 2/3
Sovereign custody.

Export  — POST /api/v1/identity/graduate/export/
Confirm — POST /api/v1/identity/graduate/confirm/
"""

import binascii
import json
import logging
import os
import time
from typing import Any

from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .vault_client import delete_identity_key, read_identity_key

logger = logging.getLogger(__name__)

HKDF_INFO = b"iyou-idp/graduation-export/v1"
RECEIPT_MAX_AGE_SECONDS = 600
GRADUATION_ACTION = "graduate"
X25519_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


class GraduationProtocolError(ValueError):
    pass


def _decode_material(raw: Any, expected_size: int) -> bytes:
    """
    Decode client-supplied binary key material accepted as hex, base64 or
    base64url, enforcing an exact byte length.
    """
    if not isinstance(raw, str):
        raise GraduationProtocolError("malformed_key_material")
    try:
        try:
            decoded = binascii.unhexlify(raw)
        except (binascii.Error, ValueError):
            stripped = raw.replace("-", "+").replace("_", "/")
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = binascii.a2b_base64(padded)
    except (binascii.Error, ValueError):
        raise GraduationProtocolError("malformed_key_material")
    if len(decoded) != expected_size:
        raise GraduationProtocolError("malformed_key_material")
    return decoded


def _canonical_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_vault_keypair(custodial_did: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    data = read_identity_key(custodial_did)
    private_pem = data.get("private_key_pem")
    if not isinstance(private_pem, (str, bytes)):
        raise KeyError("private_key_pem")
    if isinstance(private_pem, str):
        private_pem = private_pem.encode("utf-8")
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("vault_private_key_not_ed25519")
    return private_key, private_key.public_key()


@require_POST
@csrf_protect
def graduate_export(request: HttpRequest) -> HttpResponse:
    """
    Export the managed Ed25519 private key seed, sealed to a client-supplied
    short-lived X25519 ephemeral public key so plaintext never crosses the
    transit boundary.
    """
    if not request.user.is_authenticated:
        return _error("authentication_required", 401)
    if request.user.is_sovereign:
        return _error("already_sovereign", 400)

    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return _error("malformed_json", 400)

    try:
        peer_public_bytes = _decode_material(
            payload.get("ephemeral_pubkey"), X25519_KEY_SIZE
        )
    except GraduationProtocolError as exc:
        return _error(str(exc), 400)

    custodial_did = request.user.custodial_did
    try:
        private_key, _ = _load_vault_keypair(custodial_did)
    except KeyError:
        return _error("managed_key_not_found", 404)
    except Exception:
        logger.exception("VAULT READ FAILED during graduation export did=%s", custodial_did)
        return _error("vault_unavailable", 502)

    server_ephemeral = X25519PrivateKey.generate()
    shared_secret = server_ephemeral.exchange(
        X25519PublicKey.from_public_bytes(peer_public_bytes)
    )
    nonce = os.urandom(12)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=HKDF_INFO,
    ).derive(shared_secret)
    ciphertext = AESGCM(wrapping_key).encrypt(
        nonce, private_key.private_bytes_raw(), custodial_did.encode("utf-8")
    )

    logger.info(
        "GRADUATION EXPORT: did=%s sealed key for transit did=%s",
        custodial_did,
        custodial_did,
    )
    return JsonResponse({
        "server_ephemeral_pub": binascii.hexlify(
            server_ephemeral.public_key().public_bytes_raw()
        ).decode("ascii"),
        "nonce": binascii.hexlify(nonce).decode("ascii"),
        "ciphertext": binascii.hexlify(ciphertext).decode("ascii"),
    })


@require_POST
@csrf_protect
def graduate_confirm(request: HttpRequest) -> HttpResponse:
    """
    Verify an Ed25519-signed graduation receipt produced by the newly
    exported local identity, then atomically promote the user to sovereign
    status and shred the managed key block in Vault.

    Vault deletion executes INSIDE the transaction: any Vault failure rolls
    the promotion back, preserving L1 Managed state.
    """
    if not request.user.is_authenticated:
        return _error("authentication_required", 401)
    if request.user.is_sovereign:
        return _error("already_sovereign", 400)

    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return _error("malformed_json", 400)

    receipt = payload.get("receipt")
    signature_hex = payload.get("signature")
    if not isinstance(receipt, dict) or not isinstance(signature_hex, str):
        return _error("malformed_payload", 400)

    user = request.user
    if receipt.get("did") != user.custodial_did:
        return _error("receipt_did_mismatch", 400)
    if receipt.get("action") != GRADUATION_ACTION:
        return _error("receipt_action_invalid", 400)

    issued_at = receipt.get("issued_at")
    if not isinstance(issued_at, (int, float)) or isinstance(issued_at, bool):
        return _error("receipt_timestamp_missing", 400)
    if abs(time.time() - float(issued_at)) > RECEIPT_MAX_AGE_SECONDS:
        return _error("receipt_expired", 400)

    try:
        signature = _decode_material(signature_hex, ED25519_SIGNATURE_SIZE)
    except GraduationProtocolError as exc:
        return _error(str(exc), 400)

    custodial_did = user.custodial_did
    try:
        _, vault_public_key = _load_vault_keypair(custodial_did)
    except KeyError:
        return _error("managed_key_not_found", 404)
    except Exception:
        logger.exception("VAULT READ FAILED during graduation confirm did=%s", custodial_did)
        return _error("vault_unavailable", 502)

    message = _canonical_receipt_bytes(receipt)
    try:
        vault_public_key.verify(signature, message)
    except InvalidSignature:
        logger.warning(
            "GRADUATION REJECTED: invalid receipt signature did=%s", custodial_did
        )
        return _error("invalid_receipt_signature", 400)

    try:
        with transaction.atomic():
            user.is_sovereign = True
            user.account_tier = "sovereign"
            user.save(update_fields=["is_sovereign", "account_tier", "updated_at"])
            delete_identity_key(custodial_did)
    except Exception:
        logger.exception(
            "VAULT SHRED FAILED — rolled back graduation did=%s", custodial_did
        )
        return _error("vault_shred_failed", 502)

    logger.info("GRADUATION COMPLETE: did=%s promoted to sovereign", custodial_did)
    return JsonResponse({
        "status": "graduated",
        "did": custodial_did,
        "is_sovereign": True,
    })


def _error(error: str, status: int) -> HttpResponse:
    return JsonResponse({"error": error}, status=status)
