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
RFC-002 Invite Capability Token verification for the Sovereign Airlock.

Byte-for-byte counterpart of the iyou_home minter
(`src-tauri/src/invites.rs`, RFC-002 §5.1). The scheme is:

1. Canonical payload: a JSON object over the ten signed fields with
   alphabetically sorted keys and no insignificant whitespace. The
   ``signature`` field is never part of it.
2. Digest: ``SHA-256`` of the canonical payload bytes.
3. Signature: Ed25519 over the 32-byte digest, base58-encoded (an optional
   multibase ``z`` prefix is tolerated).
4. Issuer key: ``did:key:z6Mk...`` — base58btc multibase carrying the Ed25519
   multicodec ``0xed01`` over a 34-byte body.

Admission order mirrors the node-side gate: schema → expiry → signature →
authorization → quota. Every failure raises :class:`InviteTokenError` carrying
the RFC-002 denial code, and the view surfaces a human-readable message.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import time
from typing import Any

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from django.conf import settings as django_settings

from .resilient_cache import cache as shared_cache

logger = logging.getLogger(__name__)

RFC002_TOKEN_VERSION = 1
RFC002_MAX_USES_PER_TOKEN = 4
RFC002_MAX_VALIDITY_SECONDS = 90 * 86_400
RFC002_NONCE_MIN_HEX_CHARS = 32
RFC002_VALID_TIERS = ("admin", "member", "guest")
RFC002_ADMISSIBLE_TIERS = ("admin", "member")

RFC002_SIGNED_FIELDS = (
    "v",
    "issuer_did",
    "satellite_id",
    "nonce",
    "max_uses",
    "uses_count",
    "tier",
    "created_at",
    "expires_at",
    "scope",
)

USES_CACHE_PREFIX = "airlock:nonce"


class InviteTokenError(Exception):
    """RFC-002 validation failure carrying the wire denial code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def uses_cache_key(nonce: str) -> str:
    return f"{USES_CACHE_PREFIX}:{nonce}:uses"


def _b64url_decode(raw: str) -> bytes | None:
    padded = raw + "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def _decode_token_object(blob: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or "signature" not in payload:
        return None
    return payload


def parse_token_input(raw: str) -> dict[str, Any] | None:
    """
    Decode an invite submission into a token object, or ``None`` if it is not
    an RFC-002 envelope at all (i.e. it is a legacy static invite key).

    Accepts a raw JSON object, a Base64URL-encoded JSON object (query
    parameters cannot carry raw JSON safely), or a Base58-wrapped JSON blob as
    emitted by the iyou_home QR encoder. Base58 and Base64URL share an
    alphabet, so every plausible decoding is tried and the first that yields a
    signed envelope wins.
    """
    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if not candidate:
        return None

    blobs: list[bytes] = []
    if candidate.startswith("{"):
        blobs.append(candidate.encode("utf-8"))
    else:
        b64 = _b64url_decode(candidate)
        if b64 is not None:
            blobs.append(b64)
        try:
            blobs.append(base58.b58decode(candidate))
        except Exception:
            pass

    for blob in blobs:
        payload = _decode_token_object(blob)
        if payload is not None:
            return payload
    return None


def is_cryptographic_invite(raw: str) -> bool:
    """True when *raw* is an RFC-002 capability token rather than a static key."""
    return parse_token_input(raw) is not None


def canonical_payload(token: dict[str, Any]) -> bytes:
    """
    Serialize the ten signed fields with sorted keys and no whitespace.

    ``satellite_id`` defaults to the empty string, which is how the minter
    encodes a portable token, so a consumer that omits the field still
    reproduces the exact bytes that were signed.
    """
    canonical = {field: token.get(field, "" if field == "satellite_id" else None) for field in RFC002_SIGNED_FIELDS}
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def token_digest(token: dict[str, Any]) -> bytes:
    return hashlib.sha256(canonical_payload(token)).digest()


def ed25519_pubkey_from_did(did: str) -> bytes | None:
    """Extract the raw 32-byte Ed25519 public key from a ``did:key:z6Mk...`` URI."""
    if not did or not isinstance(did, str) or not did.startswith("did:key:"):
        return None
    multibase = did[len("did:key:"):]
    if not multibase.startswith("z"):
        return None
    try:
        decoded = base58.b58decode(multibase[1:])
    except Exception:
        return None
    if len(decoded) == 34 and decoded[0] == 0xED and decoded[1] == 0x01:
        return decoded[2:]
    return None


def _decode_signature(signature: str) -> bytes:
    trimmed = signature.strip()
    b58 = trimmed[1:] if trimmed.startswith("z") else trimmed
    try:
        raw = base58.b58decode(b58)
    except Exception:
        raise InviteTokenError("INVITE_INVALID", "Signature is not valid base58")
    if len(raw) != 64:
        raise InviteTokenError("INVITE_INVALID", f"Signature must be 64 bytes (got {len(raw)})")
    return raw


def verify_token_signature(token: dict[str, Any]) -> None:
    """Verify the issuer's Ed25519 signature over ``SHA-256(canonical payload)``."""
    signature = token.get("signature")
    if not signature or not isinstance(signature, str):
        raise InviteTokenError("INVITE_INVALID", "Token is missing its signature")

    issuer_did = token.get("issuer_did")
    pubkey_bytes = ed25519_pubkey_from_did(issuer_did)
    if pubkey_bytes is None:
        raise InviteTokenError("INVITE_INVALID", "issuer_did is not an Ed25519 did:key URI")

    try:
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(
            _decode_signature(signature),
            token_digest(token),
        )
    except InvalidSignature:
        raise InviteTokenError("INVITE_INVALID", "Signature verification failed")
    except ValueError as e:
        raise InviteTokenError("INVITE_INVALID", f"Invalid issuer public key: {e}")


def validate_schema(token: dict[str, Any]) -> None:
    """Fail closed on any deviation from the RFC-002 §5.1 schema."""
    if token.get("v") != RFC002_TOKEN_VERSION:
        raise InviteTokenError("INVITE_INVALID", f"Unsupported token version {token.get('v')!r}")

    issuer_did = token.get("issuer_did")
    if not issuer_did or not isinstance(issuer_did, str) or ed25519_pubkey_from_did(issuer_did) is None:
        raise InviteTokenError("INVITE_INVALID", "Token is missing a usable issuer_did")

    nonce = token.get("nonce")
    if (
        not nonce
        or not isinstance(nonce, str)
        or len(nonce) < RFC002_NONCE_MIN_HEX_CHARS
        or not all(c in "0123456789abcdefABCDEF" for c in nonce)
    ):
        raise InviteTokenError("INVITE_INVALID", "Nonce must be >= 16 hex bytes (32 hex chars)")

    max_uses = token.get("max_uses")
    if not isinstance(max_uses, int) or isinstance(max_uses, bool) or not 1 <= max_uses <= RFC002_MAX_USES_PER_TOKEN:
        raise InviteTokenError("INVITE_INVALID", f"max_uses must be an integer in [1, {RFC002_MAX_USES_PER_TOKEN}]")

    tier = token.get("tier")
    if tier not in RFC002_VALID_TIERS:
        raise InviteTokenError("INVITE_INVALID", f"Unknown token tier {tier!r}")

    scope = token.get("scope")
    if not isinstance(scope, list) or not all(isinstance(item, str) for item in scope):
        raise InviteTokenError("INVITE_INVALID", "scope must be a list of strings")

    for numeric in ("created_at", "expires_at", "uses_count"):
        value = token.get(numeric)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise InviteTokenError("INVITE_INVALID", f"{numeric} must be a non-negative unix integer")

    if not token.get("signature"):
        raise InviteTokenError("INVITE_INVALID", "Token is missing its signature")

    if token["expires_at"] - token["created_at"] > RFC002_MAX_VALIDITY_SECONDS:
        raise InviteTokenError("INVITE_INVALID", "Token lifetime exceeds the 90 day ceiling")


def validate_expiry(token: dict[str, Any], now: int) -> None:
    if token["expires_at"] <= now:
        raise InviteTokenError("INVITE_EXPIRED", "Token has expired")


def validate_authorization(token: dict[str, Any]) -> None:
    """
    The issuer must be the operator DID or an issuer the operator has
    explicitly delegated invite issuance to. Signature verification already
    proved the issuer holds the key behind the DID, so allowlisting is a
    statement of trust in that key, not a claim of identity.
    """
    issuer_did = token["issuer_did"]
    if issuer_did == getattr(django_settings, "ADMIN_DID", ""):
        return
    allowlist = set(getattr(django_settings, "BETA_ACCESS_ALLOWLIST", []) or [])
    if issuer_did in allowlist:
        return
    raise InviteTokenError("INVITE_UNAUTHORIZED", "Token issuer is not authorized to admit to this instance")


def consume_use(token: dict[str, Any], cache=None) -> int:
    """
    Atomically claim one use from the token's budget.

    The counter is seeded from the issuer-declared ``uses_count`` so a token
    already partly spent at mint time cannot be replayed into a fresh full
    budget here. The counter only needs to outlive the token itself, so it
    expires with the token rather than leaking a permanent key.
    """
    backend = cache if cache is not None else shared_cache
    key = uses_cache_key(token["nonce"])
    cap = token["max_uses"]
    floor = max(int(token.get("uses_count", 0)), 0)
    ttl = max(int(token["expires_at"]) - int(time.time()), 60)

    count = backend.claim_unit(key, initial=floor, timeout=ttl)
    if count is None:
        raise InviteTokenError("INVITE_USED", "Token use could not be recorded")
    if count > cap:
        logger.warning("SYSTEM GATE: invite nonce %s exhausted its budget (%s > %s)", token["nonce"], count, cap)
        raise InviteTokenError("INVITE_USED", "Token has exhausted its use budget")
    return count


def verify_invite_token(raw: str, cache=None) -> dict[str, Any]:
    """
    Full RFC-002 admission check for a raw invite submission.

    Returns the verified token object. Raises :class:`InviteTokenError` for
    every failure mode, including an unrecognized input shape.
    """
    token = parse_token_input(raw)
    if token is None:
        raise InviteTokenError("INVITE_INVALID", "Invite is not a recognizable RFC-002 capability token")

    validate_schema(token)
    validate_expiry(token, int(time.time()))
    verify_token_signature(token)
    validate_authorization(token)
    if token["tier"] not in RFC002_ADMISSIBLE_TIERS:
        raise InviteTokenError(
            "INVITE_SCOPE",
            f"'{token['tier']}' tier is read-only and does not admit to the beta gate",
        )
    consume_use(token, cache=cache)
    return token
