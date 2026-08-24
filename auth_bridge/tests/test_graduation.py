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
Integration tests for the Identity Graduation protocol: sealed export,
signed receipt confirmation, transactional Vault shredding and the
sovereign front-channel authorization gate.
"""

import binascii
import json
import time
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from django.test import TestCase

from auth_bridge.models import User
from auth_bridge.views_graduation import HKDF_INFO

EXPORT_URL = "/api/v1/identity/graduate/export/"
CONFIRM_URL = "/api/v1/identity/graduate/confirm/"


class VaultDouble:
    """
    In-memory stand-in for the Vault KV identity mount, tracking every
    delete attempt so tests can assert whether Vault was ever targeted.
    """

    def __init__(self) -> None:
        self.store: dict[str, dict[str, Any]] = {}
        self.delete_calls: list[str] = []

    def seed(self, did: str, data: dict[str, Any]) -> None:
        self.store[did] = data

    def read(self, did: str) -> dict[str, Any]:
        if did not in self.store:
            raise KeyError(did)
        return self.store[did]

    def delete(self, did: str) -> None:
        self.delete_calls.append(did)
        if did not in self.store:
            raise KeyError(did)
        del self.store[did]


def _make_vault_keypair(did: str) -> tuple[Ed25519PrivateKey, dict[str, str]]:
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return private_key, {
        "private_key_pem": pem.decode("ascii"),
        "did": did,
    }


def _canonical(receipt: dict[str, Any]) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")


class GraduationBaseTestCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.vault = VaultDouble()
        self.read_patch = patch(
            "auth_bridge.views_graduation.read_identity_key", side_effect=self.vault.read
        )
        self.delete_patch = patch(
            "auth_bridge.views_graduation.delete_identity_key", side_effect=self.vault.delete
        )
        self.read_patch.start()
        self.delete_patch.start()
        self.addCleanup(self.read_patch.stop)
        self.addCleanup(self.delete_patch.stop)

    def _make_user(self, email: str = "managed@iyou.me") -> User:
        user = User.objects.create_user(email=email)
        private_key, vault_data = _make_vault_keypair(user.custodial_did)
        self.vault.seed(user.custodial_did, vault_data)
        return user, private_key

    def _export(self, user: User) -> tuple[dict[str, Any], X25519PrivateKey]:
        client_ephemeral = X25519PrivateKey.generate()
        response = self.client.post(
            EXPORT_URL,
            data=json.dumps({
                "ephemeral_pubkey": client_ephemeral.public_key()
                .public_bytes_raw()
                .hex()
            }),
            content_type="application/json",
        )
        assert response.status_code == 200, response.content
        return json.loads(response.content), client_ephemeral

    def _unseal(
        self,
        did: str,
        payload: dict[str, Any],
        client_ephemeral: X25519PrivateKey,
    ) -> bytes:
        server_pub = X25519PublicKey.from_public_bytes(
            binascii.unhexlify(payload["server_ephemeral_pub"])
        )
        shared = client_ephemeral.exchange(server_pub)
        nonce = binascii.unhexlify(payload["nonce"])
        wrapping_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=nonce, info=HKDF_INFO
        ).derive(shared)
        ciphertext = binascii.unhexlify(payload["ciphertext"])
        return AESGCM(wrapping_key).decrypt(nonce, ciphertext, did.encode("utf-8"))

    def _receipt_payload(
        self,
        signing_key: Ed25519PrivateKey,
        did: str | None = None,
        issued_at: float | None = None,
        action: str = "graduate",
        mutate_after_signing: bool = False,
    ) -> dict[str, Any]:
        receipt = {
            "action": action,
            "did": did or "will-be-set-by-caller",
            "issued_at": issued_at if issued_at is not None else time.time(),
        }
        signature = signing_key.sign(_canonical(receipt))
        if mutate_after_signing:
            receipt["issued_at"] = float(receipt["issued_at"]) + 1.0
        return {"receipt": receipt, "signature": signature.hex()}


class GraduationHappyPathTest(GraduationBaseTestCase):
    """Case A — flawless export → signed receipt → sovereign + shredded."""

    def test_full_graduation_loop(self) -> None:
        user, vault_private_key = self._make_user()
        self.assertFalse(user.is_sovereign)
        self.client.force_login(user)

        export_payload, client_ephemeral = self._export(user)
        recovered_seed = self._unseal(user.custodial_did, export_payload, client_ephemeral)

        self.assertEqual(recovered_seed, vault_private_key.private_bytes_raw())

        local_identity = Ed25519PrivateKey.from_private_bytes(recovered_seed)
        body = self._receipt_payload(local_identity, did=user.custodial_did)
        response = self.client.post(CONFIRM_URL, data=json.dumps(body), content_type="application/json")

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["status"], "graduated")
        self.assertTrue(data["is_sovereign"])

        user.refresh_from_db()
        self.assertTrue(user.is_sovereign)
        self.assertEqual(user.account_tier, "sovereign")

        self.assertNotIn(user.custodial_did, self.vault.store)
        self.assertEqual(self.vault.delete_calls, [user.custodial_did])

    def test_graduated_did_is_blocked_from_front_channel_issuance(self) -> None:
        user, vault_private_key = self._make_user()
        self.client.force_login(user)
        export_payload, client_ephemeral = self._export(user)
        recovered_seed = self._unseal(user.custodial_did, export_payload, client_ephemeral)
        local_identity = Ed25519PrivateKey.from_private_bytes(recovered_seed)
        body = self._receipt_payload(local_identity, did=user.custodial_did)
        self.client.post(CONFIRM_URL, data=json.dumps(body), content_type="application/json")

        blocked = self.client.get("/openid/authorize/", {"client_id": "x", "response_type": "code"})
        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(json.loads(blocked.content)["error"], "access_denied")


class GraduationAtomicityTest(GraduationBaseTestCase):
    """Case B — Vault erasure failure must roll the promotion back entirely."""

    def test_vault_shred_failure_rolls_back_sovereign_flip(self) -> None:
        user, vault_private_key = self._make_user()
        original_tier = user.account_tier
        self.client.force_login(user)

        export_payload, client_ephemeral = self._export(user)
        recovered_seed = self._unseal(user.custodial_did, export_payload, client_ephemeral)
        local_identity = Ed25519PrivateKey.from_private_bytes(recovered_seed)
        body = self._receipt_payload(local_identity, did=user.custodial_did)

        def network_interruption(custodial_did: str) -> None:
            raise ConnectionError("vault unreachable during shred")

        with patch(
            "auth_bridge.views_graduation.delete_identity_key",
            side_effect=network_interruption,
        ):
            response = self.client.post(
                CONFIRM_URL, data=json.dumps(body), content_type="application/json"
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(json.loads(response.content)["error"], "vault_shred_failed")

        user.refresh_from_db()
        self.assertFalse(user.is_sovereign)
        self.assertEqual(user.account_tier, original_tier)
        self.assertIn(user.custodial_did, self.vault.store)


class GraduationRejectionTest(GraduationBaseTestCase):
    """Case C — malicious/malformed receipts change nothing anywhere."""

    def _attempt_and_assert_clean_rejection(
        self, body: dict[str, Any], expected_error: str
    ) -> None:
        response = self.client.post(CONFIRM_URL, data=json.dumps(body), content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], expected_error)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_sovereign)
        self.assertNotEqual(self.user.account_tier, "sovereign")
        self.assertEqual(self.vault.delete_calls, [])
        self.assertIn(self.user.custodial_did, self.vault.store)

    def setUp(self) -> None:
        super().setUp()
        self.user, self.vault_private_key = self._make_user("victim@iyou.me")
        self.client.force_login(self.user)

    def test_signature_by_foreign_key_rejected(self) -> None:
        impostor = Ed25519PrivateKey.generate()
        body = self._receipt_payload(impostor, did=self.user.custodial_did)
        self._attempt_and_assert_clean_rejection(body, "invalid_receipt_signature")

    def test_tampered_receipt_after_signing_rejected(self) -> None:
        body = self._receipt_payload(
            self.vault_private_key,
            did=self.user.custodial_did,
            mutate_after_signing=True,
        )
        self._attempt_and_assert_clean_rejection(body, "invalid_receipt_signature")

    def test_receipt_did_mismatch_rejected_without_vault_call(self) -> None:
        body = self._receipt_payload(self.vault_private_key, did="did:web:iyou.me:user:other")
        self._attempt_and_assert_clean_rejection(body, "receipt_did_mismatch")

    def test_stale_receipt_rejected(self) -> None:
        stale_time = time.time() - 3600
        body = self._receipt_payload(
            self.vault_private_key, did=self.user.custodial_did, issued_at=stale_time
        )
        self._attempt_and_assert_clean_rejection(body, "receipt_expired")

    def test_wrong_action_rejected(self) -> None:
        body = self._receipt_payload(
            self.vault_private_key, did=self.user.custodial_did, action="rotate"
        )
        self._attempt_and_assert_clean_rejection(body, "receipt_action_invalid")

    def test_missing_signature_rejected(self) -> None:
        receipt = {
            "action": "graduate",
            "did": self.user.custodial_did,
            "issued_at": time.time(),
        }
        self._attempt_and_assert_clean_rejection({"receipt": receipt}, "malformed_payload")

    def test_garbage_signature_encoding_rejected(self) -> None:
        receipt = {
            "action": "graduate",
            "did": self.user.custodial_did,
            "issued_at": time.time(),
        }
        body = {"receipt": receipt, "signature": "0xzznotreal"}
        self._attempt_and_assert_clean_rejection(body, "malformed_key_material")


class GraduationAccessControlTest(GraduationBaseTestCase):
    def test_export_requires_authentication(self) -> None:
        response = self.client.post(
            EXPORT_URL,
            data=json.dumps({"ephemeral_pubkey": "00" * 32}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "authentication_required")

    def test_confirm_requires_authentication(self) -> None:
        response = self.client.post(CONFIRM_URL, data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "authentication_required")

    def test_export_rejects_bad_ephemeral_pubkey_length(self) -> None:
        user, _ = self._make_user()
        self.client.force_login(user)
        response = self.client.post(
            EXPORT_URL,
            data=json.dumps({"ephemeral_pubkey": "aabb"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "malformed_key_material")

    def test_already_sovereign_user_cannot_export_or_confirm(self) -> None:
        user, _ = self._make_user()
        user.is_sovereign = True
        user.save(update_fields=["is_sovereign"])
        self.client.force_login(user)

        export_response = self.client.post(
            EXPORT_URL,
            data=json.dumps({"ephemeral_pubkey": "00" * 32}),
            content_type="application/json",
        )
        confirm_response = self.client.post(
            CONFIRM_URL,
            data=json.dumps({"receipt": {}, "signature": "00" * 64}),
            content_type="application/json",
        )
        self.assertEqual(export_response.status_code, 400)
        self.assertEqual(confirm_response.status_code, 400)
        for response in (export_response, confirm_response):
            self.assertEqual(json.loads(response.content)["error"], "already_sovereign")
