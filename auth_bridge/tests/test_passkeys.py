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
Integration tests for passwordless passkey registration and assertion
ceremonies, driven by a software ES256 authenticator.
"""

import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import TestCase, override_settings
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
    CoseKey,
)

from auth_bridge.models import PasskeyCredential, User

REG_BEGIN = "/auth/passkeys/register/begin/"
REG_COMPLETE = "/auth/passkeys/register/complete/"
AUTH_BEGIN = "/auth/passkeys/authenticate/begin/"
AUTH_COMPLETE = "/auth/passkeys/authenticate/complete/"

TEST_SETTINGS = {
    "IDP_BASE_URL": "http://localhost:8001",
    "CACHES": {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    },
}


class VirtualAuthenticator:
    """
    Software ES256 authenticator producing spec-shaped registration and
    assertion responses consumed by the real server-side verification stack.
    """

    def __init__(self) -> None:
        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private_key.public_key().public_numbers()
        self.cose_public_key = CoseKey({
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })
        self.counter = 0

    def _attested_credential_data(self) -> AttestedCredentialData:
        return AttestedCredentialData.create(
            Aaguid.NONE, self.credential_id, self.cose_public_key
        )

    def _signature(self, message: bytes) -> bytes:
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def register(self, challenge: str, origin: str, rp_id: str) -> dict[str, Any]:
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.CREATE, challenge, origin
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT,
            self.counter,
            self._attested_credential_data(),
        )
        attestation_object = AttestationObject.create("none", auth_data, {})
        encoded_id = websafe_encode(self.credential_id)
        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "response": {
                "attestationObject": websafe_encode(attestation_object),
                "clientDataJSON": websafe_encode(client_data),
                "transports": ["internal"],
            },
        }

    def assert_credential(
        self, challenge: str, origin: str, rp_id: str, user_handle: bytes | None = None
    ) -> dict[str, Any]:
        self.counter += 1
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET, challenge, origin
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(rp_id.encode()).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV,
            self.counter,
        )
        signed = bytes(auth_data) + client_data.hash
        encoded_id = websafe_encode(self.credential_id)
        response: dict[str, Any] = {
            "authenticatorData": websafe_encode(auth_data),
            "signature": websafe_encode(self._signature(signed)),
            "clientDataJSON": websafe_encode(client_data),
        }
        if user_handle is not None:
            response["userHandle"] = websafe_encode(user_handle)
        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "response": response,
        }


@override_settings(**TEST_SETTINGS)
class PasskeyCeremonyBase(TestCase):
    origin = "http://localhost:8001"
    rp_id = "localhost"

    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="managed@iyou.me")

    def _begin_registration(self) -> dict[str, Any]:
        self.client.force_login(self.user)
        response = self.client.post(REG_BEGIN, data="{}", content_type="application/json")
        assert response.status_code == 200, response.content
        return json.loads(response.content)

    def _register_authenticator(self, authenticator: VirtualAuthenticator) -> dict[str, Any]:
        begin_payload = self._begin_registration()
        options = begin_payload["publicKey"]
        attestation = authenticator.register(options["challenge"], self.origin, self.rp_id)
        response = self.client.post(
            REG_COMPLETE,
            data=json.dumps({"ceremony_id": begin_payload["ceremony_id"], **attestation}),
            content_type="application/json",
        )
        return begin_payload, response

    def _begin_authentication(self) -> dict[str, Any]:
        response = self.client.post(AUTH_BEGIN, data="{}", content_type="application/json")
        assert response.status_code == 200, response.content
        return json.loads(response.content)


class PasskeyRegistrationTest(PasskeyCeremonyBase):
    def test_registration_roundtrip_persists_credential(self) -> None:
        authenticator = VirtualAuthenticator()
        _, response = self._register_authenticator(authenticator)
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body["status"], "registered")

        row = PasskeyCredential.objects.get(user=self.user)
        self.assertEqual(bytes(row.credential_id), authenticator.credential_id)
        self.assertEqual(row.transports, ["internal"])

    def test_registration_requires_authentication(self) -> None:
        response = self.client.post(REG_BEGIN, data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content)["error"], "authentication_required")

    def test_duplicate_credential_rejected_with_conflict(self) -> None:
        authenticator = VirtualAuthenticator()
        _, first = self._register_authenticator(authenticator)
        self.assertEqual(first.status_code, 200)
        _, second = self._register_authenticator(authenticator)
        self.assertEqual(second.status_code, 409)
        self.assertEqual(
            json.loads(second.content)["error"], "credential_already_registered"
        )

    def test_bogus_attestation_rejected(self) -> None:
        begin_payload = self._begin_registration()
        response = self.client.post(
            REG_COMPLETE,
            data=json.dumps({"ceremony_id": begin_payload["ceremony_id"], "garbage": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_attestation")

    def test_unknown_or_expired_ceremony_rejected(self) -> None:
        self.client.force_login(self.user)
        response = self.client.post(
            REG_COMPLETE,
            data=json.dumps({"ceremony_id": "nonexistent"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "unknown_or_expired_ceremony")


class PasskeyAuthenticationTest(PasskeyCeremonyBase):
    def setUp(self) -> None:
        super().setUp()
        self.authenticator = VirtualAuthenticator()
        _, response = self._register_authenticator(self.authenticator)
        assert response.status_code == 200
        self.client.logout()

    def _assert_credential(self, user_handle: bytes | None = None) -> dict[str, Any]:
        begin_payload = self._begin_authentication()
        options = begin_payload["publicKey"]
        assertion = self.authenticator.assert_credential(
            options["challenge"], self.origin, self.rp_id, user_handle=user_handle
        )
        payload = {
            "ceremony_id": begin_payload["ceremony_id"],
            **assertion,
        }
        return begin_payload, self.client.post(
            AUTH_COMPLETE, data=json.dumps(payload), content_type="application/json"
        )

    def test_passwordless_login_via_discoverable_assertion(self) -> None:
        _, response = self._assert_credential(user_handle=bytes(self.user.id.bytes))
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body["status"], "authenticated")
        self.assertEqual(body["did"], self.user.custodial_did)

        session_user_id = self.client.session.get("_auth_user_id")
        self.assertIsNotNone(session_user_id)

        row = PasskeyCredential.objects.get(user=self.user)
        self.assertIsNotNone(row.last_used_at)
        self.assertEqual(row.sign_count, self.authenticator.counter)

    def test_wrong_challenge_assertion_rejected(self) -> None:
        begin_payload = self._begin_authentication()
        assertion = self.authenticator.assert_credential(
            websafe_decode("Zm9vYmFy"), self.origin, self.rp_id
        )
        response = self.client.post(
            AUTH_COMPLETE,
            data=json.dumps({"ceremony_id": begin_payload["ceremony_id"], **assertion}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_assertion")
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    def test_unregistered_credential_rejected_before_verification(self) -> None:
        rogue = VirtualAuthenticator()
        begin_payload = self._begin_authentication()
        options = begin_payload["publicKey"]
        assertion = rogue.assert_credential(options["challenge"], self.origin, self.rp_id)
        response = self.client.post(
            AUTH_COMPLETE,
            data=json.dumps({"ceremony_id": begin_payload["ceremony_id"], **assertion}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "unknown_credential")

    def test_cloned_credential_counter_regression_detected(self) -> None:
        _, ok_response = self._assert_credential(user_handle=bytes(self.user.id.bytes))
        self.assertEqual(ok_response.status_code, 200)

        row = PasskeyCredential.objects.get(user=self.user)
        row.sign_count = 99999
        row.save(update_fields=["sign_count"])

        begin_payload, response = self._assert_credential(
            user_handle=bytes(self.user.id.bytes)
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "cloned_credential_detected")

    def test_foreign_user_handle_rejected(self) -> None:
        stranger = User.objects.create_user(email="stranger@iyou.me")
        _, response = self._assert_credential(user_handle=bytes(stranger.id.bytes))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "user_handle_mismatch")
        self.assertIsNone(self.client.session.get("_auth_user_id"))
