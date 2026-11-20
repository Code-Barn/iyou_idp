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

import json
from typing import Any
from unittest.mock import patch
from urllib.parse import urlencode

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.test import Client, TestCase, override_settings
from oidc_provider.models import Client as OIDCClient
from oidc_provider.models import ResponseType
from oidc_provider.models import RSAKey as OIDCRSAKey

from auth_bridge.models import User
from auth_bridge.oidc import custom_id_token_claims, custom_userinfo_claims
from auth_bridge.resilient_cache import cache

BIND_URL = "/api/v1/identity/graduate/bind/"
MANAGED_DID = "did:web:iyou.me:user:22222222-2222-4222-8222-222222222222"


def _make_did(pub_bytes: bytes) -> str:
    multicodec = bytes([0xed, 0x01]) + pub_bytes
    return f"did:key:z{base58.b58encode(multicodec).decode('ascii')}"


def _sign_vp(private_key: ed25519.Ed25519PrivateKey, holder: str, challenge: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "holder": holder,
        "challenge": challenge,
        "verifiableCredential": [],
        "issuer": holder,
    }
    signature = private_key.sign(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload["proof"] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": f"{holder}#keys-1",
        "challenge": challenge,
        "proofValue": signature.hex(),
    }
    return payload


class GraduationBindTest(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.did_key = _make_did(
            self.private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        self.user = User.objects.create_user(email="bind_user@iyou.me", custodial_did=MANAGED_DID)
        self.challenge = "graduation-bind-challenge"
        cache.set(self.challenge, json.dumps({"status": "pending", "did": None}), 300)

        self.delete_patch = patch("auth_bridge.views_graduation.delete_identity_key")
        self.mock_delete = self.delete_patch.start()
        self.addCleanup(self.delete_patch.stop)

    def _bind(self, vp: dict[str, Any], challenge: str | None = None):
        return self.client.post(
            BIND_URL,
            data=json.dumps({"vp": vp, "challenge": challenge or self.challenge}),
            content_type="application/json",
        )

    def test_bind_transitions_primary_did_and_shreds_custodial_key(self) -> None:
        self.client.force_login(self.user)
        response = self._bind(_sign_vp(self.private_key, self.did_key, self.challenge))

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "graduated")
        self.assertTrue(data["is_sovereign"])

        self.user.refresh_from_db()
        self.assertEqual(self.user.custodial_did, self.did_key)
        self.assertEqual(self.user.graduated_from_did, MANAGED_DID)
        self.assertTrue(self.user.is_sovereign)
        self.assertEqual(self.user.account_tier, "sovereign")
        self.assertFalse(self.user.has_usable_password())
        self.mock_delete.assert_called_once_with(MANAGED_DID)
        self.assertIsNone(cache.get(self.challenge))
        self.assertEqual(self.client.session.get("auth_method"), "did:websocket")

    def test_bind_rejects_did_key_already_bound_to_other_user(self) -> None:
        User.objects.create_user(email="other@iyou.me", custodial_did=self.did_key)
        self.client.force_login(self.user)
        response = self._bind(_sign_vp(self.private_key, self.did_key, self.challenge))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], "did_key_already_bound")
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_sovereign)

    def test_bind_rejects_invalid_signature(self) -> None:
        self.client.force_login(self.user)
        vp = _sign_vp(self.private_key, self.did_key, self.challenge)
        vp["proof"]["proofValue"] = "00" * 64
        response = self._bind(vp)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "invalid_vp")

    def test_bind_requires_cached_challenge(self) -> None:
        self.client.force_login(self.user)
        response = self._bind(_sign_vp(self.private_key, self.did_key, "unknown-challenge"), "unknown-challenge")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "challenge_expired")


class GraduatedClaimsTest(TestCase):
    def setUp(self) -> None:
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.did_key = _make_did(
            self.private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )

    def test_graduated_from_did_emitted_in_userinfo_and_id_token(self) -> None:
        user = User.objects.create(
            custodial_did=self.did_key,
            graduated_from_did=MANAGED_DID,
            is_sovereign=True,
            account_tier="sovereign",
            email_verified=True,
        )
        userinfo = custom_userinfo_claims({}, user)
        id_token = custom_id_token_claims({}, user)
        self.assertEqual(userinfo["sub"], self.did_key)
        self.assertEqual(userinfo["account_tier"], "sovereign")
        self.assertEqual(userinfo["graduated_from_did"], MANAGED_DID)
        self.assertEqual(id_token["sub"], self.did_key)
        self.assertEqual(id_token["graduated_from_did"], MANAGED_DID)

    def test_direct_did_key_user_omits_graduated_from_did(self) -> None:
        user = User.objects.create(
            custodial_did=self.did_key,
            is_sovereign=True,
            account_tier="sovereign",
        )
        self.assertNotIn("graduated_from_did", custom_userinfo_claims({}, user))
        self.assertNotIn("graduated_from_did", custom_id_token_claims({}, user))


class DidWebDocumentTest(TestCase):
    def test_also_known_as_links_retired_did_web_to_active_did_key(self) -> None:
        private_key = ed25519.Ed25519PrivateKey.generate()
        did_key = _make_did(
            private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        User.objects.create(
            custodial_did=did_key,
            graduated_from_did=MANAGED_DID,
            is_sovereign=True,
            account_tier="sovereign",
        )
        uuid = MANAGED_DID.rsplit(":", 1)[1]

        response = self.client.get(f"/user/{uuid}/did.json")
        self.assertEqual(response.status_code, 200)
        document = response.json()
        self.assertEqual(document["id"], MANAGED_DID)
        self.assertIn(did_key, document["alsoKnownAs"])

    def test_unknown_user_returns_404(self) -> None:
        response = self.client.get("/user/33333333-3333-4333-8333-333333333333/did.json")
        self.assertEqual(response.status_code, 404)


@override_settings(SYSTEM_GATE_ENABLED=False)
class GraduatedIngressAuthorizationTest(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        private_key = ed25519.Ed25519PrivateKey.generate()
        self.did_key = _make_did(
            private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())
        self.oidc_client = OIDCClient.objects.create(
            name="Graduation Satellite",
            client_type="public",
            client_id="graduation-satellite",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.oidc_client.response_types.add(ResponseType.objects.get(value="code"))
        self.user = User.objects.create(
            custodial_did=self.did_key,
            graduated_from_did=MANAGED_DID,
            is_sovereign=True,
            account_tier="sovereign",
            email_verified=True,
            show_legal_disclaimer=False,
        )

    def _authorize(self, auth_method: str, prompt: str | None = None):
        self.client.force_login(self.user)
        session = self.client.session
        session["auth_method"] = auth_method
        session.save()
        params = {
            "client_id": "graduation-satellite",
            "response_type": "code",
            "redirect_uri": "https://satellite.iyou.me/callback/",
            "scope": "openid profile",
            "state": "graduation-state",
            "code_challenge": "E9Melhoa2OwvFrGMTJguCH5rtx64KA1iLyEUXVS7tkU",
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        return self.client.get("/openid/authorize/?" + urlencode(params))

    def test_tier3_websocket_session_mints_code(self) -> None:
        response = self._authorize("did:websocket")
        self.assertEqual(response.status_code, 302)
        self.assertIn("code=", response["Location"])
        self.assertIn("state=graduation-state", response["Location"])

    def test_tier2_qr_session_mints_code(self) -> None:
        response = self._authorize("did:oob_qr")
        self.assertEqual(response.status_code, 302)
        self.assertIn("code=", response["Location"])

    def test_passkey_session_mints_code(self) -> None:
        response = self._authorize("webauthn:passkey")
        self.assertEqual(response.status_code, 302)
        self.assertIn("code=", response["Location"])

    def test_custodial_email_otp_session_is_blocked(self) -> None:
        response = self._authorize("otp:email")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "access_denied")

    def test_custodial_session_prompt_none_returns_error_redirect(self) -> None:
        response = self._authorize("otp:email", prompt="none")
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=interaction_required", response["Location"])
        self.assertIn("state=graduation-state", response["Location"])
