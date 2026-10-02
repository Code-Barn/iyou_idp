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

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from oidc_provider.models import Client as OIDCClient
from oidc_provider.models import ResponseType
from oidc_provider.models import RSAKey as OIDCRSAKey

from auth_bridge.models import User
from auth_bridge.oidc import (
    CustomScopeClaims,
    custom_id_token_claims,
    custom_idtoken_processing_hook,
    custom_userinfo_claims,
)
from auth_bridge.resilient_cache import cache


def _make_did(pub_bytes: bytes) -> str:
    multicodec = bytes([0xed, 0x01]) + pub_bytes
    return f"did:key:z{base58.b58encode(multicodec).decode('ascii')}"


def _sign(obj: dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    payload = {k: v for k, v in obj.items() if k != "proof"}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(raw)
    return {
        **obj,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2026-10-02T00:00:00Z",
            "verificationMethod": f"{obj['holder']}#keys-1",
            "proofPurpose": "authentication",
            "signatureValue": sig.hex(),
        },
    }


@override_settings(SYSTEM_GATE_ENABLED=False)
class SovereignAuthDecouplingTest(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.sovereign_did = _make_did(pub_bytes)

        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        self.oidc_client = OIDCClient.objects.create(
            name="Satellite Client",
            client_type="public",
            client_id="satellite-client-123",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.oidc_client.response_types.add(ResponseType.objects.get(value="code"))

        self.sovereign_user = User.objects.create(
            custodial_did=self.sovereign_did,
            email="sovereign@iyou.me",
            is_sovereign=True,
            account_tier="sovereign",
            email_verified=True,
            show_legal_disclaimer=False,
            is_active=True,
        )
        self.sovereign_user.set_unusable_password()
        self.sovereign_user.save()

    def test_sovereign_tier3_websocket_oidc_issuance(self) -> None:
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        challenge = resp.json()["challenge"]

        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.sovereign_did,
                "challenge": challenge,
                "verifiableCredential": [],
                "issuer": self.sovereign_did,
            },
            self.private_key,
        )

        authorize_next = (
            f"/openid/authorize/"
            f"?client_id={self.oidc_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile"
            f"&state=sovereign-state-123"
        )

        verify_resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
                "next_url": authorize_next,
            }),
            content_type="application/json",
        )
        self.assertEqual(verify_resp.status_code, 200)
        verify_data = verify_resp.json()
        self.assertTrue(verify_data["success"])
        self.assertEqual(self.client.session.get("auth_method"), "did:websocket")

        redirect_url = verify_data["redirect_url"]
        if "code=" in redirect_url:
            self.assertIn("https://satellite.iyou.me/callback/", redirect_url)
            self.assertIn("code=", redirect_url)
            self.assertIn("state=sovereign-state-123", redirect_url)
        else:
            auth_resp = self.client.get(redirect_url)
            self.assertEqual(auth_resp.status_code, 302)
            location = auth_resp["Location"]
            self.assertTrue(location.startswith("https://satellite.iyou.me/callback/"))
            self.assertIn("code=", location)
            self.assertIn("state=sovereign-state-123", location)

    def test_sovereign_tier2_mobile_qr_oidc_issuance(self) -> None:
        challenge_id = "test-mobile-challenge-456"
        authorize_next = (
            f"/openid/authorize/"
            f"?client_id={self.oidc_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile"
            f"&state=qr-state-789"
        )
        cache.set(
            challenge_id,
            json.dumps({
                "status": "solved",
                "did": self.sovereign_did,
                "next_url": authorize_next,
            }),
            300,
        )

        status_url = reverse("auth_bridge:challenge_status", kwargs={"challenge_id": challenge_id})
        status_resp = self.client.get(status_url)
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertTrue(status_data["solved"])
        self.assertEqual(self.client.session.get("auth_method"), "did:oob_qr")

        redirect_url = status_data["redirect_url"]
        if "code=" in redirect_url:
            self.assertIn("https://satellite.iyou.me/callback/", redirect_url)
            self.assertIn("code=", redirect_url)
            self.assertIn("state=qr-state-789", redirect_url)
        else:
            auth_resp = self.client.get(redirect_url)
            self.assertEqual(auth_resp.status_code, 302)
            location = auth_resp["Location"]
            self.assertTrue(location.startswith("https://satellite.iyou.me/callback/"))
            self.assertIn("code=", location)
            self.assertIn("state=qr-state-789", location)

    def test_sovereign_claims_and_amr_instrumentation(self) -> None:
        class DummyRequest:
            def __init__(self, session_data: dict[str, Any]) -> None:
                self.session = session_data

        req_ws = DummyRequest({"auth_method": "did:websocket"})
        userinfo_ws = custom_userinfo_claims({}, self.sovereign_user, request=req_ws)
        self.assertEqual(userinfo_ws["sub"], self.sovereign_did)
        self.assertEqual(userinfo_ws["did"], self.sovereign_did)
        self.assertEqual(userinfo_ws["account_tier"], "sovereign")
        self.assertTrue(userinfo_ws["email_verified"])
        self.assertEqual(userinfo_ws["amr"], ["did:websocket"])

        id_token_ws = custom_id_token_claims({}, self.sovereign_user, request=req_ws)
        self.assertEqual(id_token_ws["sub"], self.sovereign_did)
        self.assertEqual(id_token_ws["account_tier"], "sovereign")
        self.assertTrue(id_token_ws["email_verified"])
        self.assertEqual(id_token_ws["amr"], ["did:websocket"])

        hook_result = custom_idtoken_processing_hook({}, user=self.sovereign_user, request=req_ws)
        self.assertEqual(hook_result["amr"], ["did:websocket"])
        self.assertEqual(hook_result["account_tier"], "sovereign")

        req_qr = DummyRequest({"auth_method": "did:oob_qr"})
        userinfo_qr = custom_userinfo_claims({}, self.sovereign_user, request=req_qr)
        self.assertEqual(userinfo_qr["amr"], ["did:oob_qr"])
        self.assertEqual(userinfo_qr["account_tier"], "sovereign")

        id_token_qr = custom_id_token_claims({}, self.sovereign_user, request=req_qr)
        self.assertEqual(id_token_qr["amr"], ["did:oob_qr"])

        token_mock = type("TokenMock", (), {"user": self.sovereign_user, "scope": ["openid", "profile"], "client": self.oidc_client})()
        scope_claims = CustomScopeClaims(token_mock)
        scope_claims.create_response_dic()
        profile_claims = scope_claims.scope_profile()
        self.assertEqual(profile_claims["account_tier"], "sovereign")
        self.assertEqual(profile_claims["did"], self.sovereign_did)

    def test_legacy_password_session_blocked_from_front_channel(self) -> None:
        self.client.force_login(self.sovereign_user)
        session = self.client.session
        session["auth_method"] = "password"
        session.save()

        auth_url = (
            f"/openid/authorize/"
            f"?client_id={self.oidc_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile"
            f"&state=pwd-state"
        )
        resp = self.client.get(auth_url)
        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertEqual(data["error"], "access_denied")
        self.assertIn("Legacy password or unverified authentication", data["error_description"])

    def test_unverified_session_blocked_from_front_channel(self) -> None:
        self.client.force_login(self.sovereign_user)
        session = self.client.session
        session["auth_method"] = "unverified"
        session.save()

        auth_url = (
            f"/openid/authorize/"
            f"?client_id={self.oidc_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile"
            f"&state=unverified-state"
        )
        resp = self.client.get(auth_url)
        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertEqual(data["error"], "access_denied")
        self.assertIn("Legacy password or unverified authentication", data["error_description"])
