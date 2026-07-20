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
Integration tests for the DID challenge-response authentication flow.
"""
import json
import hashlib
import base58
from base64 import urlsafe_b64encode
from django.test import TestCase, Client
from django.urls import reverse
from django.core.cache import cache
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from auth_bridge.models import User


def _make_did(pub_bytes: bytes) -> str:
    multicodec = bytes([0xed, 0x01]) + pub_bytes
    return "did:key:z" + base58.b58encode(multicodec).decode("ascii")


def _sign(obj: dict, private_key, exclude: set = None) -> dict:
    exclude = exclude or {"proof"}
    payload = {k: v for k, v in obj.items() if k not in exclude}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(raw)
    return {
        **obj,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2025-01-01T00:00:00Z",
            "verificationMethod": f"{obj['holder']}#keys-1",
            "proofPurpose": "authentication",
            "signatureValue": sig.hex(),
        },
    }


def _sign_vc(vc: dict, private_key) -> dict:
    payload = {k: v for k, v in vc.items() if k != "proof"}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(raw)
    return {
        **vc,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2025-01-01T00:00:00Z",
            "verificationMethod": f"{vc['issuer']}#keys-1",
            "proofPurpose": "assertionMethod",
            "signatureValue": base58.b58encode(sig).decode("ascii"),
        },
    }


class ChallengeResponseCycleTest(TestCase):
    """Full end-to-end: request challenge → build VP → verify → session."""

    def setUp(self):
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.did = _make_did(pub_bytes)

    def _signed_vp(self, challenge: str) -> dict:
        vc = _sign_vc(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": self.did,
                "issuanceDate": "2025-01-01T00:00:00Z",
                "credentialSubject": {"id": self.did, "name": "Test"},
            },
            self.private_key,
        )
        return _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "verifiableCredential": [vc],
            },
            self.private_key,
        )

    def _master_vp(self, challenge: str) -> dict:
        return _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "challenge": challenge,
                "verifiableCredential": [],
                "issuer": self.did,
            },
            self.private_key,
        )

    def test_full_cycle_creates_session(self):
        # 1. Request a challenge
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("challenge", data)
        challenge = data["challenge"]

        # 2. Build a signed master-key VP (no inner credentials)
        vp = self._master_vp(challenge)

        # 3. Submit VP for verification
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
            }),
            content_type="application/json",
        )

        # 4. Assert success and user session
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["user"]["did"], self.did)
        self.assertTrue(body["user"]["is_authenticated"])
        self.assertIsNotNone(body["user"]["session_id"])

    def test_stringified_vp_parses_correctly(self):
        """VP sent as a JSON string (not a dict) must be parsed by the view."""
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        challenge = resp.json()["challenge"]
        vp = self._master_vp(challenge)

        # Send the VP as a JSON-encoded string to account for browser
        # double-serialisation (e.g., from a WebSocket message).
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": json.dumps(vp),
                "challenge": challenge,
            }),
            content_type="application/json",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["user"]["did"], self.did)

    def test_next_url_roundtrip(self):
        """Verify that next_url sent in the POST body is echoed back as redirect_url."""
        # 1. Challenge
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        challenge = resp.json()["challenge"]

        # 2. Build a master-key VP
        vp = self._master_vp(challenge)

        # 3. Submit with next_url
        expected_next = "/openid/authorize/?client_id=test&response_type=code"
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
                "next_url": expected_next,
            }),
            content_type="application/json",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["redirect_url"], expected_next)

    def test_missing_fields_returns_400(self):
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_expired_challenge_returns_404(self):
        vp = self._master_vp("nonexistent-uuid")
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": "nonexistent-uuid",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class OIDCAuthorizeFlowTest(TestCase):
    """End-to-end: DID login → OIDC authorize → code exchange."""

    def setUp(self):
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        from oidc_provider.models import RSAKey as OIDCRSAKey
        from oidc_provider.models import Client as OIDCClient

        # Create RSA key for token signing
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        # Create an OIDC client
        from oidc_provider.models import ResponseType
        self.client_obj = OIDCClient.objects.create(
            name="Test Client",
            client_type="confidential",
            client_id="test-client-id",
            client_secret="test-client-secret",
            jwt_alg="RS256",
            _redirect_uris="http://testclient/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.client_obj.response_types.add(ResponseType.objects.get(value="code"))

        # Create a user via DID auth
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        self.challenge = resp.json()["challenge"]

        self.did = _make_did(pub_bytes)
        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "challenge": self.challenge,
                "verifiableCredential": [],
                "issuer": self.did,
            },
            self.private_key,
        )

        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": self.challenge,
                "next_url": "/openid/authorize/",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)

    def test_authorize_returns_code_for_authenticated_user(self):
        """OIDC authorize should redirect with code when user is logged in."""
        resp = self.client.get(
            reverse("oidc_provider:authorize"),
            {
                "client_id": self.client_obj.client_id,
                "response_type": "code",
                "redirect_uri": "http://testclient/callback/",
                "scope": "openid profile",
                "state": "test-state-123",
                "nonce": "test-nonce-456",
            },
        )

        # Should redirect to the client's callback URI with a code
        self.assertEqual(resp.status_code, 302)
        location = resp["Location"]
        self.assertTrue(location.startswith("http://testclient/callback/"))
        self.assertIn("code=", location)
        self.assertIn("state=test-state-123", location)

    def test_verify_redirects_directly_to_client(self):
        """Verify_signature returns client callback URI when next_url has OIDC params."""
        # Fresh challenge — setUp already consumed self.challenge
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        challenge = resp.json()["challenge"]

        # Build a master-key VP signed with the setUp key
        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "challenge": challenge,
                "verifiableCredential": [],
                "issuer": self.did,
            },
            self.private_key,
        )

        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
                "next_url": (
                    f"/openid/authorize/"
                    f"?client_id={self.client_obj.client_id}"
                    f"&response_type=code"
                    f"&redirect_uri=http://testclient/callback/"
                    f"&scope=openid+profile"
                    f"&state=test-state-789"
                ),
            }),
            content_type="application/json",
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        # The root auth flow returns the next_url with OIDC params for the
        # client to complete the authorize exchange.
        redirect_url = body["redirect_url"]
        self.assertIn("client_id=test-client-id", redirect_url)
        self.assertIn("state=test-state-789", redirect_url)

    def test_jwks_endpoint_returns_valid_key(self):
        """The /openid/jwks/ endpoint must expose at least one RSA key."""
        resp = self.client.get(reverse("oidc_provider:jwks"))
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("keys", body)
        self.assertGreater(len(body["keys"]), 0)
        key = body["keys"][0]
        self.assertEqual(key["kty"], "RSA")
        self.assertIn("n", key)
        self.assertIn("e", key)
        self.assertIn("kid", key)


class PkceEnforcementTest(TestCase):
    """Verify PKCE S256 enforcement, Redis persistence, and token exchange."""

    def setUp(self):
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

        from oidc_provider.models import RSAKey as OIDCRSAKey
        from oidc_provider.models import Client as OIDCClient

        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        from oidc_provider.models import ResponseType
        self.client_obj = OIDCClient.objects.create(
            name="PKCE Test Client",
            client_type="confidential",
            client_id="pkce-test-client",
            client_secret="pkce-test-secret",
            jwt_alg="RS256",
            _redirect_uris="http://testclient/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.client_obj.response_types.add(ResponseType.objects.get(value="code"))

        self.did = _make_did(pub_bytes)
        self.user, _ = User.objects.get_or_create(
            custodial_did=self.did,
            defaults={"email": f"test_{self.did[:20]}@iyou.me"},
        )

    def _oidc_url(self, method="S256", code_challenge_value=None):
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        if code_challenge_value is None:
            code_challenge_value = (
                urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
                .decode("utf-8")
                .replace("=", "")
            )
        return (
            f"/openid/authorize/"
            f"?client_id={self.client_obj.client_id}"
            f"&response_type=code"
            f"&redirect_uri=http://testclient/callback/"
            f"&scope=openid+profile"
            f"&state=pkce-state"
            f"&code_challenge={code_challenge_value}"
            f"&code_challenge_method={method}"
        ), code_verifier

    def test_s256_challenge_persisted_in_redis(self):
        from auth_bridge.views import _build_oidc_redirect
        url, _ = self._oidc_url("S256")
        redirect = _build_oidc_redirect(url, self.user)
        self.assertIsNotNone(redirect)
        self.assertIn("code=", redirect)

        from oidc_provider.models import Code
        code_obj = Code.objects.order_by('-id').first()
        self.assertIsNotNone(code_obj)
        self.assertEqual(code_obj.code_challenge_method, "S256")

        pkce_key = f"pkce:{code_obj.code}"
        cached = cache.get(pkce_key)
        self.assertIsNotNone(cached)
        data = json.loads(cached)
        self.assertEqual(data["code_challenge_method"], "S256")
        self.assertIsNotNone(data["code_challenge"])

    def test_plain_method_rejected(self):
        from auth_bridge.views import _build_oidc_redirect
        url, _ = self._oidc_url("plain")
        redirect = _build_oidc_redirect(url, self.user)
        self.assertIsNone(redirect)

    def test_token_exchange_succeeds_with_valid_verifier(self):
        from auth_bridge.views import _build_oidc_redirect
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        url, _ = self._oidc_url("S256")
        redirect = _build_oidc_redirect(url, self.user)
        self.assertIsNotNone(redirect)

        from oidc_provider.models import Code
        code_obj = Code.objects.order_by('-id').first()
        self.assertIsNotNone(code_obj)
        code = code_obj.code

        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://testclient/callback/",
                "client_id": self.client_obj.client_id,
                "client_secret": self.client_obj.client_secret,
                "code_verifier": code_verifier,
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("access_token", body)
        self.assertIn("id_token", body)
        self.assertEqual(body["token_type"], "bearer")

    def test_token_exchange_fails_with_invalid_verifier(self):
        from auth_bridge.views import _build_oidc_redirect
        url, _ = self._oidc_url("S256")
        redirect = _build_oidc_redirect(url, self.user)
        self.assertIsNotNone(redirect)

        from oidc_provider.models import Code
        code_obj = Code.objects.order_by('-id').first()
        self.assertIsNotNone(code_obj)
        code = code_obj.code

        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://testclient/callback/",
                "client_id": self.client_obj.client_id,
                "client_secret": self.client_obj.client_secret,
                "code_verifier": "wrong_verifier_value_0000000000000000000",
            },
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertEqual(body["error"], "invalid_grant")

        pkce_key = f"pkce:{code}"
        self.assertIsNone(cache.get(pkce_key))

    def test_token_without_verifier_when_pkce_required(self):
        from auth_bridge.views import _build_oidc_redirect
        url, _ = self._oidc_url("S256")
        redirect = _build_oidc_redirect(url, self.user)
        self.assertIsNotNone(redirect)

        from oidc_provider.models import Code
        code_obj = Code.objects.order_by('-id').first()
        code = code_obj.code

        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://testclient/callback/",
                "client_id": self.client_obj.client_id,
                "client_secret": self.client_obj.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertEqual(body["error"], "invalid_grant")
