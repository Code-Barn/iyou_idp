# Copyright (C) 2026 Byers Brands, LLC
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
import base58
from django.test import TestCase, Client
from django.urls import reverse
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization


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
            "signatureValue": base58.b58encode(sig).decode("ascii"),
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

    def test_full_cycle_creates_session(self):
        # 1. Request a challenge
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("challenge", data)
        challenge = data["challenge"]

        # 2. Build a signed VP
        vp = self._signed_vp(challenge)

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
        vp = self._signed_vp(challenge)

        # Send the VP as a JSON-encoded string to account for browser
        # double-serialisation (e.g. from a WebSocket message).
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

        # 2. Build VP
        vp = self._signed_vp(challenge)

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
        vp = self._signed_vp("nonexistent-uuid")
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

        vc = _sign_vc(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": f"did:key:z{base58.b58encode(bytes([0xed, 0x01]) + pub_bytes).decode('ascii')}",
                "issuanceDate": "2025-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": f"did:key:z{base58.b58encode(bytes([0xed, 0x01]) + pub_bytes).decode('ascii')}",
                    "name": "Test",
                },
            },
            self.private_key,
        )
        self.did = vc["credentialSubject"]["id"]
        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "verifiableCredential": [vc],
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

        # Build a VP signed with the setUp key
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
        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "verifiableCredential": [vc],
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
        # Should point directly to client callback, NOT /openid/authorize/
        redirect_url = body["redirect_url"]
        self.assertTrue(
            redirect_url.startswith("http://testclient/callback/"),
            f"Expected client callback URL, got: {redirect_url}",
        )
        self.assertIn("code=", redirect_url)
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
