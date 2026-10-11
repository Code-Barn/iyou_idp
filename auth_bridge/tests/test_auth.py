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
Production Release Hardening Tests:
- Cache resilience & LocMem fallback
- Empty string email invariant (NULL in DB, preventing UniqueViolation)
- Nonce & signature verification (TTL expiration, empty nonce rejection, mismatch rejection)
- OIDC consent skip for mesh satellites
- Redirect URI sanitization (blocking .svc.cluster.local)
"""

import json
from unittest.mock import patch
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.core.cache.backends.locmem import LocMemCache
from django.test import Client as TestClient, TestCase
from django.urls import reverse
from oidc_provider.models import Client as OIDCClient, ResponseType, RSAKey as OIDCRSAKey

from auth_bridge.models import User
from auth_bridge.resilient_cache import ResilientCache
from auth_bridge.views import _build_oidc_redirect, _is_safe_public_redirect, cache as views_cache


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
            "created": "2026-01-01T00:00:00Z",
            "verificationMethod": f"{obj['holder']}#keys-1",
            "proofPurpose": "authentication",
            "signatureValue": sig.hex(),
        },
    }


class CacheResilienceAuditTest(TestCase):
    """Confirm challenge generation and verification gracefully fallback to LocMemCache."""

    def setUp(self):
        self.client = TestClient()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.did = _make_did(pub_bytes)

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

    def test_resilient_cache_fallback_on_primary_failure(self):
        """ResilientCache delegates to LocMemCache when primary raises any exception."""
        test_locmem = LocMemCache("test_locmem", {})
        resilient = ResilientCache(primary_cache=views_cache._primary, fallback_cache=test_locmem)

        with patch.object(views_cache._primary, "set", side_effect=Exception("Redis connection error")):
            with patch.object(views_cache._primary, "get", side_effect=Exception("Redis connection error")):
                resilient.set("test_key", "test_value", timeout=60)
                self.assertEqual(resilient.get("test_key"), "test_value")

    def test_challenge_issuance_never_500_on_redis_outage(self):
        """POST /auth/challenge/ succeeds and returns 200 with challenge UUID during Redis outage."""
        with patch.object(views_cache._primary, "set", side_effect=Exception("Redis unavailable")):
            with patch.object(views_cache._primary, "get", side_effect=Exception("Redis unavailable")):
                resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
                self.assertEqual(resp.status_code, 200)
                data = resp.json()
                self.assertIn("challenge", data)
                self.assertTrue(data.get("stored"))


class EmptyStringEmailInvariantTest(TestCase):
    """Ensure absent emails are strictly stored as NULL (None), never empty string."""

    def setUp(self):
        self.client = TestClient()
        self.private_key1 = ed25519.Ed25519PrivateKey.generate()
        self.did1 = _make_did(
            self.private_key1.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        self.private_key2 = ed25519.Ed25519PrivateKey.generate()
        self.did2 = _make_did(
            self.private_key2.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )

    def test_user_model_converts_empty_email_to_none(self):
        user1 = User.objects.create_user(email="", custodial_did="did:test:user1")
        self.assertIsNone(user1.email)

        user2 = User.objects.create_user(email="   ", custodial_did="did:test:user2")
        self.assertIsNone(user2.email)

        # Saving directly with empty string
        user3 = User(email="", custodial_did="did:test:user3")
        user3.save()
        self.assertIsNone(user3.email)

    def test_multiple_sovereign_users_without_email_do_not_violate_unique_constraint(self):
        """Multiple sovereign users with None email can coexist without UniqueViolation."""
        user1, created1 = User.objects.get_or_create(custodial_did=self.did1, defaults={"email": None})
        user2, created2 = User.objects.get_or_create(custodial_did=self.did2, defaults={"email": None})

        self.assertTrue(created1)
        self.assertTrue(created2)
        self.assertIsNone(user1.email)
        self.assertIsNone(user2.email)


class SignatureAndNonceAuditTest(TestCase):
    """Verify challenge expiration, nonce checks, and replay defense."""

    def setUp(self):
        self.client = TestClient()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.did = _make_did(pub_bytes)

    def _master_vp(self, challenge: str, holder: str = None) -> dict:
        holder = holder or self.did
        return _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": holder,
                "challenge": challenge,
                "verifiableCredential": [],
                "issuer": holder,
            },
            self.private_key,
        )

    def test_expired_or_nonexistent_challenge_returns_400(self):
        vp = self._master_vp("expired-challenge-uuid")
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": "expired-challenge-uuid",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Challenge expired", resp.json().get("error", ""))

    def test_empty_nonce_rejected_400(self):
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": {"type": ["VerifiablePresentation"]},
                "challenge": "",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_mismatched_nonce_in_proof_returns_401(self):
        # 1. Issue real challenge
        ch_resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        challenge = ch_resp.json()["challenge"]

        # 2. Build VP with different nonce in proof
        vp = self._master_vp("different-challenge-nonce")

        # 3. Submit with issued challenge
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("mismatch", resp.json().get("error", "").lower())


class OIDCConsentAndRedirectSanitizationTest(TestCase):
    """Verify consent skipping for internal mesh and redirect URL sanitization."""

    def setUp(self):
        self.client = TestClient()
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        code_type, _ = ResponseType.objects.get_or_create(value="code")
        self.satellite_client, _ = OIDCClient.objects.get_or_create(
            client_id="test-mesh-satellite-client",
            defaults={
                "name": "Test Mesh Client",
                "client_type": "public",
                "client_secret": "",
                "jwt_alg": "RS256",
                "_redirect_uris": "https://wun.iyou.me/oidc/callback/\nhttp://127.0.0.1:8001/oidc/callback/",
                "_scope": "openid profile email",
                "require_consent": False,
                "reuse_consent": True,
            },
        )
        self.satellite_client.response_types.add(code_type)

        self.user, _ = User.objects.get_or_create(custodial_did="did:key:testuser123", defaults={"email": None})

    def test_safe_public_redirect_validation(self):
        self.assertTrue(_is_safe_public_redirect("https://wun.iyou.me/oidc/callback/"))
        self.assertTrue(_is_safe_public_redirect("http://127.0.0.1:8001/oidc/callback/"))
        self.assertFalse(_is_safe_public_redirect("http://iyou-wun.identity.svc.cluster.local:8000/oidc/callback/"))
        self.assertFalse(_is_safe_public_redirect("http://internal.service.cluster.local/callback/"))
        self.assertFalse(_is_safe_public_redirect(""))

    def test_oidc_redirect_skips_consent_for_satellite_client(self):
        oidc_req = (
            f"/openid/authorize/"
            f"?client_id={self.satellite_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://wun.iyou.me/oidc/callback/"
            f"&scope=openid+profile"
            f"&state=mesh-state-999"
        )
        redirect_url = _build_oidc_redirect(oidc_req, self.user)
        self.assertIsNotNone(redirect_url)
        self.assertTrue(redirect_url.startswith("https://wun.iyou.me/oidc/callback/"))
        self.assertIn("code=", redirect_url)
        self.assertIn("state=mesh-state-999", redirect_url)

    def test_oidc_redirect_blocks_internal_k8s_dns_redirect(self):
        """Redirect URIs targeting internal cluster DNS must be rejected."""
        fake_client = OIDCClient.objects.create(
            name="Internal Cluster Client",
            client_type="public",
            client_id="internal-cluster-client",
            client_secret="",
            jwt_alg="RS256",
            _redirect_uris="http://iyou-wun.identity.svc.cluster.local:8000/oidc/callback/",
            _scope="openid profile",
            require_consent=False,
        )
        fake_client.response_types.add(ResponseType.objects.get(value="code"))

        oidc_req = (
            f"/openid/authorize/"
            f"?client_id={fake_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=http://iyou-wun.identity.svc.cluster.local:8000/oidc/callback/"
            f"&scope=openid+profile"
            f"&state=bad-k8s-state"
        )
        redirect_url = _build_oidc_redirect(oidc_req, self.user)
        self.assertIsNone(redirect_url)


class CanonicalJcsSignatureVerificationTest(TestCase):
    """
    Forensic regression tests ensuring RFC 8785 JSON Canonicalization Scheme (JCS)
    signatures issued by iyou_home / did_rust verify cleanly via Tier 1 Ed25519.
    """

    def setUp(self):
        self.client = TestClient()
        self.live_vp = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": "did:key:z6MkujsSdMm1j7QqUNaZo8U8kkcJNfFNikUQYJzmZX4wwgND",
            "challenge": "7edf7d19-392e-4de0-bdc8-0205cbfe6120",
            "verifiableCredential": [],
            "issuer": "did:key:z6MkujsSdMm1j7QqUNaZo8U8kkcJNfFNikUQYJzmZX4wwgND",
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:key:z6MkujsSdMm1j7QqUNaZo8U8kkcJNfFNikUQYJzmZX4wwgND#keys-1",
                "proofValue": "6643eb9466e31c81ec31ca2d77ff81dff479f0832b6562463e12850fb241a06a3b57767fee764bc5c797505839e443dd99418adaa6db1b2b6b411eaf8f7de90b",
            },
        }

    def test_exact_live_iyou_home_vp_verifies_via_tier1(self):
        """Live desktop Verifiable Presentation verifies cleanly via Tier 1 Ed25519."""
        challenge = self.live_vp["challenge"]
        views_cache.set(challenge, json.dumps({"challenge": challenge, "status": "pending"}), timeout=300)

        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": self.live_vp,
                "challenge": challenge,
            }),
            content_type="application/json",
            REMOTE_ADDR="127.0.0.1",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("user", {}).get("did"), self.live_vp["holder"])
        self.assertTrue(data.get("user", {}).get("is_authenticated"))

    def test_tampered_payload_rejected_under_production_lockdown(self):
        """Tampered payload with DEBUG=False must return 401."""
        challenge = "tampered-challenge-nonce"
        views_cache.set(challenge, json.dumps({"challenge": challenge, "status": "pending"}), timeout=300)
        vp = dict(self.live_vp, challenge=challenge)
        vp["proof"] = dict(vp["proof"], proofValue="00" * 64)

        with self.settings(DEBUG=False, ALLOW_EMERGENCY_BYPASS=False, ENABLE_DEV_AUTH_BYPASS=False):
            resp = self.client.post(
                reverse("auth_bridge:verify_signature"),
                data=json.dumps({
                    "verifiable_presentation": vp,
                    "challenge": challenge,
                }),
                content_type="application/json",
                REMOTE_ADDR="127.0.0.1",
            )
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.json().get("error"), "Signature verification failed")

    def test_dev_loopback_bypass_when_debug_enabled(self):
        """Under DEBUG=True, emergency bypass successfully authenticates local loopback."""
        challenge = "dev-bypass-challenge-nonce"
        views_cache.set(challenge, json.dumps({"challenge": challenge, "status": "pending"}), timeout=300)
        vp = dict(self.live_vp, challenge=challenge)
        vp["proof"] = dict(vp["proof"], proofValue="00" * 64)

        with self.settings(DEBUG=True):
            resp = self.client.post(
                reverse("auth_bridge:verify_signature"),
                data=json.dumps({
                    "verifiable_presentation": vp,
                    "challenge": challenge,
                }),
                content_type="application/json",
                REMOTE_ADDR="127.0.0.1",
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.json().get("success"))
