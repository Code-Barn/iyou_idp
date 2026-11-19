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

from datetime import timedelta
import json
from unittest.mock import patch
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.contrib import admin
from django.core.cache.backends.locmem import LocMemCache
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.test import Client as TestClient, RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
from oidc_provider.models import Client as OIDCClient, ResponseType, RSAKey as OIDCRSAKey

from auth_bridge.admin import (
    FederatedIdentityAdmin,
    IssuedCredentialAdmin,
    LinkedEmailAdmin,
    PasskeyCredentialAdmin,
    SovereignInfrastructureLeaseAdmin,
    UserAdmin,
)
from auth_bridge.middleware import SSOHintCookieMiddleware
from auth_bridge.models import (
    FederatedIdentity,
    IssuedCredential,
    LinkedEmail,
    PasskeyCredential,
    SovereignInfrastructureLease,
    User,
)
from auth_bridge.resilient_cache import ResilientCache
from auth_bridge.signals import SSO_HINT_MARKER, mark_sso_hint_on_login, mark_sso_hint_on_logout
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

    def test_primary_email_credential_returns_404_for_user_without_email(self):
        user, _ = User.objects.get_or_create(custodial_did=self.did1, defaults={"email": None})
        self.client.force_login(user)
        response = self.client.get(reverse("auth_bridge:email_link_credential"))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"], "no_primary_email")


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

        with self.settings(DEBUG=False, IDP_ALLOW_EMERGENCY_BYPASS=False):
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
            self.assertEqual(resp.json().get("error"), "Invalid cryptographic signature.")

    def test_dev_loopback_bypass_rejected_under_debug_by_default(self):
        """Under DEBUG=True, emergency bypass is rejected by default with 401."""
        challenge = "dev-bypass-challenge-nonce"
        views_cache.set(challenge, json.dumps({"challenge": challenge, "status": "pending"}), timeout=300)
        vp = dict(self.live_vp, challenge=challenge)
        vp["proof"] = dict(vp["proof"], proofValue="00" * 64)

        with self.settings(DEBUG=True, IDP_ALLOW_EMERGENCY_BYPASS=False):
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
            self.assertEqual(resp.json().get("error"), "Invalid cryptographic signature.")

    def test_dev_loopback_bypass_when_explicitly_enabled(self):
        """Emergency bypass succeeds when IDP_ALLOW_EMERGENCY_BYPASS=True."""
        challenge = "dev-bypass-challenge-nonce-enabled"
        views_cache.set(challenge, json.dumps({"challenge": challenge, "status": "pending"}), timeout=300)
        vp = dict(self.live_vp, challenge=challenge)
        vp["proof"] = dict(vp["proof"], proofValue="00" * 64)

        with self.settings(DEBUG=True, IDP_ALLOW_EMERGENCY_BYPASS=True, SYSTEM_GATE_ENABLED=False):
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


class GlobalLogoutViewTest(TestCase):
    def setUp(self):
        self.client = TestClient()
        self.user = User.objects.create_user(
            email="logout_user@iyou.me",
            custodial_did="did:key:logout-user",
        )

    def test_logout_flushes_session_and_clears_cookies(self):
        self.client.force_login(self.user)
        self.client.cookies["idp_csrftoken"] = "a" * 32
        self.client.cookies["iyou_sso_hint"] = "1"

        response = self.client.get(reverse("auth_bridge:global_logout"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(response.cookies["idp_csrftoken"].value, "")
        self.assertEqual(response.cookies["iyou_sso_hint"].value, "")

    def test_logout_allows_local_relative_next(self):
        self.client.force_login(self.user)
        response = self.client.get(f"{reverse('auth_bridge:global_logout')}?next=/gate/")
        self.assertEqual(response["Location"], "/gate/")

    def test_logout_rejects_external_open_redirect(self):
        self.client.force_login(self.user)
        response = self.client.get(
            f"{reverse('auth_bridge:global_logout')}?next=https://evil.example/"
        )
        self.assertEqual(response["Location"], "/")


class LoginPageCacheHeaderTest(TestCase):
    def setUp(self):
        self.client = TestClient()

    def test_login_page_has_no_store_headers(self):
        response = self.client.get(reverse("auth_bridge:login"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("no-cache", response["Cache-Control"])
        self.assertEqual(response["Pragma"], "no-cache")

    def test_dashboard_has_no_store_headers(self):
        user = User.objects.create_user(
            email="cached_user@iyou.me",
            custodial_did="did:key:cached-dashboard",
        )
        self.client.force_login(user)
        response = self.client.get(reverse("auth_bridge:login"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "auth_bridge/authenticated_dashboard.html")
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Pragma"], "no-cache")


class PassiveLoginLoadAndExplicitActionTest(TestCase):
    """
    Verify GET / and GET /auth/login/ load passively with zero background
    POST /auth/challenge/ requests and zero WebSocket connections, while
    preserving explicit user-initiated click handlers.
    """

    def setUp(self):
        self.client = TestClient()

    def test_login_endpoints_render_passively_without_auto_challenge_or_websocket(self):
        endpoints = ["/", reverse("auth_bridge:login")]
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 200)
                html = response.content.decode("utf-8")

                # Verify state initializes passively
                self.assertIn("let currentChallenge = null;", html)
                self.assertIn('window.sovereignConnectionLock = "IDLE";', html)

                # Extract init() function body from HTML
                init_start = html.find("function init() {")
                self.assertNotEqual(init_start, -1, "init() function missing")
                init_end = html.find("function tryConnectIYouHome()", init_start)
                self.assertNotEqual(init_end, -1, "tryConnectIYouHome() function missing")
                init_body = html[init_start:init_end]

                # Assert init() does NOT invoke fetchChallenge or tryConnectIYouHome
                self.assertNotIn("fetchChallenge(", init_body)
                self.assertNotIn("tryConnectIYouHome(", init_body)

                # Verify explicit click handlers are bound inside init()
                self.assertIn("iyouBtn.addEventListener('click', signWithIYouHome);", init_body)
                self.assertIn("requestChallengeBtn.addEventListener('click', requestChallenge);", init_body)

                # Verify Tab 0 buttons
                self.assertIn('id="iyouHomeBtn"', html)
                self.assertIn("Sign in with iyou_home", html)
                self.assertIn('id="requestChallengeBtn"', html)
                self.assertIn("Manual Paste / Request Challenge", html)

                # Verify Community Tab 1 lazy initialization
                self.assertIn("if (idx === 1) {\n                    initCommunityTab();", html)
                self.assertIn('id="refreshCommunityQrBtn"', html)
                self.assertIn("refreshQrBtn.addEventListener('click', () => initCommunityTab());", html)

    def test_community_tab_activation_lazy_loads_qr_challenge(self):
        response = self.client.get(reverse("auth_bridge:login") + "?tab=community")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode("utf-8")
        self.assertIn("activateTab(activeIdx);", html)
        self.assertIn("initCommunityTab()", html)


class SSOHintCookieTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email="sso_user@iyou.me",
            custodial_did="did:key:sso-hint",
        )

    def _run_middleware(self, request):
        return SSOHintCookieMiddleware(lambda req: HttpResponse("ok"))(request)

    def test_signal_receivers_mark_request(self):
        request = self.factory.get("/")
        mark_sso_hint_on_login(sender=User, request=request, user=self.user)
        self.assertEqual(getattr(request, SSO_HINT_MARKER), "set")
        mark_sso_hint_on_logout(sender=User, request=request, user=self.user)
        self.assertEqual(getattr(request, SSO_HINT_MARKER), "delete")

    def test_middleware_sets_hint_on_login(self):
        request = self.factory.get("/")
        request.COOKIES = {}
        setattr(request, SSO_HINT_MARKER, "set")
        response = self._run_middleware(request)
        self.assertEqual(response.cookies["iyou_sso_hint"].value, "1")

    def test_middleware_suppresses_hint_when_opted_out(self):
        request = self.factory.get("/")
        request.COOKIES = {"iyou_sso_opt_out": "1"}
        setattr(request, SSO_HINT_MARKER, "set")
        response = self._run_middleware(request)
        self.assertEqual(response.cookies["iyou_sso_hint"].value, "")

    def test_middleware_deletes_hint_on_logout(self):
        request = self.factory.get("/")
        request.COOKIES = {"iyou_sso_hint": "1"}
        setattr(request, SSO_HINT_MARKER, "delete")
        response = self._run_middleware(request)
        self.assertEqual(response.cookies["iyou_sso_hint"].value, "")

    def test_sso_preference_requires_authentication(self):
        response = TestClient().post(
            reverse("auth_bridge:sso_preference"),
            data=json.dumps({"auto_login": False}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "authentication_required")

    def test_sso_preference_toggle(self):
        client = TestClient()
        client.force_login(self.user)
        url = reverse("auth_bridge:sso_preference")

        disable = client.post(url, data=json.dumps({"auto_login": False}), content_type="application/json")
        self.assertEqual(disable.status_code, 200)
        self.assertFalse(disable.json()["auto_login"])
        self.assertEqual(client.cookies["iyou_sso_opt_out"].value, "1")
        self.assertEqual(client.cookies["iyou_sso_hint"].value, "")

        enable = client.post(url, data=json.dumps({"auto_login": True}), content_type="application/json")
        self.assertEqual(enable.status_code, 200)
        self.assertTrue(enable.json()["auto_login"])
        self.assertEqual(client.cookies["iyou_sso_opt_out"].value, "")
        self.assertEqual(client.cookies["iyou_sso_hint"].value, "1")


class SovereignModelAdminTests(TestCase):
    def setUp(self) -> None:
        self.site = admin.AdminSite()
        self.user = User.objects.create(
            email="sovereign_admin_test@iyou.me",
            custodial_did="did:key:zSovereignAdminUser",
            account_tier="sovereign",
            is_sovereign=True,
        )
        self.request = RequestFactory().get("/admin/")

    def test_actions_disabled_by_default(self) -> None:
        user_admin = UserAdmin(User, self.site)
        self.assertIsNone(user_admin.actions)

    def test_immutable_fields_marked_readonly_on_edit(self) -> None:
        user_admin = UserAdmin(User, self.site)
        add_readonly = user_admin.get_readonly_fields(self.request, obj=None)
        self.assertEqual(add_readonly, ())

        change_readonly = user_admin.get_readonly_fields(self.request, obj=self.user)
        for field in user_admin.immutable_fields:
            self.assertIn(field, change_readonly)

    def test_save_model_raises_validation_error_on_immutable_field_mutation(self) -> None:
        user_admin = UserAdmin(User, self.site)
        self.user.custodial_did = "did:key:zTamperedDid"
        with self.assertRaises(ValidationError) as cm:
            user_admin.save_model(self.request, self.user, form=None, change=True)
        self.assertIn("Field 'custodial_did' is immutable", str(cm.exception))

    def test_save_model_permits_mutable_field_update(self) -> None:
        user_admin = UserAdmin(User, self.site)
        self.user.account_tier = "managed_free"
        user_admin.save_model(self.request, self.user, form=None, change=True)
        self.user.refresh_from_db()
        self.assertEqual(self.user.account_tier, "managed_free")

    def test_issued_credential_ledger_immutability_and_permissions(self) -> None:
        cred = IssuedCredential.objects.create(
            subject_did="did:key:zSubjectLeaf",
            issuer_did="did:key:zIssuerParent",
            bracket="U14",
        )
        cred_admin = IssuedCredentialAdmin(IssuedCredential, self.site)
        self.assertFalse(cred_admin.has_add_permission(self.request))
        self.assertFalse(cred_admin.has_delete_permission(self.request, obj=cred))

        cred.subject_did = "did:key:zTamperedSubject"
        with self.assertRaises(ValidationError) as cm:
            cred_admin.save_model(self.request, cred, form=None, change=True)
        self.assertIn("Field 'subject_did' is immutable", str(cm.exception))

    def test_append_only_models_disallow_add_permission(self) -> None:
        passkey_admin = PasskeyCredentialAdmin(PasskeyCredential, self.site)
        linked_email_admin = LinkedEmailAdmin(LinkedEmail, self.site)
        federated_identity_admin = FederatedIdentityAdmin(FederatedIdentity, self.site)

        self.assertFalse(passkey_admin.has_add_permission(self.request))
        self.assertFalse(linked_email_admin.has_add_permission(self.request))
        self.assertFalse(federated_identity_admin.has_add_permission(self.request))

    def test_sovereign_infra_lease_admin_immutability(self) -> None:
        lease = SovereignInfrastructureLease.objects.create(
            user=self.user,
            billing_token_hash="hash123",
            expires_at=timezone.now() + timedelta(days=30),
        )
        lease_admin = SovereignInfrastructureLeaseAdmin(SovereignInfrastructureLease, self.site)
        lease.billing_token_hash = "tampered_hash"
        with self.assertRaises(ValidationError) as cm:
            lease_admin.save_model(self.request, lease, form=None, change=True)
        self.assertIn("Field 'billing_token_hash' is immutable", str(cm.exception))


