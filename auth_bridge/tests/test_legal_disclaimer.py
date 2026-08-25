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
Integration tests for the post-login Legal Disclaimer Gate in iyou_idp.
"""

import json
from unittest.mock import patch
from django.test import TestCase, Client
from django.urls import reverse
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization

from auth_bridge.models import User
from auth_bridge.tests import _make_did, _sign


class LegalDisclaimerGateUITest(TestCase):
    """Verify Legal Disclaimer modal markup, text content, and controls."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="disclaimer_test@iyou.me",
            custodial_did="did:web:iyou.me:user:test-disclaimer",
        )

    def test_modal_present_in_login_page(self):
        resp = self.client.get(reverse("auth_bridge:login"))
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode("utf-8")

        # Header check
        self.assertIn("Sovereign Network Access &amp; Legal Notice", content)

        # 4 Required Body Sections
        self.assertIn("Cryptographic Keyholder Liability", content)
        self.assertIn("All interactions, broadcasts, and data payloads are signed using your sovereign cryptographic keys.", content)
        self.assertIn("You bear sole legal and operational responsibility for the content generated via your identity.", content)

        self.assertIn("Neutral Conduit &amp; Protocol Interface", content)
        self.assertIn("This node instance acts strictly as an open-source indexing interface and communication gateway.", content)
        self.assertIn("The operator does not host, author, or curate third-party mesh communications.", content)

        self.assertIn("Node Operator Policies", content)
        self.assertIn("In accordance with jurisdiction baseline compliance, this gateway explicitly prohibits illegal conduct", content)
        self.assertIn("(including CSAM and direct incitement to violence).", content)
        self.assertIn("The operator reserves the right to filter, de-index, or drop packet visibility at the gateway level.", content)

        self.assertIn("Open Source Ecosystem", content)
        self.assertIn('Core software operates under GPLv3. Service is provided "as is" with no express warranties.', content)

        # Controls Check
        self.assertIn("Show this legal disclaimer on next login", content)
        self.assertIn("Acknowledge and Proceed", content)
        self.assertIn('id="disclaimer-show-next-checkbox"', content)
        self.assertIn('checked', content)

    def test_disclaimer_standalone_view_requires_auth(self):
        resp = self.client.get(reverse("auth_bridge:legal_disclaimer"))
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].startswith(reverse("auth_bridge:login")))

    def test_disclaimer_standalone_view_authenticated(self):
        from urllib.parse import quote
        self.client.force_login(self.user)
        target_next = "https://satellite.iyou.me/callback/?code=test&state=123"
        resp = self.client.get(f"{reverse('auth_bridge:legal_disclaimer')}?next={quote(target_next, safe='')}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["next_url"], target_next)
        content = resp.content.decode("utf-8")
        self.assertIn("Sovereign Network Access &amp; Legal Notice", content)
        self.assertIn("Acknowledge and Proceed", content)
        self.assertIn("https://satellite.iyou.me/callback/", content)

    def test_disclaimer_defaults_to_wun_when_no_next_provided(self):
        self.client.force_login(self.user)
        resp = self.client.get(reverse("auth_bridge:legal_disclaimer"))
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode("utf-8")
        self.assertIn(settings.IDP_WUN_URL, content)


class LegalDisclaimerStatePersistenceTest(TestCase):
    """Verify preference persistence and dismissal logic."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="persist_test@iyou.me",
            custodial_did="did:web:iyou.me:user:test-persist",
        )

    def test_default_user_show_legal_disclaimer_is_true(self):
        self.assertTrue(self.user.show_legal_disclaimer)

    def test_acknowledge_requires_authentication(self):
        resp = self.client.post(
            reverse("auth_bridge:legal_disclaimer_acknowledge"),
            data=json.dumps({"show_on_next": False}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)

    def test_acknowledge_with_checkbox_checked_retains_disclaimer(self):
        self.client.force_login(self.user)
        resp = self.client.post(
            reverse("auth_bridge:legal_disclaimer_acknowledge"),
            data=json.dumps({"show_on_next": True}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["show_legal_disclaimer"])

        self.user.refresh_from_db()
        self.assertTrue(self.user.show_legal_disclaimer)

    def test_acknowledge_with_checkbox_unchecked_persists_bypass(self):
        self.client.force_login(self.user)
        resp = self.client.post(
            reverse("auth_bridge:legal_disclaimer_acknowledge"),
            data=json.dumps({"show_on_next": False}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertFalse(data["show_legal_disclaimer"])

        self.user.refresh_from_db()
        self.assertFalse(self.user.show_legal_disclaimer)
        self.assertIsNotNone(self.user.disclaimer_acknowledged_at)

    def test_acknowledge_endpoint_alias_disclaimer_acknowledge(self):
        self.client.force_login(self.user)
        resp = self.client.post(
            reverse("auth_bridge:disclaimer_acknowledge"),
            data=json.dumps({"show_on_next": False}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["show_legal_disclaimer"])


class LegalDisclaimerFlowAndRoutingTest(TestCase):
    """Verify DID verification, OAuth, and OIDC state continuity with disclaimer gate."""

    def setUp(self):
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.did = _make_did(pub_bytes)

        # OIDC RSA key
        from oidc_provider.models import RSAKey as OIDCRSAKey, Client as OIDCClient, ResponseType
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        self.oidc_client = OIDCClient.objects.create(
            name="Satellite App",
            client_type="public",
            client_id="test-satellite-client",
            client_secret="",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.oidc_client.response_types.add(ResponseType.objects.get(value="code"))

    def _get_signed_vp(self, challenge: str) -> dict:
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

    def test_verify_signature_returns_show_legal_disclaimer_flag(self):
        # 1. Challenge
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        challenge = resp.json()["challenge"]

        # 2. Verify
        vp = self._get_signed_vp(challenge)
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("show_legal_disclaimer", data)
        self.assertTrue(data["show_legal_disclaimer"])
        self.assertTrue(data["user"]["show_legal_disclaimer"])

    def test_verify_signature_preserves_oidc_redirect_url(self):
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        challenge = resp.json()["challenge"]

        next_url = (
            f"/openid/authorize/"
            f"?client_id={self.oidc_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile"
            f"&state=custom-oidc-state-456"
        )
        vp = self._get_signed_vp(challenge)
        resp = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
                "next_url": next_url,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        redirect_url = data["redirect_url"]
        self.assertIn("client_id=test-satellite-client", redirect_url)
        self.assertIn("state=custom-oidc-state-456", redirect_url)
        self.assertTrue(data["show_legal_disclaimer"])

    def test_oauth_callback_routes_through_disclaimer_when_active(self):
        user = User.objects.create_user(
            email="oauth_disclaimer@iyou.me",
            custodial_did="did:web:iyou.me:user:oauth-user",
        )
        self.assertTrue(user.show_legal_disclaimer)

        with patch("auth_bridge.views_oauth.OAuthCallbackView._exchange_code", return_value={"access_token": "mock"}), \
             patch("auth_bridge.views_oauth.OAuthCallbackView._fetch_userinfo", return_value={"sub": "12345", "email": "oauth_disclaimer@iyou.me"}):

            session = self.client.session
            session["oauth_state"] = "valid-state"
            session["oauth_provider"] = "google"
            session["oauth_next"] = "https://satellite.iyou.me/callback/?code=mockcode&state=mystate"
            session.save()

            resp = self.client.get(
                reverse("auth_bridge:oauth_callback", kwargs={"provider": "google"}),
                {"state": "valid-state", "code": "valid-code"},
            )
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp["Location"].startswith(reverse("auth_bridge:legal_disclaimer")))
            self.assertIn("next=", resp["Location"])
            self.assertIn("state%3Dmystate", resp["Location"])

    def test_oauth_callback_bypasses_disclaimer_when_user_has_bypassed(self):
        user = User.objects.create_user(
            email="oauth_bypassed@iyou.me",
            custodial_did="did:web:iyou.me:user:oauth-bypassed",
            show_legal_disclaimer=False,
        )
        self.assertFalse(user.show_legal_disclaimer)

        with patch("auth_bridge.views_oauth.OAuthCallbackView._exchange_code", return_value={"access_token": "mock"}), \
             patch("auth_bridge.views_oauth.OAuthCallbackView._fetch_userinfo", return_value={"sub": "54321", "email": "oauth_bypassed@iyou.me"}):

            session = self.client.session
            session["oauth_state"] = "valid-state"
            session["oauth_provider"] = "google"
            session["oauth_next"] = "https://satellite.iyou.me/callback/?state=mystate"
            session.save()

            resp = self.client.get(
                reverse("auth_bridge:oauth_callback", kwargs={"provider": "google"}),
                {"state": "valid-state", "code": "valid-code"},
            )
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp["Location"], "https://satellite.iyou.me/callback/?state=mystate")
