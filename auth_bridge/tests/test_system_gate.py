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
Sovereign Airlock gate tests:

- Non-admin DIDs are shown the beta gate when SYSTEM_GATE_ENABLED=True
- ADMIN_DID completes DID authentication and the OIDC code exchange unhindered
- Approved beta DIDs and redeemable invite keys unlock access
- iyou_home download modal is gated for unauthorized visitors
"""

import json
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from django.test import Client as TestClient, RequestFactory, TestCase, override_settings
from django.template.loader import render_to_string
from django.urls import reverse
from oidc_provider.models import Client as OIDCClient, ResponseType, RSAKey as OIDCRSAKey

from auth_bridge.models import User
from auth_bridge.tests import _make_did, _sign


class SovereignAirlockGateTest(TestCase):
    """Gate behavior on the DID challenge/verify flow."""

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

    def _challenge(self) -> str:
        resp = self.client.post(reverse("auth_bridge:challenge"), content_type="application/json")
        return resp.json()["challenge"]

    def _verify(self, challenge: str, vp: dict = None, next_url: str = "/openid/authorize/"):
        return self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps({
                "verifiable_presentation": vp or self._master_vp(challenge),
                "challenge": challenge,
                "next_url": next_url,
            }),
            content_type="application/json",
        )

    def test_non_admin_did_receives_gate_screen_when_gate_enabled(self):
        with override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID="did:key:unrelated-admin"):
            challenge = self._challenge()
            resp = self._verify(challenge)

        self.assertEqual(resp.status_code, 403)
        body = resp.content.decode("utf-8")
        self.assertIn("Private Beta", body)
        self.assertIn("Access is currently limited to authorized keys", body)
        self.assertIn('name="invite_key"', body)
        self.assertIn('name="did"', body)
        self.assertIn("waitlist", body.lower())

        # No session or user may be minted for an airlocked DID.
        self.assertFalse(User.objects.filter(custodial_did=self.did).exists())

    def test_admin_did_completes_oidc_exchange_unhindered(self):
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        code_type, _ = ResponseType.objects.get_or_create(value="code")
        client_obj = OIDCClient.objects.create(
            name="Admin Test Client",
            client_type="confidential",
            client_id="admin-test-client",
            client_secret="admin-test-secret",
            jwt_alg="RS256",
            _redirect_uris="http://testclient/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        client_obj.response_types.add(code_type)

        with override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID=self.did):
            challenge = self._challenge()
            oidc_authorize = (
                f"/openid/authorize/"
                f"?client_id={client_obj.client_id}"
                f"&response_type=code"
                f"&redirect_uri=http://testclient/callback/"
                f"&scope=openid+profile"
                f"&state=admin-state"
                f"&nonce=admin-nonce"
            )
            resp = self._verify(challenge, next_url=oidc_authorize)

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["user"]["did"], self.did)

        user = User.objects.get(custodial_did=self.did)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

        # The server-side Legal Gate requires one affirmative acknowledgment
        # before the front-channel will issue a code; complete it for the
        # admin so the OIDC exchange proceeds unhindered.
        with override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID=self.did):
            ack = self.client.post(
                reverse("auth_bridge:legal_disclaimer_acknowledge"),
                data=json.dumps({"consent_accepted": True}),
                content_type="application/json",
            )
        self.assertEqual(ack.status_code, 200)

        # OIDC front-channel authorize must issue a code without stumbling on the gate.
        authorize = None
        with override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID=self.did):
            authorize = self.client.get(
                reverse("oidc_provider:authorize"),
                {
                    "client_id": client_obj.client_id,
                    "response_type": "code",
                    "redirect_uri": "http://testclient/callback/",
                    "scope": "openid profile",
                    "state": "admin-state",
                    "nonce": "admin-nonce",
                },
            )
        self.assertEqual(authorize.status_code, 302)
        location = authorize["Location"]
        self.assertTrue(location.startswith("http://testclient/callback/"))
        code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code", [None])[0]
        self.assertIsNotNone(code)

        # Token exchange completes the OIDC flow unhindered.
        token = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://testclient/callback/",
                "client_id": client_obj.client_id,
                "client_secret": client_obj.client_secret,
            },
        )
        self.assertEqual(token.status_code, 200)
        token_body = token.json()
        self.assertIn("access_token", token_body)
        self.assertIn("id_token", token_body)

    def test_allowlisted_did_authenticates_when_gate_enabled(self):
        with override_settings(SYSTEM_GATE_ENABLED=True, BETA_ACCESS_ALLOWLIST=[self.did]):
            challenge = self._challenge()
            resp = self._verify(challenge)

        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])

    def test_gate_disabled_allows_non_admin_did(self):
        with override_settings(SYSTEM_GATE_ENABLED=False):
            challenge = self._challenge()
            resp = self._verify(challenge)

        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])


class BetaGateRedemptionTest(TestCase):
    """Invite-key redemption stamps the browser session with beta access."""

    def setUp(self):
        self.client = TestClient()

    def test_valid_invite_key_grants_beta_session_and_redirects(self):
        with override_settings(BETA_INVITE_KEYS=["INVITE-BETA-001"]):
            resp = self.client.post(
                reverse("auth_bridge:gate_redeem"),
                {"invite_key": "INVITE-BETA-001", "next_url": "/auth/login/"},
            )

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/auth/login/")
        self.assertTrue(self.client.session.get("beta_access"))

    def test_invalid_invite_key_rerenders_gate_without_access(self):
        resp = self.client.post(
            reverse("auth_bridge:gate_redeem"),
            {"invite_key": "NOT-ISSUED", "next_url": "/auth/login/"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("not been issued", resp.content.decode("utf-8"))
        self.assertIsNone(self.client.session.get("beta_access"))

    def test_allowlisted_did_submission_grants_beta_session(self):
        with override_settings(BETA_ACCESS_ALLOWLIST=["did:key:beta-tester-one"]):
            resp = self.client.post(
                reverse("auth_bridge:gate_redeem"),
                {"did": "did:key:beta-tester-one", "next_url": "/auth/login/"},
            )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))

    def test_gate_page_renders_with_waitlist_inputs(self):
        resp = self.client.get(reverse("auth_bridge:gate"))
        self.assertEqual(resp.status_code, 403)
        body = resp.content.decode("utf-8")
        self.assertIn("Sovereign Mesh Airlock", body)
        self.assertIn('name="invite_key"', body)
        self.assertIn('name="did"', body)


class GatedDownloadModalTest(TestCase):
    """iyou_home desktop downloads are gated behind admin/beta access."""

    def setUp(self):
        self.client = TestClient()

    def test_ungated_visitor_sees_early_access_card(self):
        resp = self.client.get(reverse("auth_bridge:login"))
        body = resp.content.decode("utf-8")
        self.assertIn("Early Access Key Required", body)
        self.assertNotIn("iyou-network/iyou_home/releases/download/", body)

    def test_beta_session_visitor_sees_real_download_links(self):
        session = self.client.session
        session["beta_access"] = True
        session.save()

        resp = self.client.get(reverse("auth_bridge:login"))
        body = resp.content.decode("utf-8")
        self.assertNotIn("Early Access Key Required", body)
        self.assertIn("https://github.com/iyou-network/iyou_home/releases/download/", body)

    def test_admin_user_sees_real_download_links_in_modal(self):
        admin = User.objects.create_user(
            email="admin_modal@iyou.me",
            custodial_did="did:key:modal-admin",
        )
        request = RequestFactory().get("/auth/login/")
        request.user = admin

        with override_settings(ADMIN_DID="did:key:modal-admin"):
            html = render_to_string(
                "auth_bridge/_download_modal.html",
                context={},
                request=request,
            )

        self.assertNotIn("Early Access Key Required", html)
        self.assertIn("https://github.com/iyou-network/iyou_home/releases/download/", html)


class DisclaimerAuthorizeGateTest(TestCase):
    """Server-side legal hard gate on the OIDC front-channel."""

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
        self.client_obj = OIDCClient.objects.create(
            name="Disclaimer Test Client",
            client_type="confidential",
            client_id="disclaimer-test-client",
            client_secret="disclaimer-test-secret",
            jwt_alg="RS256",
            _redirect_uris="http://testclient/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.client_obj.response_types.add(code_type)

        self.admin_did = "did:key:disclaimer-admin"
        self.user = User.objects.create_user(
            email="disclaimer_admin@iyou.me",
            custodial_did=self.admin_did,
            show_legal_disclaimer=True,
        )

    def _authorize(self):
        return self.client.get(
            reverse("sovereign_authorize"),
            {
                "client_id": self.client_obj.client_id,
                "response_type": "code",
                "redirect_uri": "http://testclient/callback/",
                "scope": "openid profile",
                "state": "disclaimer-state",
                "nonce": "disclaimer-nonce",
            },
        )

    def test_authorize_endpoint_blocks_when_disclaimer_unacknowledged(self):
        self.client.force_login(self.user, backend="django.contrib.auth.backends.ModelBackend")
        with override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID=self.admin_did):
            resp = self._authorize()

        # A 302 to the legal disclaimer page, NOT a code redirect.
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].startswith(reverse("auth_bridge:legal_disclaimer")))
        next_param = urllib.parse.parse_qs(
            urllib.parse.urlparse(resp["Location"]).query
        ).get("next", [None])[0]
        self.assertIsNotNone(next_param)
        self.assertIn("client_id=disclaimer-test-client", next_param)
        self.assertIn("state=disclaimer-state", next_param)

        resumed = self.client.session.get("post_disclaimer_redirect")
        self.assertIsNotNone(resumed)
        self.assertIn("client_id=disclaimer-test-client", resumed)
        self.assertIn("state=disclaimer-state", resumed)

    def test_authorize_endpoint_proceeds_after_disclaimer_acknowledged(self):
        self.client.force_login(self.user, backend="django.contrib.auth.backends.ModelBackend")
        with override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID=self.admin_did):
            blocked = self._authorize()
            self.assertTrue(blocked["Location"].startswith(reverse("auth_bridge:legal_disclaimer")))

            ack = self.client.post(
                reverse("auth_bridge:legal_disclaimer_acknowledge"),
                data=json.dumps({"consent_accepted": True}),
                content_type="application/json",
            )

            # OIDC flow now completes unhindered with a real authorization code.
            authorize = self._authorize()

        self.assertEqual(ack.status_code, 200)
        ack_data = ack.json()
        self.assertTrue(ack_data["success"])
        self.assertFalse(ack_data["show_legal_disclaimer"])

        self.user.refresh_from_db()
        self.assertFalse(self.user.show_legal_disclaimer)
        self.assertIsNotNone(self.user.disclaimer_acknowledged_at)

        self.assertEqual(authorize.status_code, 302)
        location = authorize["Location"]
        self.assertTrue(location.startswith("http://testclient/callback/"))
        code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code", [None])[0]
        self.assertIsNotNone(code)