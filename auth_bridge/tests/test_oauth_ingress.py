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

from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from oidc_provider.models import Client as OIDCClient, RSAKey as OIDCRSAKey, ResponseType

from auth_bridge.models import FederatedIdentity
from auth_bridge.pipeline import process_oauth_identity
from auth_bridge.views_oauth import (
    SESSION_KEY_OAUTH_NEXT,
    SESSION_KEY_OAUTH_PROVIDER,
    SESSION_KEY_OAUTH_STATE,
    _extract_apple_profile,
    _extract_github_profile,
    _extract_google_profile,
    _fetch_github_primary_email,
)

User = get_user_model()


class OAuthProfileExtractorTests(TestCase):
    def test_google_extractor_rejects_unverified_payload(self) -> None:
        payload = {"sub": "g-1", "email": "unverified@gmail.com", "email_verified": False}
        profile = _extract_google_profile(payload, {"email_verified": False})
        self.assertFalse(profile["email_verified"])

        empty_profile = _extract_google_profile({"sub": "g-1", "email": "unverified@gmail.com"}, {})
        self.assertFalse(empty_profile["email_verified"])

    def test_google_extractor_accepts_verified_payload(self) -> None:
        payload = {"sub": "g-2", "email": "verified@gmail.com", "email_verified": True}
        profile = _extract_google_profile(payload, {})
        self.assertTrue(profile["email_verified"])
        self.assertEqual(profile["provider_uid"], "g-2")
        self.assertEqual(profile["email"], "verified@gmail.com")

    def test_google_extractor_accepts_verified_userinfo(self) -> None:
        payload = {"sub": "g-3", "email": "userinfo@gmail.com"}
        userinfo = {"sub": "g-3", "email": "userinfo@gmail.com", "email_verified": True}
        profile = _extract_google_profile(payload, userinfo)
        self.assertTrue(profile["email_verified"])

    def test_apple_extractor_rejects_unverified_payload(self) -> None:
        payload_false = {"sub": "a-1", "email": "apple@privaterelay.appleid.com", "email_verified": False}
        profile_false = _extract_apple_profile(payload_false)
        self.assertFalse(profile_false["email_verified"])

        payload_str_false = {"sub": "a-2", "email": "apple2@privaterelay.appleid.com", "email_verified": "false"}
        profile_str_false = _extract_apple_profile(payload_str_false)
        self.assertFalse(profile_str_false["email_verified"])

        payload_missing = {"sub": "a-3", "email": "apple3@privaterelay.appleid.com"}
        profile_missing = _extract_apple_profile(payload_missing)
        self.assertFalse(profile_missing["email_verified"])

    def test_apple_extractor_accepts_verified_string_and_bool(self) -> None:
        payload_bool = {"sub": "a-4", "email": "apple_bool@iyou.me", "email_verified": True}
        profile_bool = _extract_apple_profile(payload_bool)
        self.assertTrue(profile_bool["email_verified"])

        payload_str = {"sub": "a-5", "email": "apple_str@iyou.me", "email_verified": "true"}
        profile_str = _extract_apple_profile(payload_str)
        self.assertTrue(profile_str["email_verified"])

    @patch("auth_bridge.views_oauth._fetch_github_primary_email")
    def test_github_extractor_calls_primary_email_helper_and_rejects_unverified(
        self,
        mock_fetch_email: MagicMock,
    ) -> None:
        mock_fetch_email.return_value = ""
        userinfo = {"id": 12345, "email": "untrusted_public@github.com", "login": "ghuser"}
        with self.assertRaises(ValueError):
            _extract_github_profile({"access_token": "gh_secret_token"}, userinfo)
        mock_fetch_email.assert_called_once_with("gh_secret_token")

    @patch("auth_bridge.views_oauth._fetch_github_primary_email")
    def test_github_extractor_ignores_unverified_userinfo_email(
        self,
        mock_fetch_email: MagicMock,
    ) -> None:
        mock_fetch_email.return_value = "verified_primary@github.com"
        userinfo = {"id": 67890, "email": "untrusted_public@github.com", "login": "octocat"}
        profile = _extract_github_profile({"access_token": "gh_token_2"}, userinfo)
        self.assertTrue(profile["email_verified"])
        self.assertEqual(profile["email"], "verified_primary@github.com")
        self.assertEqual(profile["provider_uid"], "67890")

    @patch("requests.get")
    def test_fetch_github_primary_email_queries_api(self, mock_get: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {"email": "unverified@example.com", "primary": False, "verified": False},
            {"email": "verified_primary@example.com", "primary": True, "verified": True},
        ]
        mock_resp.raise_for_status.return_value = None
        mock_get.return_value = mock_resp

        email = _fetch_github_primary_email("gho_live_token")
        self.assertEqual(email, "verified_primary@example.com")


class SmartMergePipelineTests(TestCase):
    def test_process_oauth_identity_rejects_unverified_email(self) -> None:
        with self.assertRaises(PermissionDenied):
            process_oauth_identity(
                provider_name="google",
                provider_uid="uid-100",
                email="unverified@iyou.me",
                email_verified=False,
            )

    def test_sovereign_account_rejects_unauthenticated_oauth_merge(self) -> None:
        User.objects.create_user(
            email="sovereign_owner@iyou.me",
            custodial_did="did:web:iyou.me:user:sovereign-test",
            account_tier="sovereign",
            is_sovereign=True,
        )

        with self.assertRaises(PermissionDenied):
            process_oauth_identity(
                provider_name="google",
                provider_uid="uid-sovereign-attacker",
                email="sovereign_owner@iyou.me",
                email_verified=True,
                request_user=None,
            )

        other_user = User.objects.create_user(
            email="other@iyou.me",
            custodial_did="did:web:iyou.me:user:other",
        )
        with self.assertRaises(PermissionDenied):
            process_oauth_identity(
                provider_name="google",
                provider_uid="uid-sovereign-attacker",
                email="sovereign_owner@iyou.me",
                email_verified=True,
                request_user=other_user,
            )

    def test_sovereign_account_allows_authenticated_oauth_linking(self) -> None:
        sovereign_user = User.objects.create_user(
            email="sovereign_legit@iyou.me",
            custodial_did="did:web:iyou.me:user:sovereign-legit",
            account_tier="sovereign",
            is_sovereign=True,
        )

        result = process_oauth_identity(
            provider_name="google",
            provider_uid="uid-sovereign-legit",
            email="sovereign_legit@iyou.me",
            email_verified=True,
            request_user=sovereign_user,
        )
        self.assertEqual(result["action"], "login")
        self.assertEqual(result["user"].id, sovereign_user.id)
        self.assertTrue(
            FederatedIdentity.objects.filter(
                user=sovereign_user,
                provider="google",
                provider_user_id="uid-sovereign-legit",
            ).exists()
        )

    def test_new_user_provisioned_with_unusable_password_and_did(self) -> None:
        result = process_oauth_identity(
            provider_name="github",
            provider_uid="gh-new-999",
            email="brand_new@iyou.me",
            email_verified=True,
        )
        self.assertEqual(result["action"], "login")
        user = result["user"]
        self.assertEqual(user.email, "brand_new@iyou.me")
        self.assertTrue(user.email_verified)
        self.assertIsNotNone(user.email_verified_at)
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.custodial_did.startswith("did:web:"))
        self.assertTrue(
            FederatedIdentity.objects.filter(
                user=user,
                provider="github",
                provider_user_id="gh-new-999",
            ).exists()
        )

    def test_existing_managed_user_auto_links_safely(self) -> None:
        existing = User.objects.create_user(
            email="managed@iyou.me",
            custodial_did="did:web:iyou.me:user:managed-test",
            account_tier="managed_free",
        )
        self.assertFalse(existing.has_usable_password())

        result = process_oauth_identity(
            provider_name="apple",
            provider_uid="apple-managed-1",
            email="managed@iyou.me",
            email_verified=True,
        )
        self.assertEqual(result["action"], "login")
        self.assertEqual(result["user"].id, existing.id)
        self.assertTrue(result["user"].email_verified)
        self.assertFalse(result["user"].has_usable_password())


@override_settings(SYSTEM_GATE_ENABLED=False)
class OAuthIngressFlowTests(TestCase):
    def setUp(self) -> None:
        self.client = Client()

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
            client_id="oauth-test-satellite",
            client_secret="",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.oidc_client.response_types.add(ResponseType.objects.get(value="code"))

    def test_unsupported_provider_initiate_returns_400(self) -> None:
        resp = self.client.get(
            reverse("auth_bridge:oauth_initiate", kwargs={"provider": "unknown_provider"})
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data["error"], "unsupported_provider")

    def test_unconfigured_provider_initiate_returns_descriptive_error(self) -> None:
        resp = self.client.get(
            reverse("auth_bridge:oauth_initiate", kwargs={"provider": "google"})
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data["error"], "unconfigured_provider")
        self.assertIn("Missing client credentials", data["error_description"])

    @override_settings(DEBUG=True, SYSTEM_GATE_ENABLED=False)
    def test_mock_oauth_initiate_and_callback_flow_in_debug(self) -> None:
        resp = self.client.get(
            reverse("auth_bridge:oauth_initiate", kwargs={"provider": "google"}),
            {"mock": "true", "next": "https://satellite.iyou.me/callback/?state=test-state"},
        )
        self.assertEqual(resp.status_code, 302)
        redirect_location = resp["Location"]
        self.assertIn("/auth/oauth/callback/google/", redirect_location)
        self.assertIn("code=mock-code-google", redirect_location)

        callback_resp = self.client.get(redirect_location)
        self.assertEqual(callback_resp.status_code, 302)
        self.assertTrue(
            User.objects.filter(email="mock-google-user@iyou.me").exists()
        )

    def test_callback_rejects_unverified_email_with_403(self) -> None:
        session = self.client.session
        session[SESSION_KEY_OAUTH_STATE] = "test-state-123"
        session[SESSION_KEY_OAUTH_PROVIDER] = "google"
        session.save()

        with patch("auth_bridge.views_oauth.OAuthCallbackView._exchange_code", return_value={"access_token": "mock"}), \
             patch("auth_bridge.views_oauth.OAuthCallbackView._fetch_userinfo", return_value={"sub": "g-unverified", "email": "unverified@example.com", "email_verified": False}):

            resp = self.client.get(
                reverse("auth_bridge:oauth_callback", kwargs={"provider": "google"}),
                {"state": "test-state-123", "code": "valid-code"},
            )
            self.assertEqual(resp.status_code, 403)
            data = resp.json()
            self.assertEqual(data["error"], "unverified_email")

    def test_callback_rejects_github_unverified_email_with_403(self) -> None:
        session = self.client.session
        session[SESSION_KEY_OAUTH_STATE] = "test-state-gh"
        session[SESSION_KEY_OAUTH_PROVIDER] = "github"
        session.save()

        with patch("auth_bridge.views_oauth.OAuthCallbackView._exchange_code", return_value={"access_token": "mock"}), \
             patch("auth_bridge.views_oauth.OAuthCallbackView._fetch_userinfo", return_value={"id": 12345, "email": "public@example.com"}), \
             patch("auth_bridge.views_oauth._fetch_github_primary_email", return_value=""):

            resp = self.client.get(
                reverse("auth_bridge:oauth_callback", kwargs={"provider": "github"}),
                {"state": "test-state-gh", "code": "valid-code"},
            )
            self.assertEqual(resp.status_code, 403)
            data = resp.json()
            self.assertEqual(data["error"], "unverified_email")

    def test_callback_protects_sovereign_account_from_oauth_takeover(self) -> None:
        User.objects.create_user(
            email="sovereign_target@iyou.me",
            custodial_did="did:web:iyou.me:user:sovereign-target",
            account_tier="sovereign",
            is_sovereign=True,
        )

        session = self.client.session
        session[SESSION_KEY_OAUTH_STATE] = "test-state-sov"
        session[SESSION_KEY_OAUTH_PROVIDER] = "google"
        session.save()

        with patch("auth_bridge.views_oauth.OAuthCallbackView._exchange_code", return_value={"access_token": "mock"}), \
             patch("auth_bridge.views_oauth.OAuthCallbackView._fetch_userinfo", return_value={"sub": "g-attacker", "email": "sovereign_target@iyou.me", "email_verified": True}):

            resp = self.client.get(
                reverse("auth_bridge:oauth_callback", kwargs={"provider": "google"}),
                {"state": "test-state-sov", "code": "valid-code"},
            )
            self.assertEqual(resp.status_code, 403)
            data = resp.json()
            self.assertEqual(data["error"], "forbidden")
            self.assertIn("sovereign identity", data["error_description"])

    def test_successful_oauth_login_maintains_next_url_oidc_continuity(self) -> None:
        User.objects.create_user(
            email="continuity_user@iyou.me",
            custodial_did="did:web:iyou.me:user:continuity-user",
            show_legal_disclaimer=False,
        )

        oidc_authorize_url = (
            f"/openid/authorize/"
            f"?client_id={self.oidc_client.client_id}"
            f"&response_type=code"
            f"&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile"
            f"&state=custom-oidc-state-999"
        )

        session = self.client.session
        session[SESSION_KEY_OAUTH_STATE] = "test-state-oidc"
        session[SESSION_KEY_OAUTH_PROVIDER] = "google"
        session[SESSION_KEY_OAUTH_NEXT] = oidc_authorize_url
        session.save()

        with patch("auth_bridge.views_oauth.OAuthCallbackView._exchange_code", return_value={"access_token": "mock"}), \
             patch("auth_bridge.views_oauth.OAuthCallbackView._fetch_userinfo", return_value={"sub": "g-cont", "email": "continuity_user@iyou.me", "email_verified": True}):

            resp = self.client.get(
                reverse("auth_bridge:oauth_callback", kwargs={"provider": "google"}),
                {"state": "test-state-oidc", "code": "valid-code"},
            )
            self.assertEqual(resp.status_code, 302)
            redirect_url = resp["Location"]
            self.assertTrue(
                redirect_url.startswith("https://satellite.iyou.me/callback/")
                or "/openid/authorize/" in redirect_url
            )
            if redirect_url.startswith("https://satellite.iyou.me/callback/"):
                self.assertIn("code=", redirect_url)
                self.assertIn("state=custom-oidc-state-999", redirect_url)
