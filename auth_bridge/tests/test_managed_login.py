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
Integration tests for Tier 1 Managed Login (managed_login) in iyou_idp.

Covers:
- JIT user creation with account_tier=1, custodial DID, and hashed password
- OIDC next parameter continuity and authorization code issuance
- Sovereign Airlock gate blocking unapproved public logins (HTTP 403)
- Gate bypass for sessions carrying beta_access
- GDPR affirmative consent / legal disclaimer redirection
- Retaining next parameter on invalid passwords and validation errors
- Safe public redirect sanitization
- Form rendering with hidden next input in _tab_managed.html
"""

from urllib.parse import quote_plus, parse_qs, urlparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.messages import get_messages
from oidc_provider.models import Client as OIDCClient, ResponseType, RSAKey as OIDCRSAKey

from auth_bridge.models import User
from auth_bridge.views import DEFAULT_NEXT_URL


class ManagedLoginTestSuite(TestCase):
    """Test suite verifying Tier 1 Managed Login lifecycle and ingress invariants."""

    def setUp(self):
        self.client = Client()

    def _setup_oidc_client(self, client_id="test-managed-client", redirect_uri="http://client.example.com/callback/"):
        """Helper to configure OIDC provider keys and client for code issuance."""
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        code_type, _ = ResponseType.objects.get_or_create(value="code")
        client_obj = OIDCClient.objects.create(
            name="Managed Client",
            client_type="confidential",
            client_id=client_id,
            client_secret="test-client-secret",
            jwt_alg="RS256",
            _redirect_uris=f"{redirect_uri}\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        client_obj.response_types.add(code_type)
        return client_obj

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_jit_user_creation_success(self):
        """Verifies new email creates account_tier=1 user with hashed password and custodial DID."""
        email = "jit_new_user@example.com"
        password = "SecurePassword123!"

        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {"email": email, "password": password},
        )

        # Should succeed and redirect to legal disclaimer by default
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(User.objects.filter(email=email).exists())

        user = User.objects.get(email=email)
        self.assertEqual(str(user.account_tier), "1")
        self.assertTrue(user.custodial_did.startswith("did:web:"))
        self.assertTrue(user.check_password(password))
        self.assertTrue(user.is_active)
        self.assertTrue(user.show_legal_disclaimer)

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_preserves_oidc_next_param(self):
        """Verifies /openid/authorize/?... in next triggers OIDC code generation or preserves the callback flow."""
        client_id = "managed-oidc-client"
        redirect_uri = "http://satellite.local:9000/callback/"
        self._setup_oidc_client(client_id=client_id, redirect_uri=redirect_uri)

        # 1. Test acknowledged user directly mints OIDC code and redirects to satellite callback
        ack_user = User.objects.create(
            email="ack_oidc@example.com",
            custodial_did="did:web:iyou.me:user:ack-oidc",
            account_tier=1,
            is_active=True,
            show_legal_disclaimer=False,
        )
        ack_user.set_password("MyPassword123!")
        ack_user.save()

        oidc_next = (
            f"/openid/authorize/?client_id={client_id}"
            f"&response_type=code"
            f"&redirect_uri={redirect_uri}"
            f"&scope=openid+profile"
            f"&state=state_managed_456"
            f"&nonce=nonce_managed_789"
        )

        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {
                "email": "ack_oidc@example.com",
                "password": "MyPassword123!",
                "next": oidc_next,
            },
        )

        self.assertEqual(resp.status_code, 302)
        location = resp["Location"]
        self.assertTrue(location.startswith(redirect_uri))
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        self.assertIn("code", params)
        self.assertEqual(params.get("state"), ["state_managed_456"])

        # 2. Test unacknowledged user preserves the OIDC authorize request in next param and session
        resp_unack = self.client.post(
            reverse("auth_bridge:managed_login"),
            {
                "email": "unack_jit@example.com",
                "password": "MyPassword123!",
                "next": oidc_next,
            },
        )
        self.assertEqual(resp_unack.status_code, 302)
        self.assertIn(reverse("auth_bridge:legal_disclaimer"), resp_unack["Location"])
        self.assertIn(quote_plus(oidc_next), resp_unack["Location"])
        self.assertEqual(self.client.session.get("post_disclaimer_redirect"), oidc_next)

    @override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID="did:key:z6MkujsSdMm1j7QqUNaZo8U8kkcJNfFNikUQYJzmZX4wwgND", BETA_ACCESS_ALLOWLIST=[])
    def test_managed_login_blocked_by_system_gate_without_invite(self):
        """Verifies unapproved JIT user receives HTTP 403 beta_gate.html when SYSTEM_GATE_ENABLED=True."""
        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {"email": "gated_public@example.com", "password": "Password123!"},
        )

        self.assertEqual(resp.status_code, 403)
        body = resp.content.decode("utf-8")
        self.assertIn("Private Beta", body)
        self.assertIn('name="invite_key"', body)

        # User is saved in DB, but session is NOT established
        self.assertTrue(User.objects.filter(email="gated_public@example.com").exists())
        self.assertNotIn("_auth_user_id", self.client.session)

    @override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID="did:key:z6MkujsSdMm1j7QqUNaZo8U8kkcJNfFNikUQYJzmZX4wwgND", BETA_ACCESS_ALLOWLIST=[])
    def test_managed_login_proceeds_with_beta_session(self):
        """Verifies user with session['beta_access'] = True bypasses the gate."""
        session = self.client.session
        session["beta_access"] = True
        session.save()

        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {"email": "beta_permitted@example.com", "password": "Password123!"},
        )

        # Should bypass the 403 gate and proceed to 302 redirect
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("auth_bridge:legal_disclaimer"), resp["Location"])
        self.assertIn("_auth_user_id", self.client.session)

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_redirects_to_legal_disclaimer_when_unacknowledged(self):
        """Verifies new user with show_legal_disclaimer=True is diverted to /auth/legal-disclaimer/."""
        target_destination = "/some/dashboard/landing/"

        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {
                "email": "disclaimer_check@example.com",
                "password": "Password123!",
                "next": target_destination,
            },
        )

        self.assertEqual(resp.status_code, 302)
        expected_base = reverse("auth_bridge:legal_disclaimer")
        self.assertTrue(resp["Location"].startswith(expected_base))
        self.assertIn(f"next={quote_plus(target_destination)}", resp["Location"])
        self.assertEqual(self.client.session.get("post_disclaimer_redirect"), target_destination)
        self.assertIn("_auth_user_id", self.client.session)

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_invalid_password_retains_next_param(self):
        """Verifies failed attempts redirect back to tab=managed while keeping the next query parameter intact."""
        email = "existing_user@example.com"
        user = User.objects.create(
            email=email,
            custodial_did="did:web:iyou.me:user:existing-pwd-test",
            account_tier=1,
            is_active=True,
        )
        user.set_password("CorrectPassword123!")
        user.save()

        target_next = "/openid/authorize/?client_id=sat1&state=xyz987"

        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {
                "email": email,
                "password": "WrongPassword!",
                "next": target_next,
            },
        )

        self.assertEqual(resp.status_code, 302)
        expected_redirect = f"{reverse('auth_bridge:login')}?tab=managed&next={quote_plus(target_next)}"
        self.assertEqual(resp["Location"], expected_redirect)

        # Message flashed
        messages = list(get_messages(resp.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Invalid email or password.")
        self.assertNotIn("_auth_user_id", self.client.session)

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_missing_credentials_retains_next_param(self):
        """Verifies missing email or password redirects back to tab=managed with next preserved."""
        target_next = "/app/return/"
        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {"email": "", "password": "", "next": target_next},
        )

        self.assertEqual(resp.status_code, 302)
        expected_redirect = f"{reverse('auth_bridge:login')}?tab=managed&next={quote_plus(target_next)}"
        self.assertEqual(resp["Location"], expected_redirect)

        messages = list(get_messages(resp.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Email and password are required.")

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_disabled_account_retains_next_param(self):
        """Verifies inactive accounts are rejected and redirect back with next preserved."""
        email = "disabled_user@example.com"
        user = User.objects.create(
            email=email,
            custodial_did="did:web:iyou.me:user:disabled",
            account_tier=1,
            is_active=False,
        )
        user.set_password("CorrectPassword123!")
        user.save()

        target_next = "/app/home/"
        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {"email": email, "password": "CorrectPassword123!", "next": target_next},
        )

        self.assertEqual(resp.status_code, 302)
        expected_redirect = f"{reverse('auth_bridge:login')}?tab=managed&next={quote_plus(target_next)}"
        self.assertEqual(resp["Location"], expected_redirect)

        messages = list(get_messages(resp.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Account is disabled.")

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_unsafe_next_url_falls_back_to_default(self):
        """Verifies unsafe redirect URLs (e.g. cluster local) fallback to DEFAULT_NEXT_URL."""
        unsafe_next = "http://internal-db.svc.cluster.local:5432/evil"
        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {
                "email": "unsafe_next_test@example.com",
                "password": "Password123!",
                "next": unsafe_next,
            },
        )

        self.assertEqual(resp.status_code, 302)
        # Should sanitize unsafe_next and redirect to legal disclaimer with DEFAULT_NEXT_URL
        self.assertIn(f"next={quote_plus(DEFAULT_NEXT_URL)}", resp["Location"])
        self.assertEqual(self.client.session.get("post_disclaimer_redirect"), DEFAULT_NEXT_URL)

    def test_form_renders_hidden_next_input_and_action(self):
        """Verifies that login page with ?next= correctly renders hidden input and action attribute."""
        next_target = "/openid/authorize/?client_id=123"
        resp = self.client.get(f"{reverse('auth_bridge:login')}?next={quote_plus(next_target)}")
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode("utf-8")

        # Hidden input present
        self.assertIn(f'<input type="hidden" name="next" value="{next_target}">', body)
        # Form action contains encoded next
        self.assertIn('action="/auth/managed-login/?next=', body)
        self.assertIn('client_id%3D123', body)
