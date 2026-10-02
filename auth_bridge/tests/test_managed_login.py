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
Integration tests for Tier 1 Managed Login deprecation in iyou_idp.

Verifies:
- Password ingress via POST /auth/managed-login/ is disabled and deprecated
- Web form submissions redirect back to login?tab=managed with deprecation notice
- API / JSON requests return HTTP 400 with deprecation error
- No unverified User records or passwords are created
- Unsafe next URLs fall back to DEFAULT_NEXT_URL
- Login page renders the 2-step email OTP UI in Tab 2
"""

import json
from urllib.parse import quote_plus

from django.contrib.messages import get_messages
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from auth_bridge.models import User
from auth_bridge.views import DEFAULT_NEXT_URL


class ManagedLoginTestSuite(TestCase):
    """Test suite verifying Tier 1 Managed Login deprecation invariants."""

    def setUp(self) -> None:
        self.client = Client()

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_deprecated_redirects_with_message(self) -> None:
        """Verifies direct password login is deprecated and redirects to tab=managed without creating users."""
        email = "jit_attempt@example.com"
        password = "SecurePassword123!"
        target_next = "/dashboard/"

        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            {"email": email, "password": password, "next": target_next},
        )

        self.assertEqual(resp.status_code, 302)
        expected_redirect = f"{reverse('auth_bridge:login')}?tab=managed&next={quote_plus(target_next)}"
        self.assertEqual(resp["Location"], expected_redirect)

        # Assert no user is created and no session established
        self.assertFalse(User.objects.filter(email=email).exists())
        self.assertNotIn("_auth_user_id", self.client.session)

        # Assert deprecation message flashed
        messages = list(get_messages(resp.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertIn("deprecated", str(messages[0]).lower())

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_managed_login_json_request_returns_400(self) -> None:
        """Verifies API / JSON calls to /auth/managed-login/ return HTTP 400 with deprecation message."""
        resp = self.client.post(
            reverse("auth_bridge:managed_login"),
            json.dumps({"email": "api_test@example.com", "password": "Password123!"}),
            content_type="application/json",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertTrue(data.get("deprecated"))
        self.assertIn("deprecated", data.get("error", "").lower())
        self.assertFalse(User.objects.filter(email="api_test@example.com").exists())

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_unsafe_next_url_falls_back_to_default(self) -> None:
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
        self.assertIn(f"next={quote_plus(DEFAULT_NEXT_URL)}", resp["Location"])

    def test_form_renders_email_otp_ui(self) -> None:
        """Verifies that login page renders the 2-step email OTP UI container."""
        resp = self.client.get(reverse("auth_bridge:login"))
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode("utf-8")

        self.assertIn('id="email-otp-container"', body)
        self.assertIn('id="otp-email"', body)
        self.assertIn('id="send-otp-btn"', body)
        self.assertIn('id="otp-code"', body)
        self.assertIn('id="verify-otp-btn"', body)
