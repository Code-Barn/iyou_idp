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
Integration tests for Redis-backed Email OTP Engine in iyou_idp.
"""

import json
import smtplib
import socket
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.conf import settings
from django.core import mail
from django.core.management import CommandError, call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from auth_bridge.models import User
from auth_bridge.resilient_cache import cache

CHALLENGE_URL = reverse("auth_bridge:email_challenge")
VERIFY_URL = reverse("auth_bridge:email_verify")


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="info@iyou.me",
)
class EmailOtpEngineTests(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        cache.clear()
        mail.outbox.clear()

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_otp_dispatch_and_cache_storage_with_ttl(self) -> None:
        email = "test_user@example.com"
        resp = self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email, "next_url": "/dashboard/"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("message"), "Verification code dispatched.")

        self.assertEqual(len(mail.outbox), 1)
        sent_mail = mail.outbox[0]
        self.assertEqual(sent_mail.to, [email])
        self.assertEqual(sent_mail.from_email, settings.DEFAULT_FROM_EMAIL)
        self.assertIn("Your iyou verification code", sent_mail.subject)
        self.assertIn("— The iyou Identity Team", sent_mail.body)

        cached_raw = cache.get(f"email_otp:{email}")
        self.assertIsNotNone(cached_raw)
        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw
        self.assertIn("otp", cached)
        self.assertIn("token", cached)
        self.assertEqual(len(cached["otp"]), 6)
        self.assertTrue(cached["otp"].isdigit())
        self.assertIn(cached["otp"], sent_mail.body)

        token_email = cache.get(f"email_otp_token:{cached['token']}")
        self.assertEqual(token_email, email)

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_invalid_expired_otp_returns_400(self) -> None:
        email = "expired_user@example.com"
        resp = self.client.post(
            VERIFY_URL,
            json.dumps({"email": email, "otp": "123456"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("expired or not found", resp.json().get("error", ""))

        self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email}),
            content_type="application/json",
        )
        cached_raw = cache.get(f"email_otp:{email}")
        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw
        wrong_otp = "999999" if cached["otp"] != "999999" else "888888"

        resp_wrong = self.client.post(
            VERIFY_URL,
            json.dumps({"email": email, "otp": wrong_otp}),
            content_type="application/json",
        )
        self.assertEqual(resp_wrong.status_code, 400)
        self.assertIn("Invalid verification code", resp_wrong.json().get("error", ""))

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_valid_otp_provisions_user_with_custodial_did_and_unusable_password(self) -> None:
        email = "new_provisioned@example.com"
        self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email}),
            content_type="application/json",
        )
        cached_raw = cache.get(f"email_otp:{email}")
        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw
        otp = cached["otp"]

        resp = self.client.post(
            VERIFY_URL,
            json.dumps({"email": email, "otp": otp}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))

        user = User.objects.get(email=email)
        self.assertTrue(user.email_verified)
        self.assertIsNotNone(user.email_verified_at)
        self.assertEqual(user.account_tier, "managed_free")
        self.assertTrue(user.custodial_did.startswith("did:web:"))
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.is_active)

        self.assertIsNone(cache.get(f"email_otp:{email}"))
        self.assertIsNone(cache.get(f"email_otp_token:{cached['token']}"))
        self.assertEqual(self.client.session.get("_auth_user_id"), str(user.id))

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_repeat_login_for_existing_email_does_not_duplicate_user(self) -> None:
        email = "existing_account@example.com"
        existing_user = User.objects.create(
            email=email,
            custodial_did="did:web:iyou.me:user:original-user-uuid",
            account_tier="managed_free",
            email_verified=False,
            is_active=True,
        )
        original_did = existing_user.custodial_did

        self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email}),
            content_type="application/json",
        )
        cached_raw = cache.get(f"email_otp:{email}")
        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw

        resp = self.client.post(
            VERIFY_URL,
            json.dumps({"email": email, "otp": cached["otp"]}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(User.objects.filter(email=email).count(), 1)
        existing_user.refresh_from_db()
        self.assertEqual(existing_user.custodial_did, original_did)
        self.assertTrue(existing_user.email_verified)
        self.assertIsNotNone(existing_user.email_verified_at)
        self.assertFalse(existing_user.has_usable_password())

        self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email}),
            content_type="application/json",
        )
        cached_raw2 = cache.get(f"email_otp:{email}")
        cached2 = json.loads(cached_raw2) if isinstance(cached_raw2, str) else cached_raw2

        resp2 = self.client.post(
            VERIFY_URL,
            json.dumps({"email": email, "otp": cached2["otp"]}),
            content_type="application/json",
        )
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(User.objects.filter(email=email).count(), 1)

    @override_settings(SYSTEM_GATE_ENABLED=False)
    def test_token_verification_and_magic_link_redemption(self) -> None:
        email = "token_flow@example.com"
        self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email, "next_url": "/satellite/callback/"}),
            content_type="application/json",
        )
        cached_raw = cache.get(f"email_otp:{email}")
        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw
        token = cached["token"]

        resp = self.client.post(
            VERIFY_URL,
            json.dumps({"token": token}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("redirect_url"), "/satellite/callback/")
        self.assertTrue(User.objects.filter(email=email).exists())

    @override_settings(SYSTEM_GATE_ENABLED=False, DEFAULT_FROM_EMAIL="custom_sender@iyou.me")
    def test_challenge_email_uses_configured_default_from_email(self) -> None:
        email = "custom_sender_test@example.com"
        resp = self.client.post(
            CHALLENGE_URL,
            json.dumps({"email": email}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "custom_sender@iyou.me")


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="info@iyou.me",
    EMAIL_HOST="smtp.mail.me.com",
    EMAIL_PORT=587,
    EMAIL_USE_TLS=True,
    EMAIL_HOST_USER="user@icloud.com",
)
class TestSmtpCommandTests(TestCase):
    def setUp(self) -> None:
        mail.outbox.clear()

    def test_successful_smtp_dispatch(self) -> None:
        out = StringIO()
        err = StringIO()
        call_command("test_smtp", "target@example.com", stdout=out, stderr=err)
        self.assertEqual(len(mail.outbox), 1)
        sent = mail.outbox[0]
        self.assertEqual(sent.to, ["target@example.com"])
        self.assertEqual(sent.from_email, "info@iyou.me")
        self.assertEqual(sent.subject, "[iyou IdP] SMTP Verification Test")
        self.assertIn("— The iyou Identity Team", sent.body)
        self.assertIn("Successfully dispatched test email", out.getvalue())

    def test_invalid_recipient_email_raises_command_error(self) -> None:
        with self.assertRaises(CommandError) as ctx:
            call_command("test_smtp", "not-an-email")
        self.assertIn("Invalid recipient email address", str(ctx.exception))

    @override_settings(DEFAULT_FROM_EMAIL="")
    def test_missing_default_from_email_raises_command_error(self) -> None:
        with self.assertRaises(CommandError) as ctx:
            call_command("test_smtp", "target@example.com")
        self.assertIn("DEFAULT_FROM_EMAIL is not configured", str(ctx.exception))

    @patch("auth_bridge.management.commands.test_smtp.send_mail")
    def test_smtp_authentication_error_handling(self, mock_send_mail: Any) -> None:
        mock_send_mail.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication failed")
        err = StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command("test_smtp", "target@example.com", stderr=err)
        self.assertIn("SMTP authentication failed", str(ctx.exception))
        self.assertIn("App-Specific Password", err.getvalue())

    @patch("auth_bridge.management.commands.test_smtp.send_mail")
    def test_smtp_socket_connection_error_handling(self, mock_send_mail: Any) -> None:
        mock_send_mail.side_effect = socket.gaierror("nodename nor servname provided, or not known")
        err = StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command("test_smtp", "target@example.com", stderr=err)
        self.assertIn("SMTP connection failed", str(ctx.exception))
        self.assertIn("Actionable Hint", err.getvalue())

    @patch("auth_bridge.management.commands.test_smtp.send_mail")
    def test_smtp_protocol_error_handling(self, mock_send_mail: Any) -> None:
        mock_send_mail.side_effect = smtplib.SMTPException("Transaction rejected")
        err = StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command("test_smtp", "target@example.com", stderr=err)
        self.assertIn("SMTP dispatch failed", str(ctx.exception))
        self.assertIn("SMTP Protocol Error", err.getvalue())

