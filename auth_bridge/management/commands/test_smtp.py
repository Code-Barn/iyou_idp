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
Management command to test SMTP email dispatch and verify configuration in iyou_idp.
"""

import logging
import smtplib
import socket
from typing import Any

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Dispatches a lightweight test email to verify SMTP configuration and connectivity."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "recipient_email",
            type=str,
            help="Recipient email address to receive the verification message.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        recipient_email = options["recipient_email"].strip()
        if not recipient_email or "@" not in recipient_email or recipient_email.startswith("@") or recipient_email.endswith("@"):
            raise CommandError(f"Invalid recipient email address: '{recipient_email}'")

        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "")
        if not from_email:
            raise CommandError("settings.DEFAULT_FROM_EMAIL is not configured or is empty.")
        assert settings.DEFAULT_FROM_EMAIL, "settings.DEFAULT_FROM_EMAIL must be configured"

        backend = getattr(settings, "EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
        host = getattr(settings, "EMAIL_HOST", "N/A")
        port = getattr(settings, "EMAIL_PORT", "N/A")
        use_tls = getattr(settings, "EMAIL_USE_TLS", False)
        host_user = getattr(settings, "EMAIL_HOST_USER", "")

        self.stdout.write(f"Initiating SMTP test dispatch to <{recipient_email}>...")
        self.stdout.write(f"  Backend: {backend}")
        self.stdout.write(f"  Host: {host}:{port}")
        self.stdout.write(f"  TLS: {use_tls}")
        self.stdout.write(f"  Host User: {host_user or '(none)'}")
        self.stdout.write(f"  From Email: {from_email}")

        subject = "[iYou IdP] SMTP Verification Test"
        message = (
            f"Hello,\n\n"
            f"This is an automated SMTP verification test dispatched by iyou_idp 'test_smtp'.\n\n"
            f"Dispatch Parameters:\n"
            f"- From: {from_email}\n"
            f"- Recipient: {recipient_email}\n"
            f"- Host: {host}:{port}\n"
            f"- Backend: {backend}\n"
            f"- TLS: {use_tls}\n\n"
            f"If you received this message, your SMTP configuration is operating normally.\n"
        )
        html_message = (
            f"<div style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px;'>"
            f"<h2 style='color: #111827; margin-bottom: 16px;'>iYou SMTP Verification Test</h2>"
            f"<p style='color: #4b5563; font-size: 15px;'>This is an automated verification test dispatched by <code>iyou_idp</code>.</p>"
            f"<div style='background: #f3f4f6; border-radius: 8px; padding: 16px; margin: 20px 0;'>"
            f"<ul style='list-style: none; padding: 0; margin: 0; font-size: 13px; color: #374151; font-family: monospace;'>"
            f"<li><strong>From:</strong> {from_email}</li>"
            f"<li><strong>Recipient:</strong> {recipient_email}</li>"
            f"<li><strong>Host:</strong> {host}:{port}</li>"
            f"<li><strong>Backend:</strong> {backend}</li>"
            f"<li><strong>TLS:</strong> {use_tls}</li>"
            f"</ul>"
            f"</div>"
            f"<p style='color: #10b981; font-weight: 600; font-size: 14px;'>✓ End-to-end SMTP delivery is operational.</p>"
            f"</div>"
        )

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=[recipient_email],
                html_message=html_message,
                fail_silently=False,
            )
        except smtplib.SMTPAuthenticationError as exc:
            code = getattr(exc, "smtp_code", "Unknown")
            raw_err = getattr(exc, "smtp_error", str(exc))
            err_text = raw_err.decode("utf-8", errors="replace") if isinstance(raw_err, bytes) else str(raw_err)
            actionable_msg = (
                f"SMTP Authentication Error ({code}): {err_text}\n"
                f"Actionable Hint: Check EMAIL_HOST_USER and EMAIL_HOST_PASSWORD in your .env.\n"
                f"For Apple iCloud SMTP (smtp.mail.me.com), generate and use an App-Specific Password at https://appleid.apple.com."
            )
            logger.error("SMTP Authentication Error: %s", actionable_msg)
            self.stderr.write(self.style.ERROR(actionable_msg))
            raise CommandError(f"SMTP authentication failed: {exc}") from exc
        except smtplib.SMTPConnectError as exc:
            actionable_msg = (
                f"SMTP Connection Error: {exc}\n"
                f"Actionable Hint: Failed to establish an SMTP connection to {host}:{port}.\n"
                f"Verify network connectivity, DNS resolution, port settings, and firewall/security rules."
            )
            logger.error("SMTP Connection Error: %s", actionable_msg)
            self.stderr.write(self.style.ERROR(actionable_msg))
            raise CommandError(f"SMTP connection failed: {exc}") from exc
        except smtplib.SMTPException as exc:
            actionable_msg = (
                f"SMTP Protocol Error: {exc}\n"
                f"Actionable Hint: The SMTP server rejected the transaction. Verify sender domain policies, TLS configuration, or message limits."
            )
            logger.error("SMTP Protocol Error: %s", actionable_msg)
            self.stderr.write(self.style.ERROR(actionable_msg))
            raise CommandError(f"SMTP dispatch failed: {exc}") from exc
        except (socket.error, OSError) as exc:
            actionable_msg = (
                f"SMTP Socket / Network Error: {exc}\n"
                f"Actionable Hint: Failed to establish a socket connection to {host}:{port}.\n"
                f"Verify network connectivity, DNS resolution, port settings, and firewall/security rules."
            )
            logger.error("SMTP Socket Error: %s", actionable_msg)
            self.stderr.write(self.style.ERROR(actionable_msg))
            raise CommandError(f"SMTP connection failed: {exc}") from exc
        except Exception as exc:
            actionable_msg = f"Unexpected error during SMTP test dispatch: {exc}"
            logger.exception("Unexpected SMTP Error: %s", actionable_msg)
            self.stderr.write(self.style.ERROR(actionable_msg))
            raise CommandError(actionable_msg) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Successfully dispatched test email from '{from_email}' to '{recipient_email}'."
            )
        )
