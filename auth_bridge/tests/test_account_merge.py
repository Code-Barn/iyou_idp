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

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core import mail
from django.core.exceptions import PermissionDenied
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from oidc_provider.models import RSAKey as OIDCRSAKey

from auth_bridge.models import FederatedIdentity, LinkedEmail, User
from auth_bridge.pipeline import process_oauth_identity
from auth_bridge.resilient_cache import cache


@override_settings(SYSTEM_GATE_ENABLED=False)
class AccountMergeTests(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        # Master account (dcbyers13@gmail.com)
        self.master_user = User.objects.create_user(
            email="dcbyers13@gmail.com",
            email_verified=True,
            is_sovereign=False,
        )

        # Standalone duplicate account (baddod13@gmail.com)
        self.source_user = User.objects.create_user(
            email="baddod13@gmail.com",
            email_verified=True,
            is_sovereign=False,
        )

        # Sovereign account
        self.sovereign_user = User.objects.create_user(
            email="sovereign@iyou.org",
            email_verified=True,
            is_sovereign=True,
        )

        cache.delete("account_merge_otp:baddod13@gmail.com")
        self.client.force_login(self.master_user)

    def test_challenge_existing_standalone_user_triggers_merge_confirmation(self) -> None:
        """Challenging an existing standalone user's email returns merge_confirmation_required."""
        res = self.client.post(
            reverse("auth_bridge:email_link_challenge"),
            data=json.dumps({"email": "baddod13@gmail.com"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["action"], "merge_confirmation_required")
        self.assertEqual(len(mail.outbox), 1)

        cached = cache.get("account_merge_otp:baddod13@gmail.com")
        self.assertIsNotNone(cached)
        cached_data = json.loads(cached) if isinstance(cached, str) else cached
        self.assertEqual(cached_data["source_user_id"], str(self.source_user.id))
        self.assertEqual(cached_data["dest_user_id"], str(self.master_user.id))
        self.assertEqual(len(cached_data["otp"]), 6)
        self.assertIn(cached_data["otp"], mail.outbox[0].subject)

    def test_sovereign_account_rejects_web_consolidation(self) -> None:
        """Sovereign accounts cannot be merged via the web tier (HTTP 403)."""
        res = self.client.post(
            reverse("auth_bridge:email_link_challenge"),
            data=json.dumps({"email": "sovereign@iyou.org"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 403)
        body = res.json()
        self.assertEqual(body["error"], "cannot_merge_sovereign_account")

    def test_confirm_merge_invalid_or_expired_otp_fails(self) -> None:
        """Invalid or expired OTP fails with HTTP 400."""
        # Expired / missing OTP
        res = self.client.post(
            reverse("auth_bridge:email_merge_confirm"),
            data=json.dumps({"email": "baddod13@gmail.com", "otp": "123456"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "expired_or_invalid_otp")

        # Invalid OTP
        cache.set(
            "account_merge_otp:baddod13@gmail.com",
            {
                "source_user_id": str(self.source_user.id),
                "dest_user_id": str(self.master_user.id),
                "otp": "654321",
            },
            timeout=300,
        )
        res = self.client.post(
            reverse("auth_bridge:email_merge_confirm"),
            data=json.dumps({"email": "baddod13@gmail.com", "otp": "111111"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["error"], "invalid_otp")

    def test_successful_account_merge(self) -> None:
        """Confirming merge transfers OAuth & linked emails, deactivates source, sets merged_into, and issues VC."""
        fed_id = FederatedIdentity.objects.create(
            user=self.source_user,
            provider="github",
            provider_user_id="gh-99999",
        )
        extra_linked = LinkedEmail.objects.create(
            user=self.source_user,
            email="extra@iyou.org",
            label="secondary",
            is_public=True,
        )

        source_client = Client()
        source_client.force_login(self.source_user)
        self.assertIsNotNone(source_client.session.session_key)

        cache.set(
            "account_merge_otp:baddod13@gmail.com",
            {
                "source_user_id": str(self.source_user.id),
                "dest_user_id": str(self.master_user.id),
                "otp": "842159",
            },
            timeout=300,
        )

        res = self.client.post(
            reverse("auth_bridge:email_merge_confirm"),
            data=json.dumps(
                {
                    "email": "baddod13@gmail.com",
                    "otp": "842-159",
                    "alias_label": "DAD BOD",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["email"], "baddod13@gmail.com")
        self.assertEqual(body["label"], "DAD BOD")

        # 1. Source user deactivated and merged_into set
        self.source_user.refresh_from_db()
        self.assertFalse(self.source_user.is_active)
        self.assertEqual(self.source_user.merged_into, self.master_user)

        # 2. FederatedIdentity transferred
        fed_id.refresh_from_db()
        self.assertEqual(fed_id.user, self.master_user)

        # 3. Existing LinkedEmail transferred
        extra_linked.refresh_from_db()
        self.assertEqual(extra_linked.user, self.master_user)

        # 4. Absorbed primary email created as LinkedEmail on master_user
        absorbed_link = LinkedEmail.objects.get(
            user=self.master_user, email="baddod13@gmail.com"
        )
        self.assertEqual(absorbed_link.label, "DAD BOD")
        self.assertFalse(absorbed_link.is_public)

        # 5. VC minted for master_user
        vc = body["vc"]
        self.assertEqual(vc["type"], ["VerifiableCredential", "EmailOwnershipCredential"])
        self.assertEqual(vc["credentialSubject"]["id"], self.master_user.custodial_did)
        self.assertEqual(vc["credentialSubject"]["email"], "baddod13@gmail.com")
        self.assertEqual(vc["credentialSubject"]["label"], "DAD BOD")
        self.assertIn("proof", vc)

        # 6. Redis OTP cleared
        self.assertIsNone(cache.get("account_merge_otp:baddod13@gmail.com"))

    def test_subsequent_oauth_login_resolves_to_master_account(self) -> None:
        """OAuth login matching a merged account's email routes directly to the master account."""
        self.source_user.is_active = False
        self.source_user.merged_into = self.master_user
        self.source_user.save(update_fields=["is_active", "merged_into"])

        result = process_oauth_identity(
            provider_name="google",
            provider_uid="google-sub-baddod13",
            email="baddod13@gmail.com",
            email_verified=True,
        )
        self.assertEqual(result["action"], "login")
        self.assertEqual(result["user"].id, self.master_user.id)
        self.assertTrue(
            FederatedIdentity.objects.filter(
                user=self.master_user,
                provider="google",
                provider_user_id="google-sub-baddod13",
            ).exists()
        )

    def test_deactivated_unmerged_account_cannot_login_via_oauth(self) -> None:
        """A deactivated account without an active master umbrella cannot be logged into."""
        deactivated_user = User.objects.create_user(
            email="suspended@iyou.org",
            email_verified=True,
            is_active=False,
        )
        with self.assertRaises(PermissionDenied):
            process_oauth_identity(
                provider_name="google",
                provider_uid="google-sub-suspended",
                email=deactivated_user.email,
                email_verified=True,
            )
