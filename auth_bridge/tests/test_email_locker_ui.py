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
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from oidc_provider.models import RSAKey as OIDCRSAKey

from auth_bridge.models import LinkedEmail, PasskeyCredential, User


@override_settings(SYSTEM_GATE_ENABLED=False)
class EmailLockerUITest(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        self.user = User.objects.create_user(
            email="root_sovereign@iyou.me",
            email_verified=True,
            email_verified_at=timezone.now(),
            account_tier="sovereign",
        )
        self.user.is_sovereign = True
        self.user.save()

        self.other_user = User.objects.create_user(
            email="other_user@iyou.me",
            email_verified=True,
        )

        self.linked_1 = LinkedEmail.objects.create(
            user=self.user,
            email="corp_work@enterprise.com",
            label="work",
            is_public=False,
        )
        self.linked_2 = LinkedEmail.objects.create(
            user=self.user,
            email="pseudonym_alias@privacy.org",
            label="alias",
            is_public=True,
        )

        self.passkey = PasskeyCredential.objects.create(
            user=self.user,
            credential_id=b"test-credential-id-12345",
            public_key_cose=b"test-cose-key-bytes",
            sign_count=1,
            transports=["internal"],
        )

    def test_unauthenticated_user_access_renders_login(self) -> None:
        response = self.client.get(reverse("auth_bridge:login"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "auth_bridge/login.html")
        self.assertNotContains(response, "Protected Identity &amp; Email Locker")
        self.assertNotContains(response, "Hardware Passkeys (FIDO2 / WebAuthn)")

    def test_authenticated_user_access_renders_dashboard_with_context(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("auth_bridge:login"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "auth_bridge/authenticated_dashboard.html")

        self.assertEqual(response.context["primary_email"], self.user.email)
        self.assertEqual(response.context["custodial_did"], self.user.custodial_did)
        self.assertEqual(response.context["account_tier"], "sovereign")
        self.assertEqual(
            list(response.context["linked_emails"]),
            list(self.user.linked_emails.all().order_by("-verified_at")),
        )
        self.assertEqual(
            list(response.context["passkeys"]),
            list(self.user.passkeys.all().order_by("-created_at")),
        )

        content = response.content.decode("utf-8")
        self.assertIn("Protected Identity &amp; Email Locker", content)
        self.assertIn("Hardware Passkeys (FIDO2 / WebAuthn)", content)
        self.assertIn("Primary / Root", content)
        self.assertIn(self.user.email, content)
        self.assertIn("corp_work@enterprise.com", content)
        self.assertIn("pseudonym_alias@privacy.org", content)
        self.assertIn("Claim &amp; Lock Additional Email", content)
        self.assertIn("+ Register Device Passkey", content)
        self.assertIn("Export W3C Credential", content)

    def test_landing_route_renders_dashboard_for_authenticated_user(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "auth_bridge/authenticated_dashboard.html")
        self.assertEqual(response.context["primary_email"], self.user.email)

    def test_toggle_linked_email_public_status_patch(self) -> None:
        self.client.force_login(self.user)
        url = reverse("auth_bridge:email_link_remove", kwargs={"id": self.linked_1.id})
        response = self.client.patch(
            url,
            data=json.dumps({"is_public": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["is_public"])

        self.linked_1.refresh_from_db()
        self.assertTrue(self.linked_1.is_public)

    def test_toggle_linked_email_public_status_post(self) -> None:
        self.client.force_login(self.user)
        url = reverse("auth_bridge:email_link_remove", kwargs={"id": self.linked_2.id})
        response = self.client.post(
            url,
            data=json.dumps({"is_public": False}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertFalse(data["is_public"])

        self.linked_2.refresh_from_db()
        self.assertFalse(self.linked_2.is_public)

    def test_toggle_linked_email_forbidden_for_other_user(self) -> None:
        self.client.force_login(self.other_user)
        url = reverse("auth_bridge:email_link_remove", kwargs={"id": self.linked_1.id})
        response = self.client.patch(
            url,
            data=json.dumps({"is_public": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)

    def test_toggle_linked_email_unauthenticated_rejected(self) -> None:
        url = reverse("auth_bridge:email_link_remove", kwargs={"id": self.linked_1.id})
        response = self.client.patch(
            url,
            data=json.dumps({"is_public": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_export_linked_email_vc_endpoint(self) -> None:
        self.client.force_login(self.user)
        url = reverse("auth_bridge:email_link_vc", kwargs={"id": self.linked_1.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("vc", data)
        self.assertEqual(data["vc"]["credentialSubject"]["email"], self.linked_1.email)
        self.assertEqual(data["vc"]["credentialSubject"]["id"], self.user.custodial_did)

    def test_export_primary_email_vc_endpoint(self) -> None:
        self.client.force_login(self.user)
        url = reverse("auth_bridge:email_link_credential")
        response = self.client.get(f"{url}?email={self.user.email}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("vc", data)
        self.assertEqual(data["vc"]["credentialSubject"]["email"], self.user.email)
        self.assertEqual(data["vc"]["credentialSubject"]["label"], "primary")

    def test_export_vc_not_found_for_unrelated_email(self) -> None:
        self.client.force_login(self.user)
        url = reverse("auth_bridge:email_link_credential")
        response = self.client.get(f"{url}?email=unknown_address@random.com")
        self.assertEqual(response.status_code, 404)

    def test_export_vc_unauthenticated_rejected(self) -> None:
        url = reverse("auth_bridge:email_link_credential")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 401)
