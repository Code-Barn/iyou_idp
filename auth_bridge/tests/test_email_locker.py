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
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core import mail
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from oidc_provider.models import RSAKey as OIDCRSAKey

from auth_bridge.models import FederatedIdentity, LinkedEmail, User
from auth_bridge.pipeline import process_oauth_identity
from auth_bridge.resilient_cache import cache


@override_settings(SYSTEM_GATE_ENABLED=False)
class MultiEmailLockerTest(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        self.user_a = User.objects.create_user(
            email="primary_a@iyou.me",
            email_verified=True,
        )
        self.user_b = User.objects.create_user(
            email="primary_b@iyou.me",
            email_verified=True,
        )

    def test_challenge_and_verify_secondary_email(self) -> None:
        self.client.force_login(self.user_a)
        secondary = "work_alias@iyou.me"

        resp = self.client.post(
            reverse("auth_bridge:email_link_challenge"),
            data=json.dumps({"email": secondary, "label": "work"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("verification code", mail.outbox[0].subject.lower())

        cached_raw = cache.get(f"email_link_otp:{secondary}")
        self.assertIsNotNone(cached_raw)
        cached_data = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw
        otp = cached_data["otp"]
        self.assertEqual(cached_data["label"], "work")

        verify_resp = self.client.post(
            reverse("auth_bridge:email_link_verify"),
            data=json.dumps({"email": secondary, "otp": otp}),
            content_type="application/json",
        )
        self.assertEqual(verify_resp.status_code, 200)
        vdata = verify_resp.json()
        self.assertTrue(vdata["success"])
        self.assertEqual(vdata["email"], secondary)
        self.assertEqual(vdata["label"], "work")

        vc = vdata["vc"]
        self.assertEqual(vc["type"], ["VerifiableCredential", "EmailOwnershipCredential"])
        self.assertEqual(vc["issuer"], "did:web:iyou.me")
        self.assertEqual(vc["credentialSubject"]["id"], self.user_a.custodial_did)
        self.assertEqual(vc["credentialSubject"]["email"], secondary)
        self.assertEqual(vc["credentialSubject"]["label"], "work")
        self.assertIn("proof", vc)

        self.assertTrue(LinkedEmail.objects.filter(email=secondary, user=self.user_a).exists())
        self.assertIsNone(cache.get(f"email_link_otp:{secondary}"))

    def test_challenge_rejected_for_already_claimed_primary_email(self) -> None:
        self.client.force_login(self.user_a)
        resp = self.client.post(
            reverse("auth_bridge:email_link_challenge"),
            data=json.dumps({"email": self.user_a.email, "label": "personal"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["error"], "email_already_claimed")

    def test_challenge_rejected_for_already_linked_email(self) -> None:
        LinkedEmail.objects.create(
            user=self.user_b,
            email="existing_alias@iyou.me",
            label="alias",
        )
        self.client.force_login(self.user_a)
        resp = self.client.post(
            reverse("auth_bridge:email_link_challenge"),
            data=json.dumps({"email": "existing_alias@iyou.me", "label": "work"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()["error"], "email_already_claimed")

    def test_non_owner_cannot_verify_otp_initiated_by_another_user(self) -> None:
        self.client.force_login(self.user_a)
        target_email = "secure_alias@iyou.me"
        self.client.post(
            reverse("auth_bridge:email_link_challenge"),
            data=json.dumps({"email": target_email, "label": "work"}),
            content_type="application/json",
        )

        cached_raw = cache.get(f"email_link_otp:{target_email}")
        otp = json.loads(cached_raw)["otp"]

        self.client.force_login(self.user_b)
        attacker_resp = self.client.post(
            reverse("auth_bridge:email_link_verify"),
            data=json.dumps({"email": target_email, "otp": otp}),
            content_type="application/json",
        )
        self.assertEqual(attacker_resp.status_code, 403)
        self.assertEqual(attacker_resp.json()["error"], "user_mismatch")
        self.assertFalse(LinkedEmail.objects.filter(email=target_email).exists())

    def test_list_linked_emails(self) -> None:
        self.client.force_login(self.user_a)
        LinkedEmail.objects.create(user=self.user_a, email="a1@work.com", label="work")
        LinkedEmail.objects.create(user=self.user_a, email="a2@alias.com", label="alias")

        resp = self.client.get(reverse("auth_bridge:email_link_list"))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["primary_email"], self.user_a.email)
        emails = [item["email"] for item in data["linked_emails"]]
        self.assertIn("a1@work.com", emails)
        self.assertIn("a2@alias.com", emails)

    def test_remove_linked_email(self) -> None:
        self.client.force_login(self.user_a)
        e = LinkedEmail.objects.create(user=self.user_a, email="removable@work.com", label="work")

        remove_url = reverse("auth_bridge:email_link_remove", kwargs={"id": e.id})
        resp = self.client.delete(remove_url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])
        self.assertFalse(LinkedEmail.objects.filter(id=e.id).exists())

        resp_404 = self.client.delete(remove_url)
        self.assertEqual(resp_404.status_code, 404)

    def test_remove_linked_email_forbidden_for_other_user(self) -> None:
        e = LinkedEmail.objects.create(user=self.user_a, email="private@work.com", label="work")
        self.client.force_login(self.user_b)

        remove_url = reverse("auth_bridge:email_link_remove", kwargs={"id": e.id})
        resp = self.client.delete(remove_url)
        self.assertEqual(resp.status_code, 404)
        self.assertTrue(LinkedEmail.objects.filter(id=e.id).exists())

    def test_unauthenticated_requests_fail_cleanly(self) -> None:
        c_url = reverse("auth_bridge:email_link_challenge")
        v_url = reverse("auth_bridge:email_link_verify")
        l_url = reverse("auth_bridge:email_link_list")
        r_url = reverse("auth_bridge:email_link_remove", kwargs={"id": uuid.uuid4()})

        self.assertEqual(self.client.post(c_url, {}).status_code, 401)
        self.assertEqual(self.client.post(v_url, {}).status_code, 401)
        self.assertEqual(self.client.get(l_url).status_code, 401)
        self.assertEqual(self.client.delete(r_url).status_code, 401)

    def test_oauth_smart_merge_resolves_via_linked_email(self) -> None:
        secondary_email = "corporate_identity@enterprise.com"
        LinkedEmail.objects.create(
            user=self.user_a,
            email=secondary_email,
            label="work",
        )

        result = process_oauth_identity(
            provider_name="google",
            provider_uid="google-corp-uid-100",
            email=secondary_email,
            email_verified=True,
        )

        self.assertEqual(result["action"], "login")
        self.assertEqual(result["user"].id, self.user_a.id)

        fed = FederatedIdentity.objects.filter(
            provider="google",
            provider_user_id="google-corp-uid-100",
        ).first()
        self.assertIsNotNone(fed)
        self.assertEqual(fed.user.id, self.user_a.id)


class PrimaryEmailClaimTest(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())
        self.claimant = User.objects.create_user(
            email=None,
            custodial_did=f"did:key:claimant-{uuid.uuid4().hex}",
        )
        self.other_user = User.objects.create_user(
            email="other_primary@iyou.me",
            custodial_did=f"did:key:other-{uuid.uuid4().hex}",
        )

    def _challenge(self, email: str):
        return self.client.post(
            reverse("auth_bridge:email_primary_challenge"),
            data=json.dumps({"email": email}),
            content_type="application/json",
        )

    def _verify(self, email: str, otp: str):
        return self.client.post(
            reverse("auth_bridge:email_primary_verify"),
            data=json.dumps({"email": email, "otp": otp}),
            content_type="application/json",
        )

    def test_challenge_and_verify_primary_email(self) -> None:
        self.client.force_login(self.claimant)
        email = "new_primary@iyou.me"

        challenge = self._challenge(email)
        self.assertEqual(challenge.status_code, 200)
        self.assertEqual(challenge.json()["action"], "primary_claim_challenge_sent")
        self.assertEqual(len(mail.outbox), 1)

        cached = json.loads(cache.get(f"email_primary_otp:{email}"))
        self.assertEqual(cached["user_id"], str(self.claimant.id))

        verified = self._verify(email, cached["otp"])
        self.assertEqual(verified.status_code, 200)
        data = verified.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["label"], "primary")
        self.assertEqual(data["vc"]["credentialSubject"]["email"], email)

        self.claimant.refresh_from_db()
        self.assertEqual(self.claimant.email, email)
        self.assertTrue(self.claimant.email_verified)
        self.assertIsNotNone(self.claimant.email_verified_at)
        self.assertIsNone(cache.get(f"email_primary_otp:{email}"))

    def test_challenge_rejected_when_primary_already_claimed(self) -> None:
        self.client.force_login(self.other_user)
        response = self._challenge("another_primary@iyou.me")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], "primary_already_claimed")

    def test_challenge_rejected_for_email_claimed_in_user_or_linked_email(self) -> None:
        self.client.force_login(self.claimant)
        user_claim = self._challenge(self.other_user.email)
        self.assertEqual(user_claim.status_code, 409)
        self.assertEqual(user_claim.json()["error"], "email_already_claimed")

        LinkedEmail.objects.create(user=self.other_user, email="linked_claim@iyou.me", label="work")
        linked_claim = self._challenge("linked_claim@iyou.me")
        self.assertEqual(linked_claim.status_code, 409)
        self.assertEqual(linked_claim.json()["error"], "email_already_claimed")

    def test_verify_rejects_wrong_otp_and_other_user(self) -> None:
        email = "otp_guard@iyou.me"
        self.client.force_login(self.claimant)
        self._challenge(email)
        cached = json.loads(cache.get(f"email_primary_otp:{email}"))

        wrong_otp = "000000" if cached["otp"] != "000000" else "111111"
        wrong = self._verify(email, wrong_otp)
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(wrong.json()["error"], "invalid_otp")

        self.client.force_login(self.other_user)
        mismatch = self._verify(email, cached["otp"])
        self.assertEqual(mismatch.status_code, 403)
        self.assertEqual(mismatch.json()["error"], "user_mismatch")

        self.claimant.refresh_from_db()
        self.assertIsNone(self.claimant.email)

    def test_verify_is_single_use(self) -> None:
        email = "single_use@iyou.me"
        self.client.force_login(self.claimant)
        self._challenge(email)
        otp = json.loads(cache.get(f"email_primary_otp:{email}"))["otp"]

        first = self._verify(email, otp)
        self.assertEqual(first.status_code, 200)
        second = self._verify(email, otp)
        self.assertEqual(second.status_code, 400)
        self.assertEqual(second.json()["error"], "expired_or_invalid_otp")

    def test_verify_rejects_email_squatted_after_challenge(self) -> None:
        email = "race_claim@iyou.me"
        self.client.force_login(self.claimant)
        self._challenge(email)
        LinkedEmail.objects.create(user=self.other_user, email=email, label="work")
        otp = json.loads(cache.get(f"email_primary_otp:{email}"))["otp"]

        response = self._verify(email, otp)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], "email_already_claimed")
        self.claimant.refresh_from_db()
        self.assertIsNone(self.claimant.email)
