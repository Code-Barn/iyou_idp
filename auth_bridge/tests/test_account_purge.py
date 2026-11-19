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
from datetime import timedelta
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from oidc_provider.models import Client as OIDCClient, ResponseType, Token

from auth_bridge.models import (
    FederatedIdentity,
    IssuedCredential,
    LinkedEmail,
    PasskeyCredential,
    User,
)
from auth_bridge.resilient_cache import cache

PURGE_URL = "/auth/account/purge/"


class AccountPurgeViewTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="gdpr_target@iyou.me",
            custodial_did="did:web:iyou.me:user:gdpr-test-subject",
        )
        self.user_id = str(self.user.id)
        cache.set(f"user_auth_method:{self.user_id}", "webauthn:passkey", timeout=86400)

    def test_unauthenticated_request_rejected(self) -> None:
        client = Client()
        resp = client.post(
            PURGE_URL,
            data=json.dumps({"confirm": "PURGE"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json(), {"error": "authentication_required"})

    def test_missing_csrf_rejected_when_enforced(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        client.get(reverse("auth_bridge:login"))
        resp = client.post(
            PURGE_URL,
            data=json.dumps({"confirm": "PURGE"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)

    def test_confirmation_keyword_required(self) -> None:
        client = Client()
        client.force_login(self.user)

        resp = client.post(
            PURGE_URL,
            data=json.dumps({"confirm": "DELETE"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json(), {"error": "confirmation_required"})

        resp_empty = client.post(
            PURGE_URL,
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp_empty.status_code, 400)
        self.assertEqual(resp_empty.json(), {"error": "confirmation_required"})

    def test_successful_purge_cascades_detaches_and_erases(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        client.get(reverse("auth_bridge:login"))
        csrf_token = client.cookies["idp_csrftoken"].value

        session_store = SessionStore()
        session_store["_auth_user_id"] = self.user_id
        session_store["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
        session_store.save()
        sess_key = session_store.session_key
        self.assertTrue(Session.objects.filter(session_key=sess_key).exists())

        child_user = User.objects.create_user(
            email="absorbed_child@iyou.me",
            custodial_did="did:web:iyou.me:user:absorbed-child",
            merged_into=self.user,
        )

        linked_email = LinkedEmail.objects.create(
            user=self.user,
            email="linked_secondary@work.com",
            label="work",
        )

        federated_id = FederatedIdentity.objects.create(
            user=self.user,
            provider="google",
            provider_user_id="google-uid-gdpr-123",
        )

        passkey = PasskeyCredential.objects.create(
            user=self.user,
            credential_id=b"passkey-raw-id-gdpr",
            public_key_cose=b"passkey-cose-bytes",
            sign_count=1,
        )

        cred_subject = IssuedCredential.objects.create(
            subject_did=self.user.custodial_did,
            issuer_did="did:web:iyou.me",
            bracket="U14",
            raw_vc={},
        )
        cred_issuer = IssuedCredential.objects.create(
            subject_did="did:key:recipient-person",
            issuer_did=self.user.custodial_did,
            bracket="U14",
            raw_vc={},
        )

        code_type, _ = ResponseType.objects.get_or_create(value="code")
        oidc_client = OIDCClient.objects.create(
            name="GDPR Test Client",
            client_type="public",
            client_id="gdpr-test-client",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/",
        )
        oidc_client.response_types.add(code_type)
        oidc_token = Token.objects.create(
            user=self.user,
            client=oidc_client,
            expires_at=timezone.now() + timedelta(hours=1),
            scope=["openid"],
            access_token="gdpr-access-token-123",
        )

        with self.assertLogs("auth_bridge.views_account", level="INFO") as captured:
            resp = client.post(
                PURGE_URL,
                data=json.dumps({"confirm": "PURGE"}),
                content_type="application/json",
                HTTP_X_CSRFTOKEN=csrf_token,
            )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"success": True, "redirect_url": "/"})

        self.assertFalse(User.objects.filter(id=self.user_id).exists())

        child_user.refresh_from_db()
        self.assertIsNone(child_user.merged_into)
        self.assertTrue(child_user.is_active)

        self.assertFalse(LinkedEmail.objects.filter(id=linked_email.id).exists())
        self.assertFalse(FederatedIdentity.objects.filter(id=federated_id.id).exists())
        self.assertFalse(PasskeyCredential.objects.filter(id=passkey.id).exists())
        self.assertFalse(IssuedCredential.objects.filter(id=cred_subject.id).exists())
        self.assertFalse(IssuedCredential.objects.filter(id=cred_issuer.id).exists())
        self.assertFalse(Token.objects.filter(id=oidc_token.id).exists())
        self.assertFalse(Session.objects.filter(session_key=sess_key).exists())

        self.assertIsNone(cache.get(f"user_auth_method:{self.user_id}"))

        self.assertEqual(resp.cookies["idp_csrftoken"].value, "")
        self.assertEqual(resp.cookies["iyou_sso_hint"].value, "")

        log_output = "\n".join(captured.output)
        expected_log = f"GDPR Art.17 erasure completed user_id={self.user_id}"
        self.assertIn(expected_log, log_output)
        self.assertNotIn("gdpr_target@iyou.me", log_output)
        self.assertNotIn(self.user.custodial_did, log_output)
        self.assertNotIn("127.0.0.1", log_output)
