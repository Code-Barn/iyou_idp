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

from datetime import datetime, timezone as dt_timezone
import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client as TestClient, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from oidc_provider.models import Client as OIDCClient, ResponseType, RSAKey as OIDCRSAKey

from auth_bridge.credentials import (
    AGE_BRACKET_ADULT,
    AGE_BRACKET_U14,
    AGE_BRACKET_U14_U18,
    DISALLOWED_PII_FIELDS,
    VALID_AGE_BRACKETS,
)
from auth_bridge.models import User
from auth_bridge.oidc import CustomScopeClaims, custom_id_token_claims, custom_userinfo_claims
from auth_bridge.tokens import register_dependent_vector
from auth_bridge.views import compute_age_bracket

SET_AGE_GATE_URL = reverse("auth_bridge:set_age_bracket")
AGE_GATE_URL = reverse("auth_bridge:age_gate")


class MockOIDCToken:
    def __init__(self, user: User, userinfo: dict, client: OIDCClient):
        self.user = user
        self.userinfo = userinfo
        self.client = client
        self.scope = ["openid", "profile"]


@override_settings(
    ALLOWED_HOSTS=["*"],
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="info@iyou.me",
    SYSTEM_GATE_ENABLED=False,
)
class AgeGateTests(TestCase):
    def setUp(self):
        super().setUp()
        self.client = TestClient()

        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        code_type, _ = ResponseType.objects.get_or_create(value="code")
        self.oidc_client = OIDCClient.objects.create(
            name="Age Gate Test Client",
            client_type="confidential",
            client_id="age-gate-test-client",
            client_secret="secret-age-123",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.oidc_client.response_types.add(code_type)

        self.user = User.objects.create(
            email="test_age_user@example.com",
            custodial_did="did:key:z6Mkh1AgeGateTestUserDidForZeroPiiVerification",
            account_tier="managed_free",
            email_verified=True,
            show_legal_disclaimer=False,
        )

    def test_constants_and_disallowed_pii(self):
        self.assertIn(AGE_BRACKET_ADULT, VALID_AGE_BRACKETS)
        self.assertIn(AGE_BRACKET_U14, VALID_AGE_BRACKETS)
        self.assertIn(AGE_BRACKET_U14_U18, VALID_AGE_BRACKETS)
        for field in ("birth_date", "dob", "birthdate", "month", "year"):
            self.assertIn(field, DISALLOWED_PII_FIELDS)

    def test_compute_age_bracket_boundaries(self):
        fixed_now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=dt_timezone.utc)

        with patch("django.utils.timezone.now", return_value=fixed_now):
            self.assertEqual(compute_age_bracket(month=6, year=2013), "U14")
            self.assertEqual(compute_age_bracket(month=7, year=2012), "U14")
            self.assertEqual(compute_age_bracket(month=5, year=2012), "U14-U18")
            self.assertEqual(compute_age_bracket(month=6, year=2012), "U14-U18")
            self.assertEqual(compute_age_bracket(month=6, year=2009), "U14-U18")
            self.assertEqual(compute_age_bracket(month=7, year=2008), "U14-U18")
            self.assertEqual(compute_age_bracket(month=5, year=2008), "ADULT")
            self.assertEqual(compute_age_bracket(month=6, year=2008), "ADULT")
            self.assertEqual(compute_age_bracket(month=1, year=1990), "ADULT")

    def test_set_age_bracket_unauthenticated_returns_401(self):
        resp = self.client.post(
            SET_AGE_GATE_URL,
            json.dumps({"month": 5, "year": 2000}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)
        self.assertFalse(resp.json().get("success"))

    def test_set_age_bracket_invalid_inputs_return_400(self):
        self.client.force_login(self.user, backend="auth_bridge.backend.DIDAuthBackend")

        resp1 = self.client.post(
            SET_AGE_GATE_URL,
            json.dumps({"month": "abc", "year": 2000}),
            content_type="application/json",
        )
        self.assertEqual(resp1.status_code, 400)

        resp2 = self.client.post(
            SET_AGE_GATE_URL,
            json.dumps({"month": 13, "year": 2000}),
            content_type="application/json",
        )
        self.assertEqual(resp2.status_code, 400)

        resp3 = self.client.post(
            SET_AGE_GATE_URL,
            json.dumps({"month": 5, "year": timezone.now().year + 2}),
            content_type="application/json",
        )
        self.assertEqual(resp3.status_code, 400)

    def test_set_age_bracket_u14_and_zero_pii_guarantee(self):
        self.client.force_login(self.user, backend="auth_bridge.backend.DIDAuthBackend")

        now_year = timezone.now().year
        resp = self.client.post(
            SET_AGE_GATE_URL,
            json.dumps({"month": 1, "year": now_year - 12}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("bracket"), "U14")
        self.assertTrue(data.get("requires_guardian"))

        self.user.refresh_from_db()
        self.assertEqual(self.user.age_bracket, "U14")
        self.assertIsNotNone(self.user.age_bracket_established_at)
        self.assertFalse(hasattr(self.user, "month"))
        self.assertFalse(hasattr(self.user, "year"))
        self.assertFalse(hasattr(self.user, "birth_date"))
        self.assertFalse(hasattr(self.user, "dob"))

    def test_set_age_bracket_adult_flow(self):
        self.client.force_login(self.user, backend="auth_bridge.backend.DIDAuthBackend")

        resp = self.client.post(
            SET_AGE_GATE_URL,
            json.dumps({"month": 1, "year": 1995, "next_url": "/satellite/callback/"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("bracket"), "ADULT")
        self.assertFalse(data.get("requires_guardian", False))

        self.user.refresh_from_db()
        self.assertEqual(self.user.age_bracket, "ADULT")

    def test_authorize_view_redirects_unbracketed_user(self):
        self.client.force_login(self.user, backend="auth_bridge.backend.DIDAuthBackend")
        self.user.age_bracket = None
        self.user.save(update_fields=["age_bracket"])

        auth_url = (
            f"/openid/authorize/?client_id={self.oidc_client.client_id}"
            f"&response_type=code&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile&state=test-state&nonce=test-nonce"
        )
        resp = self.client.get(auth_url)
        self.assertEqual(resp.status_code, 302)
        redirect_target = resp.get("Location") or getattr(resp, "url", "")
        parsed = urlparse(redirect_target)
        self.assertEqual(parsed.path, AGE_GATE_URL)
        query = parse_qs(parsed.query)
        self.assertIn("next", query)

    def test_authorize_view_passes_bracketed_user(self):
        self.client.force_login(self.user, backend="auth_bridge.backend.DIDAuthBackend")
        session = self.client.session
        session["auth_method"] = "otp:email"
        session.save()

        self.user.age_bracket = "ADULT"
        self.user.show_legal_disclaimer = False
        self.user.save(update_fields=["age_bracket", "show_legal_disclaimer"])

        auth_url = (
            f"/openid/authorize/?client_id={self.oidc_client.client_id}"
            f"&response_type=code&redirect_uri=https://satellite.iyou.me/callback/"
            f"&scope=openid+profile&state=test-state&nonce=test-nonce"
        )
        resp = self.client.get(auth_url)
        self.assertEqual(resp.status_code, 302)
        redirect_target = resp.get("Location") or getattr(resp, "url", "")
        self.assertTrue(redirect_target.startswith("https://satellite.iyou.me/callback/"))
        self.assertIn("code=", redirect_target)

    def test_userinfo_and_id_token_claims_output_age_bracket(self):
        self.user.age_bracket = "ADULT"
        self.user.save(update_fields=["age_bracket"])

        claims = custom_userinfo_claims({}, self.user)
        self.assertEqual(claims.get("age_bracket"), "ADULT")

        id_token = custom_id_token_claims({}, self.user)
        self.assertEqual(id_token.get("age_bracket"), "ADULT")

        mock_token = MockOIDCToken(self.user, claims, self.oidc_client)
        scope_claims = CustomScopeClaims(mock_token)
        profile_claims = scope_claims.scope_profile()
        self.assertEqual(profile_claims.get("age_bracket"), "ADULT")

        openid_claims = scope_claims.scope_openid()
        self.assertEqual(openid_claims.get("age_bracket"), "ADULT")

    @patch("auth_bridge.tokens.validate_age_bracket_vc", return_value={
        "bracket": "U14",
        "parent_did": "did:key:z6MkParentTestingDid12345678901234567890",
        "issued_at": 1725000000,
        "expires_at": 1756536000,
        "raw_payload": {"raw": "mock_vc_payload"},
    })
    def test_userinfo_and_id_token_claims_with_dep_block(self, mock_validate):
        parent_did = "did:key:z6MkParentTestingDid12345678901234567890"
        child_did = self.user.custodial_did
        register_dependent_vector(
            child_did=child_did,
            parent_did=parent_did,
            attestation_vc={"raw": "mock_vc_payload"},
            bracket="U14",
        )
        self.user.age_bracket = "U14"
        self.user.save(update_fields=["age_bracket"])

        claims = custom_userinfo_claims({}, self.user)
        self.assertEqual(claims.get("age_bracket"), "U14")
        self.assertIn("dep", claims)
        self.assertEqual(claims["dep"]["bracket"], "U14")

        id_token = custom_id_token_claims({}, self.user)
        self.assertEqual(id_token.get("age_bracket"), "U14")
        self.assertIn("dep", id_token)
        self.assertEqual(id_token["dep"]["bracket"], "U14")

    def test_age_gate_standalone_page_get(self):
        self.client.force_login(self.user, backend="auth_bridge.backend.DIDAuthBackend")
        resp = self.client.get(f"{AGE_GATE_URL}?next=/callback/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Age-Appropriate Safety Defaults")
        self.assertContains(resp, "Your birth date is never stored.")
