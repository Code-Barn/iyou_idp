# Copyright (C) 2026 David Byers dba Byers Brands
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but=\"WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Automated tests for DependentTokenSlot OIDC Claim Namespace (DEP-104).

Directives tested:
1. Token Payload Injection:
   - Authenticating with a valid parent-signed U14 credential injects the complete `dep` block.
   - Assert `sub` contains the child's derived leaf DID.
   - Assert no cleartext birth date is present anywhere in the token.
   - Support for multiple brackets ("U14", "U14-U18", "U18").
2. Session Revocation Interceptor:
   - If `dep.revoked == true` (checked against IssuedCredential or kind:9112 tickets),
     immediately reject token refresh or session validation with HTTP 403 `DependentSessionRevoked`.
3. Expired or revoked credentials abort token issuance.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
import jwt
from django.test import Client as TestClient, TestCase
from django.urls import reverse
from django.utils import timezone
from oidc_provider.models import Client as OIDCClient, Code, ResponseType, RSAKey as OIDCRSAKey, Token

from auth_bridge.credentials import (
    AGE_BRACKET_CONTEXT_URI,
    AGE_BRACKET_CREDENTIAL_TYPE,
    AGE_BRACKET_U14,
    AGE_BRACKET_U14_U18,
    AGE_BRACKET_U18,
    VERIFIABLE_CREDENTIAL_TYPE,
    W3C_CREDENTIALS_CONTEXT_URI,
    CredentialValidationError,
)
from auth_bridge.models import IssuedCredential, User
from auth_bridge.tokens import (
    DependentSessionRevokedError,
    ExpiredCredentialError,
    inject_dependent_claims,
    is_credential_revoked,
    record_revocation_ticket,
    register_dependent_vector,
)


def _make_did(pub_bytes: bytes) -> str:
    """Generate did:key multibase string from raw 32-byte Ed25519 public key."""
    multicodec = bytes([0xed, 0x01]) + pub_bytes
    return "did:key:z" + base58.b58encode(multicodec).decode("ascii")


def _generate_parent_identity():
    """Generate an Ed25519 private key, did:key, and raw seed for parent enclave."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    did = _make_did(pub_bytes)
    raw_seed = priv_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return priv_key, did, raw_seed


def _derive_child_leaf_identity(parent_seed: bytes, index: int = 0):
    """
    Derive child leaf Ed25519 keypair and DID per SPEC Section 2.1:
    child_seed = SHA-256(root_seed || "iyou/dependent/" || LE32(index))
    """
    hasher = hashlib.sha256()
    hasher.update(parent_seed)
    hasher.update(b"iyou/dependent/")
    hasher.update(index.to_bytes(4, "little"))
    child_seed = hasher.digest()
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(child_seed)
    pub_bytes = priv_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    did = _make_did(pub_bytes)
    return priv_key, did


def _sign_vc(payload: dict, parent_privkey: ed25519.Ed25519PrivateKey, issuer_did: str) -> dict:
    """Sign credential payload using parent private key with serde_json-compatible canonical encoding."""
    vc = copy.deepcopy(payload)
    vc["issuer"] = issuer_did

    payload_to_sign = {k: v for k, v in vc.items() if k != "proof"}
    payload_bytes = json.dumps(payload_to_sign, separators=(",", ":")).encode("utf-8")
    sig = parent_privkey.sign(payload_bytes)

    vc["proof"] = {
        "type": "Ed25519Signature2018",
        "created": "2026-09-02T00:00:00Z",
        "verificationMethod": f"{issuer_did}#keys-1",
        "proofPurpose": "assertionMethod",
        "proofValue": sig.hex(),
    }
    return vc


def _build_age_bracket_vc(
    subject_did: str,
    parent_did: str,
    parent_privkey: ed25519.Ed25519PrivateKey,
    age_bracket: str = AGE_BRACKET_U14,
    issued_at: int | None = None,
    expires_at: int | None = None,
    revoked: bool = False,
    extra_subject_fields: dict | None = None,
    extra_vc_fields: dict | None = None,
) -> dict:
    """Build a standard W3C AgeBracketCredential signed by parent DID."""
    subject = {
        "id": subject_did,
        "ageBracket": age_bracket,
    }
    if extra_subject_fields:
        subject.update(extra_subject_fields)

    vc_payload = {
        "@context": [
            W3C_CREDENTIALS_CONTEXT_URI,
            AGE_BRACKET_CONTEXT_URI,
        ],
        "type": [
            VERIFIABLE_CREDENTIAL_TYPE,
            AGE_BRACKET_CREDENTIAL_TYPE,
        ],
        "credentialSubject": subject,
    }
    if issued_at is not None:
        vc_payload["issuanceDate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued_at))
        vc_payload["issued_at"] = issued_at
    if expires_at is not None:
        vc_payload["expirationDate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at))
        vc_payload["expires_at"] = expires_at
    if revoked:
        vc_payload["revoked"] = True

    if extra_vc_fields:
        vc_payload.update(extra_vc_fields)

    return _sign_vc(vc_payload, parent_privkey, parent_did)


class DependentTokenSlotOIDCClaimsTest(TestCase):
    """Test suite for DEP-104 DependentTokenSlot OIDC Claim Namespace and Revocation Interceptor."""

    def setUp(self):
        super().setUp()
        self.client = TestClient()

        # Generate RSA signing key for OIDC provider
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        OIDCRSAKey.objects.create(key=pem.decode())

        code_type, _ = ResponseType.objects.get_or_create(value="code")
        self.oidc_client = OIDCClient.objects.create(
            name="Dependent Satellite Client",
            client_type="confidential",
            client_id="dependent-test-satellite",
            client_secret="satellite-secret-123",
            jwt_alg="RS256",
            _redirect_uris="https://satellite.iyou.me/callback/\n",
            _scope="openid profile",
            require_consent=False,
            reuse_consent=True,
        )
        self.oidc_client.response_types.add(code_type)

        # Generate cryptographic identities: Parent and Child (derived leaf keypair)
        self.parent_privkey, self.parent_did, self.parent_seed = _generate_parent_identity()
        self.child_privkey, self.child_did = _derive_child_leaf_identity(self.parent_seed, index=0)

        # Child User in IdP
        self.child_user, _ = User.objects.get_or_create(
            custodial_did=self.child_did,
            defaults={"email": None, "account_tier": "managed_free"},
        )

        # Attacker identity for negative tests
        self.attacker_privkey, self.attacker_did, _ = _generate_parent_identity()

    def _issue_auth_code_for_user(self, user: User) -> str:
        """Create and return an authorization code for the specified user."""
        code = Code.objects.create(
            user=user,
            client=self.oidc_client,
            code=f"test-auth-code-{user.id}-{int(time.time() * 1000)}",
            is_authentication=True,
            scope=["openid", "profile"],
            expires_at=timezone.now() + timezone.timedelta(minutes=10),
        )
        return code.code

    def test_valid_parent_signed_u14_credential_injects_complete_dep_block(self):
        """
        Authenticating with a valid parent-signed U14 credential injects the complete
        `dep` block into the decoded id_token with all required DEP-104 fields.
        """
        now = int(time.time())
        issued_at = now - 3600
        expires_at = now + 31536000

        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            issued_at=issued_at,
            expires_at=expires_at,
        )

        # Register dependent vector in IdP
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=vc,
            bracket=AGE_BRACKET_U14,
            issued_at=issued_at,
            expires_at=expires_at,
        )

        # Issue code and exchange at token endpoint
        code = self._issue_auth_code_for_user(self.child_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("id_token", body)

        # Decode id_token JWT
        decoded = jwt.decode(body["id_token"], options={"verify_signature": False})

        # Directive 1 assertions
        self.assertEqual(decoded["sub"], self.child_did)
        self.assertIn("dep", decoded)
        dep = decoded["dep"]
        self.assertEqual(dep["bracket"], "U14")
        self.assertEqual(dep["wot_distance"], 1)
        self.assertEqual(dep["parent_did"], self.parent_did)
        self.assertEqual(dep["issued_at"], issued_at)
        self.assertEqual(dep["expires_at"], expires_at)
        self.assertFalse(dep["revoked"])
        self.assertIsNotNone(dep.get("attestation_vc"))

    def test_sub_contains_derived_leaf_did_and_no_cleartext_birth_date(self):
        """
        Assert sub contains child's derived leaf DID and no cleartext birth date
        (birth_date, dob, date_of_birth) is present anywhere in the token.
        """
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=vc,
            bracket=AGE_BRACKET_U14,
        )

        code = self._issue_auth_code_for_user(self.child_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 200)
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})

        # Leaf DID assertion
        self.assertEqual(decoded["sub"], self.child_did)
        self.assertTrue(decoded["sub"].startswith("did:key:z6Mk"))

        # Zero-PII assertions across the entire token payload
        prohibited_pii = ["birth_date", "dob", "date_of_birth", "birthdate", "ssn", "full_name"]
        for pii in prohibited_pii:
            self.assertNotIn(pii, decoded)
            self.assertNotIn(pii, decoded.get("dep", {}))

        token_dump = json.dumps(decoded).lower()
        for pii in ["birth_date", "date_of_birth", "birthdate"]:
            self.assertNotIn(f'"{pii}"', token_dump)

    def test_cleartext_birth_date_injection_aborts_token_issuance(self):
        """Injecting cleartext birth_date into credential payload strictly aborts token issuance."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            extra_subject_fields={"birth_date": "2013-08-15"},
        )
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=vc,
            bracket=AGE_BRACKET_U14,
        )

        code = self._issue_auth_code_for_user(self.child_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())

    def test_expired_credential_aborts_token_issuance(self):
        """Expired age-bracket credentials must abort token issuance."""
        now = int(time.time())
        expired_vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            issued_at=now - 86400 * 400,
            expires_at=now - 86400 * 35,  # Expired 35 days ago
        )
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=expired_vc,
            bracket=AGE_BRACKET_U14,
            expires_at=now - 86400 * 35,
        )

        code = self._issue_auth_code_for_user(self.child_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        # Aborted issuance returns non-200 (400 invalid_grant)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.json())

        # Also test direct function invocation raises CredentialValidationError / ExpiredCredentialError
        with self.assertRaises((CredentialValidationError, ExpiredCredentialError)):
            inject_dependent_claims({"sub": self.child_did}, self.child_user)

    def test_revoked_credential_aborts_token_issuance(self):
        """Revoked credentials must abort token issuance with DependentSessionRevoked."""
        now = int(time.time())
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            issued_at=now - 3600,
            expires_at=now + 31536000,
        )
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=vc,
            bracket=AGE_BRACKET_U14,
            revoked=True,  # Revoked in database
        )

        code = self._issue_auth_code_for_user(self.child_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("DependentSessionRevoked", resp.content.decode())

        with self.assertRaises((CredentialValidationError, DependentSessionRevokedError)):
            inject_dependent_claims({"sub": self.child_did}, self.child_user)

    def test_revocation_interceptor_rejects_token_refresh(self):
        """
        Session Revocation Interceptor (Directive 2):
        Token refresh with dep.revoked == true or revoked IssuedCredential must be
        immediately rejected with HTTP 403 DependentSessionRevoked.
        """
        now = int(time.time())
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=vc,
            bracket=AGE_BRACKET_U14,
            revoked=False,
        )

        # Create active Token with refresh_token
        refresh_token_value = "test-refresh-token-active-12345"
        token = Token.objects.create(
            user=self.child_user,
            client=self.oidc_client,
            access_token="test-access-token-active-12345",
            refresh_token=refresh_token_value,
            expires_at=timezone.now() + timezone.timedelta(hours=1),
            scope=["openid", "profile"],
        )
        token.id_token = {
            "sub": self.child_did,
            "dep": {
                "bracket": "U14",
                "wot_distance": 1,
                "parent_did": self.parent_did,
                "attestation_vc": vc,
                "issued_at": now - 100,
                "expires_at": now + 31536000,
                "revoked": False,
            },
        }
        token.save()

        # 1. First verify refresh succeeds before revocation
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_value,
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 200)

        # 2. Mark IssuedCredential as revoked
        IssuedCredential.objects.filter(subject_did=self.child_did).update(revoked=True)
        self.assertTrue(is_credential_revoked(self.child_did))

        # Get latest refresh token from updated token
        latest_token = Token.objects.filter(user=self.child_user).latest("id")

        # 3. Interceptor must immediately reject with HTTP 403 DependentSessionRevoked
        resp_revoked = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": latest_token.refresh_token,
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp_revoked.status_code, 403)
        self.assertIn("DependentSessionRevoked", resp_revoked.content.decode())

    def test_revocation_interceptor_rejects_session_validation(self):
        """
        Session Revocation Interceptor (Directive 2):
        Authenticated web requests with a revoked dependent session must be
        immediately rejected with HTTP 403 DependentSessionRevoked.
        """
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc={"test": "vc"},
            bracket=AGE_BRACKET_U14,
            revoked=False,
        )

        # Login child session
        self.client.force_login(self.child_user)

        # Before revocation: landing / dashboard is accessible
        resp = self.client.get(reverse("landing"))
        self.assertNotEqual(resp.status_code, 403)

        # Parent triggers revocation
        IssuedCredential.objects.filter(subject_did=self.child_did).update(revoked=True)
        self.assertTrue(is_credential_revoked(self.child_did))

        # Middleware interceptor blocks with HTTP 403 DependentSessionRevoked
        resp_revoked = self.client.get(reverse("landing"))
        self.assertEqual(resp_revoked.status_code, 403)
        self.assertIn("DependentSessionRevoked", resp_revoked.content.decode())

    def test_kind_9112_revocation_ticket_triggers_revocation(self):
        """A Nostr kind:9112 RevocationTicket invalidates session and blocks token issuance."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )
        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=vc,
            bracket=AGE_BRACKET_U14,
            revoked=False,
        )

        # Submit Nostr kind:9112 RevocationTicket
        ticket = {
            "kind": 9112,
            "pubkey": "parent_nostr_pubkey_hex",
            "created_at": int(time.time()),
            "tags": [
                ["p", self.child_did],
                ["action", "revoke"],
                ["reason", "guardian_intervention"],
            ],
            "content": json.dumps({"action": "revoke", "subject": self.child_did}),
            "sig": "valid_nostr_sig_mock",
        }
        target = record_revocation_ticket(ticket)
        self.assertEqual(target, self.child_did)
        self.assertTrue(is_credential_revoked(self.child_did))

        # Interceptor blocks refresh / token requests with 403
        code = self._issue_auth_code_for_user(self.child_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("DependentSessionRevoked", resp.content.decode())

    def test_multiple_age_brackets_u14_u18_and_u18_injected_cleanly(self):
        """Ensure both U14-U18 and U18 age brackets inject valid dep block with correct bracket."""
        for bracket in [AGE_BRACKET_U14_U18, AGE_BRACKET_U18]:
            vc = _build_age_bracket_vc(
                subject_did=self.child_did,
                parent_did=self.parent_did,
                parent_privkey=self.parent_privkey,
                age_bracket=bracket,
            )
            register_dependent_vector(
                child_did=self.child_did,
                parent_did=self.parent_did,
                attestation_vc=vc,
                bracket=bracket,
            )

            id_token = {"sub": self.child_did}
            result = inject_dependent_claims(id_token, self.child_user)
            self.assertIn("dep", result)
            self.assertEqual(result["dep"]["bracket"], bracket)
            self.assertEqual(result["dep"]["wot_distance"], 1)
            self.assertEqual(result["dep"]["parent_did"], self.parent_did)

    def test_jwt_encoded_attestation_vc_verifies_and_injects_dep_block(self):
        """Ensure attestation_vc submitted as a parent-signed EdDSA JWT verifies and injects claims."""
        now = int(time.time())
        raw_vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            issued_at=now,
            expires_at=now + 31536000,
        )
        # Sign as EdDSA JWT using parent key
        jwt_vc = jwt.encode(
            {
                "iss": self.parent_did,
                "sub": self.child_did,
                "iat": now,
                "exp": now + 31536000,
                "vc": raw_vc,
            },
            self.parent_privkey,
            algorithm="EdDSA",
        )

        register_dependent_vector(
            child_did=self.child_did,
            parent_did=self.parent_did,
            attestation_vc=jwt_vc,
            bracket=AGE_BRACKET_U14,
        )

        id_token = {"sub": self.child_did}
        result = inject_dependent_claims(id_token, self.child_user)
        self.assertIn("dep", result)
        self.assertEqual(result["dep"]["attestation_vc"], jwt_vc)
        self.assertEqual(result["dep"]["bracket"], "U14")
        self.assertEqual(result["dep"]["parent_did"], self.parent_did)

    def test_non_dependent_regular_user_issues_token_without_dep_block(self):
        """Regular adult / sovereign user sessions must not have dep namespace injected."""
        adult_privkey, adult_did, _ = _generate_parent_identity()
        adult_user, _ = User.objects.get_or_create(
            custodial_did=adult_did,
            defaults={"email": "adult@iyou.me", "account_tier": "managed_premium"},
        )

        code = self._issue_auth_code_for_user(adult_user)
        resp = self.client.post(
            reverse("pkce_token"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://satellite.iyou.me/callback/",
                "client_id": self.oidc_client.client_id,
                "client_secret": self.oidc_client.client_secret,
            },
        )
        self.assertEqual(resp.status_code, 200)
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        self.assertEqual(decoded["sub"], adult_did)
        self.assertNotIn("dep", decoded)
