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
Tests for Zero-PII Age-Bracket Verifiable Credential Schema and Validation Engine (DEP-103).

Directives tested:
1. Valid U14 and U14-U18 credentials verify cleanly.
2. Assert validation fails if cleartext dob (or birth_date, full_name) is injected.
3. Assert validation fails on invalid parent DID signatures.
4. Schema conformance: @context, type containing AgeBracketCredential, subject ID.
5. Permission tier mapping:
   - U14: Stage 1 Guided Delegation (restricted kinds, relay allowlist).
   - U14-U18: Stage 2 Autonomous Persona (L2 contextual derivation permitted).
"""

from __future__ import annotations

import copy
import json

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from django.test import SimpleTestCase

from auth_bridge.credentials import (
    AGE_BRACKET_CONTEXT_URI,
    AGE_BRACKET_CREDENTIAL_TYPE,
    AGE_BRACKET_U14,
    AGE_BRACKET_U14_U18,
    VERIFIABLE_CREDENTIAL_TYPE,
    W3C_CREDENTIALS_CONTEXT_URI,
    CredentialValidationError,
    get_session_permission_tier,
    validate_age_bracket_credential,
)


def _make_did(pub_bytes: bytes) -> str:
    """Generate did:key multibase string from raw 32-byte Ed25519 public key."""
    multicodec = bytes([0xed, 0x01]) + pub_bytes
    return "did:key:z" + base58.b58encode(multicodec).decode("ascii")


def _generate_identity():
    """Generate an Ed25519 private key and corresponding did:key."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    did = _make_did(pub_bytes)
    return priv_key, did


def _sign_credential(
    payload: dict,
    signer_privkey: ed25519.Ed25519PrivateKey,
    issuer_did: str,
) -> dict:
    """
    Sign a credential dictionary with an Ed25519 private key,
    matching serde_json serialization order and W3C proof envelope.
    """
    vc = copy.deepcopy(payload)
    vc["issuer"] = issuer_did

    # Serialize payload without proof block
    payload_to_sign = {k: v for k, v in vc.items() if k != "proof"}
    payload_bytes = json.dumps(payload_to_sign, separators=(",", ":")).encode("utf-8")
    sig = signer_privkey.sign(payload_bytes)

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
    age_bracket: str = "U14",
    extra_subject_fields: dict | None = None,
    extra_vc_fields: dict | None = None,
    context: list[str] | None = None,
    types: list[str] | None = None,
) -> dict:
    """Build a compliant W3C Age-Bracket Verifiable Credential signed by parent DID."""
    subject = {
        "id": subject_did,
        "ageBracket": age_bracket,
    }
    if extra_subject_fields:
        subject.update(extra_subject_fields)

    vc_payload = {
        "@context": context
        or [
            W3C_CREDENTIALS_CONTEXT_URI,
            AGE_BRACKET_CONTEXT_URI,
        ],
        "type": types
        or [
            VERIFIABLE_CREDENTIAL_TYPE,
            AGE_BRACKET_CREDENTIAL_TYPE,
        ],
        "credentialSubject": subject,
    }
    if extra_vc_fields:
        vc_payload.update(extra_vc_fields)

    return _sign_credential(vc_payload, parent_privkey, parent_did)


class AgeBracketVCVerificationTests(SimpleTestCase):
    """Test suite for DEP-103 Zero-PII Age-Bracket VC Verification Schema."""

    def setUp(self):
        super().setUp()
        self.parent_privkey, self.parent_did = _generate_identity()
        self.child_privkey, self.child_did = _generate_identity()
        self.attacker_privkey, self.attacker_did = _generate_identity()

    def test_valid_u14_credential_verifies_cleanly(self):
        """Valid U14 credential verifies cleanly and maps to Stage 1 Guided Delegation."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )

        result = validate_age_bracket_credential(vc)

        self.assertTrue(result["valid"])
        self.assertEqual(result["issuer"], self.parent_did)
        self.assertEqual(result["subject_id"], self.child_did)
        self.assertEqual(result["age_bracket"], "U14")

        tier = result["permission_tier"]
        self.assertEqual(tier["bracket"], "U14")
        self.assertEqual(tier["stage"], 1)
        self.assertEqual(tier["stage_name"], "Stage 1 Guided Delegation")
        self.assertTrue(tier["restricted_kinds"])
        self.assertTrue(tier["relay_allowlist"])
        self.assertFalse(tier["l2_contextual_derivation_permitted"])

    def test_valid_u14_u18_credential_verifies_cleanly(self):
        """Valid U14-U18 credential verifies cleanly and maps to Stage 2 Autonomous Persona."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14_U18,
        )

        result = validate_age_bracket_credential(vc)

        self.assertTrue(result["valid"])
        self.assertEqual(result["issuer"], self.parent_did)
        self.assertEqual(result["subject_id"], self.child_did)
        self.assertEqual(result["age_bracket"], "U14-U18")

        tier = result["permission_tier"]
        self.assertEqual(tier["bracket"], "U14-U18")
        self.assertEqual(tier["stage"], 2)
        self.assertEqual(tier["stage_name"], "Stage 2 Autonomous Persona")
        self.assertFalse(tier["restricted_kinds"])
        self.assertFalse(tier["relay_allowlist"])
        self.assertTrue(tier["l2_contextual_derivation_permitted"])

    def test_json_string_input_supported(self):
        """Credential can be supplied as a serialized JSON string."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )
        vc_json = json.dumps(vc)

        result = validate_age_bracket_credential(vc_json)
        self.assertTrue(result["valid"])
        self.assertEqual(result["age_bracket"], "U14")

    def test_invalid_json_string_fails(self):
        """Malformed JSON string triggers CredentialValidationError."""
        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential("{invalid_json:true")
        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_validation_fails_if_cleartext_dob_is_injected_in_subject(self):
        """Assert validation fails if cleartext dob is injected into credentialSubject."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            extra_subject_fields={"dob": "2013-08-15"},
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Zero-PII violation", str(ctx.exception))
        self.assertIn("dob", str(ctx.exception))

    def test_validation_fails_if_cleartext_birth_date_is_injected(self):
        """Assert validation fails if cleartext birth_date is injected."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            extra_subject_fields={"birth_date": "2013-08-15"},
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Zero-PII violation", str(ctx.exception))
        self.assertIn("birth_date", str(ctx.exception))

    def test_validation_fails_if_cleartext_full_name_is_injected(self):
        """Assert validation fails if cleartext full_name is injected."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14_U18,
            extra_subject_fields={"full_name": "Minor Subject Name"},
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Zero-PII violation", str(ctx.exception))
        self.assertIn("full_name", str(ctx.exception))

    def test_validation_fails_if_cleartext_pii_injected_at_root(self):
        """Assert validation fails if cleartext PII is injected at root level of VC."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            extra_vc_fields={"date_of_birth": "2013-08-15"},
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Zero-PII violation", str(ctx.exception))

    def test_validation_fails_on_corrupted_parent_signature(self):
        """Assert validation fails when parent DID signature bytes are corrupted."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )
        # Invalidate proof value
        vc["proof"]["proofValue"] = "00" * 64

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Invalid parent DID signature", str(ctx.exception))

    def test_validation_fails_on_attacker_signed_credential(self):
        """Assert validation fails when signed by an attacker key instead of parent DID."""
        # Claims issuer is parent_did, but signed with attacker_privkey
        vc_payload = {
            "@context": [
                W3C_CREDENTIALS_CONTEXT_URI,
                AGE_BRACKET_CONTEXT_URI,
            ],
            "type": [
                VERIFIABLE_CREDENTIAL_TYPE,
                AGE_BRACKET_CREDENTIAL_TYPE,
            ],
            "credentialSubject": {
                "id": self.child_did,
                "ageBracket": AGE_BRACKET_U14,
            },
        }
        # Parent DID as issuer, but signed with attacker's key
        vc = _sign_credential(vc_payload, self.attacker_privkey, self.parent_did)

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Invalid parent DID signature", str(ctx.exception))

    def test_validation_fails_on_payload_tampering_after_signing(self):
        """Assert validation fails if subject is tampered from U14 to U14-U18 after signing."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
        )
        # Tamper payload after signing
        vc["credentialSubject"]["ageBracket"] = AGE_BRACKET_U14_U18

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Invalid parent DID signature", str(ctx.exception))

    def test_assert_type_contains_age_bracket_credential(self):
        """Assert validation fails if type does not contain AgeBracketCredential."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            types=["VerifiableCredential"],  # Missing AgeBracketCredential
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Credential type must contain 'AgeBracketCredential'", str(ctx.exception))

    def test_assert_context_validation(self):
        """Assert validation fails if required @context URIs are missing."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket=AGE_BRACKET_U14,
            context=[W3C_CREDENTIALS_CONTEXT_URI],  # Missing age-bracket context
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn(AGE_BRACKET_CONTEXT_URI, str(ctx.exception))

    def test_assert_unsupported_age_bracket_fails(self):
        """Assert validation fails on unsupported ageBracket."""
        vc = _build_age_bracket_vc(
            subject_did=self.child_did,
            parent_did=self.parent_did,
            parent_privkey=self.parent_privkey,
            age_bracket="U10",
        )

        with self.assertRaises(CredentialValidationError) as ctx:
            validate_age_bracket_credential(vc)
        self.assertIn("Unsupported ageBracket", str(ctx.exception))

    def test_direct_permission_tier_mapping(self):
        """Test get_session_permission_tier mappings directly."""
        u14_tier = get_session_permission_tier(AGE_BRACKET_U14)
        self.assertEqual(u14_tier["stage"], 1)
        self.assertTrue(u14_tier["restricted_kinds"])
        self.assertTrue(u14_tier["relay_allowlist"])
        self.assertFalse(u14_tier["l2_contextual_derivation_permitted"])

        u14_u18_tier = get_session_permission_tier(AGE_BRACKET_U14_U18)
        self.assertEqual(u14_u18_tier["stage"], 2)
        self.assertFalse(u14_u18_tier["restricted_kinds"])
        self.assertFalse(u14_u18_tier["relay_allowlist"])
        self.assertTrue(u14_u18_tier["l2_contextual_derivation_permitted"])

        with self.assertRaises(CredentialValidationError):
            get_session_permission_tier("INVALID_BRACKET")
