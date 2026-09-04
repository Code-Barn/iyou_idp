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
Zero-PII Age-Bracket Verifiable Credential Schema and Validation Engine (DEP-103).

Parses and verifies parent-attested W3C Age-Bracket Verifiable Credentials
without requiring or storing exact birth dates. Enforces zero-PII by rejecting
any payload with cleartext PII (such as birth_date, dob, full_name).
Maps age brackets to session permission tiers:
- U14: Stage 1 Guided Delegation (restricted kinds, relay allowlist)
- U14-U18: Stage 2 Autonomous Persona (L2 contextual derivation permitted)
"""

from __future__ import annotations

import json
import logging
from typing import Any

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger(__name__)

# Canonical schema & context URIs
AGE_BRACKET_CONTEXT_URI = "https://iyou.me/credentials/age-bracket/v1"
W3C_CREDENTIALS_CONTEXT_URI = "https://www.w3.org/2018/credentials/v1"

# Required credential types
VERIFIABLE_CREDENTIAL_TYPE = "VerifiableCredential"
AGE_BRACKET_CREDENTIAL_TYPE = "AgeBracketCredential"

# Supported age brackets
AGE_BRACKET_U14 = "U14"
AGE_BRACKET_U14_U18 = "U14-U18"
VALID_AGE_BRACKETS = {AGE_BRACKET_U14, AGE_BRACKET_U14_U18}

# Cleartext PII fields prohibited in Zero-PII credential payloads
DISALLOWED_PII_FIELDS = {
    "birth_date",
    "dob",
    "full_name",
    "date_of_birth",
    "birthdate",
    "first_name",
    "last_name",
    "ssn",
}

# Session permission tiers mapped from ageBracket
PERMISSION_TIERS: dict[str, dict[str, Any]] = {
    AGE_BRACKET_U14: {
        "bracket": AGE_BRACKET_U14,
        "stage": 1,
        "stage_name": "Stage 1 Guided Delegation",
        "restricted_kinds": True,
        "relay_allowlist": True,
        "l2_contextual_derivation_permitted": False,
        "l2_derivation_permitted": False,
        "autonomous_persona": False,
        "description": "Stage 1 Guided Delegation (restricted kinds, relay allowlist)",
    },
    AGE_BRACKET_U14_U18: {
        "bracket": AGE_BRACKET_U14_U18,
        "stage": 2,
        "stage_name": "Stage 2 Autonomous Persona",
        "restricted_kinds": False,
        "relay_allowlist": False,
        "l2_contextual_derivation_permitted": True,
        "l2_derivation_permitted": True,
        "autonomous_persona": True,
        "description": "Stage 2 Autonomous Persona (L2 contextual derivation permitted)",
    },
}


class CredentialValidationError(ValueError):
    """Raised when a Verifiable Credential fails structure, PII check, or signature verification."""
    pass


def get_session_permission_tier(age_bracket: str) -> dict[str, Any]:
    """
    Map an ageBracket string to session permission tiers.

    - U14: Stage 1 Guided Delegation (restricted kinds, relay allowlist).
    - U14-U18: Stage 2 Autonomous Persona (L2 contextual derivation permitted).
    """
    if age_bracket not in PERMISSION_TIERS:
        raise CredentialValidationError(
            f"Unsupported ageBracket '{age_bracket}'. Supported brackets: {sorted(VALID_AGE_BRACKETS)}"
        )
    return dict(PERMISSION_TIERS[age_bracket])


def _find_pii_fields(data: Any, disallowed: set[str] = DISALLOWED_PII_FIELDS) -> list[str]:
    """Recursively search dictionary keys and collections for prohibited cleartext PII fields."""
    found: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            normalized_key = str(k).strip().lower().replace("-", "_")
            if normalized_key in disallowed:
                found.append(str(k))
            found.extend(_find_pii_fields(v, disallowed))
    elif isinstance(data, list):
        for item in data:
            found.extend(_find_pii_fields(item, disallowed))
    return found


def _pubkey_from_did_key(did: str) -> bytes | None:
    """Extract raw 32-byte Ed25519 public key from a did:key string."""
    if not did or not did.startswith("did:key:"):
        return None
    multibase = did[len("did:key:"):]
    if not multibase.startswith("z"):
        return None
    try:
        decoded = base58.b58decode(multibase[1:])
    except Exception:
        return None
    if len(decoded) == 34 and decoded[0] == 0xed and decoded[1] == 0x01:
        return decoded[2:]
    return None


def _get_rust_verify_vc():
    """Import and return the verify_vc callable from did_rust / _crypto bridge if available."""
    try:
        from iyou_idp import _crypto
        if hasattr(_crypto, "verify_vc"):
            return _crypto.verify_vc, None
    except ImportError as e:
        logger.debug("from iyou_idp import _crypto failed: %s", e)

    try:
        import _crypto  # type: ignore[import-not-found]
        if hasattr(_crypto, "verify_vc"):
            return _crypto.verify_vc, None
    except ImportError as e:
        logger.debug("import _crypto failed: %s", e)

    return None, "Rust verify_vc not available"


def _verify_vc_signature_python(vc_obj: dict[str, Any], issuer_did: str) -> bool:
    """
    Fallback Python Ed25519 signature verification against issuer DID.
    Matches serde_json canonical payload serialization.
    """
    proof = vc_obj.get("proof")
    if not isinstance(proof, dict):
        return False

    raw_sig_hex = proof.get("proofValue") or proof.get("signatureValue")
    if not raw_sig_hex or not isinstance(raw_sig_hex, str):
        return False

    pub_bytes = _pubkey_from_did_key(issuer_did)
    if not pub_bytes:
        return False

    try:
        sig_bytes = bytes.fromhex(raw_sig_hex)
        if len(sig_bytes) != 64:
            return False

        payload = {k: v for k, v in vc_obj.items() if k != "proof"}
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, payload_bytes)
        return True
    except Exception:
        return False


def verify_signature_with_did_rust(vc_obj: dict[str, Any]) -> bool:
    """
    Verify signature against issuer DID using did_rust bridge (with pure Python fallback).
    """
    issuer_did = vc_obj.get("issuer")
    if not issuer_did or not isinstance(issuer_did, str):
        raise CredentialValidationError("Credential is missing required 'issuer' DID.")

    rust_verify_vc, _ = _get_rust_verify_vc()
    if rust_verify_vc is not None:
        try:
            vc_json_str = json.dumps(vc_obj, separators=(",", ":"))
            res_str = rust_verify_vc(vc_json_str)
            res = json.loads(res_str)
            if res.get("valid", False):
                return True
            error_msg = res.get("error", "Signature verification failed")
            raise CredentialValidationError(f"Invalid parent DID signature: {error_msg}")
        except CredentialValidationError:
            raise
        except Exception as e:
            logger.warning("Rust verify_vc bridge encountered error, trying fallback: %s", e)

    # Python verification fallback
    if _verify_vc_signature_python(vc_obj, issuer_did):
        return True

    raise CredentialValidationError("Invalid parent DID signature: VC Signature Failure")


def validate_age_bracket_credential(payload: dict[str, Any] | str) -> dict[str, Any]:
    """
    Validate an Age-Bracket Verifiable Credential against W3C structure,
    zero-PII invariants, and parent DID cryptographic signature.

    Directives:
    1. Validate W3C payload structure (assert type contains AgeBracketCredential).
    2. Reject any payload containing cleartext PII fields (birth_date, dob, full_name).
    3. Verify signature against issuer DID using did_rust.
    4. Map ageBracket string to session permission tiers.

    Returns:
        dict: Validated credential details including parsed subject, issuer,
              ageBracket, and session permission tier.

    Raises:
        CredentialValidationError: If any validation rule fails.
    """
    if isinstance(payload, str):
        try:
            vc_obj = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise CredentialValidationError(f"Invalid JSON payload: {exc}") from exc
    elif isinstance(payload, dict):
        vc_obj = payload
    else:
        raise CredentialValidationError(f"Expected dict or JSON string payload, got {type(payload).__name__}")

    # 1. Reject any cleartext PII fields anywhere in the payload
    detected_pii = _find_pii_fields(vc_obj)
    if detected_pii:
        raise CredentialValidationError(
            f"Zero-PII violation: cleartext PII field(s) detected in credential payload: {detected_pii}"
        )

    # 2. Validate W3C payload structure: @context
    context = vc_obj.get("@context")
    if not context:
        raise CredentialValidationError("Credential is missing '@context'.")
    if isinstance(context, str):
        context = [context]
    if not isinstance(context, list):
        raise CredentialValidationError("'@context' must be a list or string.")
    if W3C_CREDENTIALS_CONTEXT_URI not in context:
        raise CredentialValidationError(
            f"'@context' must contain W3C credentials context '{W3C_CREDENTIALS_CONTEXT_URI}'."
        )
    if AGE_BRACKET_CONTEXT_URI not in context:
        raise CredentialValidationError(
            f"'@context' must contain Age-Bracket schema context '{AGE_BRACKET_CONTEXT_URI}'."
        )

    # 3. Validate W3C payload structure: type
    types = vc_obj.get("type")
    if not types:
        raise CredentialValidationError("Credential is missing 'type'.")
    if isinstance(types, str):
        types = [types]
    if not isinstance(types, list):
        raise CredentialValidationError("'type' must be a list or string.")
    if AGE_BRACKET_CREDENTIAL_TYPE not in types:
        raise CredentialValidationError(
            f"Credential type must contain '{AGE_BRACKET_CREDENTIAL_TYPE}'."
        )

    # 4. Validate credentialSubject
    subject = vc_obj.get("credentialSubject")
    if not isinstance(subject, dict):
        raise CredentialValidationError("Missing or invalid 'credentialSubject' object.")

    subject_id = subject.get("id")
    if not subject_id or not isinstance(subject_id, str):
        raise CredentialValidationError("credentialSubject is missing valid 'id' DID.")

    age_bracket = subject.get("ageBracket")
    if not age_bracket or not isinstance(age_bracket, str):
        raise CredentialValidationError("credentialSubject is missing required 'ageBracket'.")

    # 5. Map ageBracket to session permission tier
    permission_tier = get_session_permission_tier(age_bracket)

    # 6. Verify cryptographic signature against issuer DID using did_rust
    verify_signature_with_did_rust(vc_obj)

    issuer_did = vc_obj.get("issuer")
    return {
        "valid": True,
        "issuer": issuer_did,
        "subject_id": subject_id,
        "age_bracket": age_bracket,
        "permission_tier": permission_tier,
        "credential": vc_obj,
    }
