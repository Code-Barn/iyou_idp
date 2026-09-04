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
Token Payload Injection & Dependent Identity Claims (DEP-104).

Wires the W3C AgeBracketCredential verification pipeline into the OIDC token
generation flow. Injects the standardized `dep.*` namespace into the JWT payload
for authenticated dependent sessions while enforcing zero-PII and parent revocation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from django.conf import settings
from django.utils import timezone
from oidc_provider.lib.errors import TokenError, UserAuthError

from auth_bridge.credentials import (
    CredentialValidationError,
    validate_age_bracket_vc,
)
from auth_bridge.views import cache

logger = logging.getLogger(__name__)

# In-memory stores for runtime fast lookups
_DEPENDENT_REGISTRY: dict[str, dict[str, Any]] = {}
_REVOCATION_REGISTRY: set[str] = set()


class DependentSessionRevokedError(UserAuthError, CredentialValidationError):
    """Raised when a dependent credential has been revoked by parent authority."""

    error = "DependentSessionRevoked"

    def __init__(self, description: str = "Dependent session has been revoked by parent guardian."):
        self.description = description
        CredentialValidationError.__init__(self, description)


class ExpiredCredentialError(TokenError, CredentialValidationError):
    """Raised when an age-bracket verifiable credential has expired."""

    def __init__(self, description: str = "Dependent credential has expired."):
        TokenError.__init__(self, "invalid_grant")
        self.description = description
        CredentialValidationError.__init__(self, description)


def register_dependent_vector(
    child_did: str,
    parent_did: str,
    attestation_vc: Any,
    bracket: str = "U14",
    wot_distance: int = 1,
    issued_at: int | None = None,
    expires_at: int | None = None,
    revoked: bool = False,
) -> Any:
    """
    Register a dependent identity vector for child DID.
    Persists to IssuedCredential model and populates runtime lookup cache.
    """
    vector_data = {
        "child_did": child_did,
        "parent_did": parent_did,
        "attestation_vc": attestation_vc,
        "bracket": bracket,
        "wot_distance": wot_distance,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked": revoked,
    }
    _DEPENDENT_REGISTRY[child_did] = vector_data

    try:
        from auth_bridge.models import IssuedCredential

        if isinstance(attestation_vc, (dict, list)):
            vc_payload = attestation_vc
        elif isinstance(attestation_vc, str) and attestation_vc.strip().startswith("{"):
            try:
                vc_payload = json.loads(attestation_vc)
            except Exception:
                vc_payload = {"raw": attestation_vc}
        else:
            vc_payload = {"raw": attestation_vc}

        cred, _ = IssuedCredential.objects.update_or_create(
            subject_did=child_did,
            defaults={
                "issuer_did": parent_did,
                "bracket": bracket,
                "wot_distance": wot_distance,
                "raw_vc": vc_payload,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "revoked": revoked,
                "revoked_at": timezone.now() if revoked else None,
            },
        )
        return cred
    except Exception as exc:
        logger.warning("Could not persist IssuedCredential to DB (%s); cached in-memory", exc)
        return vector_data


def record_revocation_ticket(ticket: dict | str) -> str | None:
    """
    Record a signed kind:9112 Nostr RevocationTicket issued by the parent enclave.
    Invalidates any matching IssuedCredential and terminates dependent sessions.
    """
    if isinstance(ticket, str):
        try:
            ticket = json.loads(ticket)
        except Exception:
            return None
    if not isinstance(ticket, dict):
        return None

    target_did = None
    tags = ticket.get("tags", [])
    for tag in tags:
        if isinstance(tag, (list, tuple)) and len(tag) >= 2:
            if tag[0] in ("p", "subject", "did", "child_did"):
                target_did = str(tag[1]).strip()
                break

    if not target_did:
        content_raw = ticket.get("content")
        if isinstance(content_raw, str) and content_raw.strip().startswith("{"):
            try:
                content_dict = json.loads(content_raw)
                target_did = (
                    content_dict.get("subject")
                    or content_dict.get("did")
                    or content_dict.get("child_did")
                )
            except Exception:
                pass
        elif isinstance(content_raw, dict):
            target_did = (
                content_raw.get("subject")
                or content_raw.get("did")
                or content_raw.get("child_did")
            )

    if not target_did:
        target_did = ticket.get("subject") or ticket.get("child_did")

    if target_did:
        _REVOCATION_REGISTRY.add(target_did)
        cache.set(f"revocation_ticket:{target_did}", json.dumps(ticket), timeout=86400 * 30)

        try:
            from auth_bridge.models import IssuedCredential

            IssuedCredential.objects.filter(subject_did=target_did).update(
                revoked=True,
                revoked_at=timezone.now(),
                revocation_ticket=ticket,
            )
        except Exception as exc:
            logger.warning("Could not update IssuedCredential revocation for %s: %s", target_did, exc)

        if target_did in _DEPENDENT_REGISTRY:
            _DEPENDENT_REGISTRY[target_did]["revoked"] = True

        return target_did

    return None


def is_credential_revoked(did: str) -> bool:
    """
    Check if a DID's credential has been revoked against IssuedCredential or kind:9112 tickets.
    """
    if not did:
        return False
    if did in _REVOCATION_REGISTRY:
        return True

    cached = cache.get(f"revocation_ticket:{did}")
    if cached is not None:
        return True

    vector = _DEPENDENT_REGISTRY.get(did)
    if vector and vector.get("revoked") is True:
        return True

    try:
        from auth_bridge.models import IssuedCredential

        if IssuedCredential.objects.filter(subject_did=did, revoked=True).exists():
            return True
    except Exception:
        pass

    return False


def get_dependent_vector_for_did(did: str):
    """Retrieve the registered dependent vector or IssuedCredential for a child DID."""
    if not did:
        return None
    try:
        from auth_bridge.models import IssuedCredential

        cred = IssuedCredential.objects.filter(subject_did=did).order_by("-created_at").first()
        if cred:
            return cred
    except Exception:
        pass
    return _DEPENDENT_REGISTRY.get(did)


def is_dependent_user(did: str) -> bool:
    """Determine whether the specified DID represents a registered dependent identity."""
    return get_dependent_vector_for_did(did) is not None


def inject_dependent_claims(
    id_token: dict[str, Any],
    user: Any,
    token: Any = None,
    request: Any = None,
) -> dict[str, Any]:
    """
    Inject the standardized `dep.*` namespace into the decoded id_token JWT payload.

    Directives:
    1. Check if user DID matches a registered dependent vector or submits a valid attestation_vc.
    2. Check revocation against IssuedCredential / kind:9112 RevocationTickets.
    3. Run credentials.validate_age_bracket_vc(attestation_vc) against did_rust verification engine.
    4. Extract bracket ("U14", "U14-U18", or "U18"), wot_distance = 1, parent_did from issuer.
    5. Inject the dep dictionary into id_token.
    """
    user_did = getattr(user, "custodial_did", None) or id_token.get("sub", "")
    if not user_did:
        return id_token

    # 1. Determine if this session is a dependent session
    dep_vector = get_dependent_vector_for_did(user_did)
    attestation_vc = None

    if request is not None:
        if hasattr(request, "session"):
            attestation_vc = request.session.get("attestation_vc")
        if not attestation_vc and hasattr(request, "POST"):
            attestation_vc = request.POST.get("attestation_vc")
        if not attestation_vc and hasattr(request, "META"):
            attestation_vc = request.META.get("HTTP_X_ATTESTATION_VC")

    if not attestation_vc and hasattr(user, "attestation_vc"):
        attestation_vc = getattr(user, "attestation_vc")

    if not attestation_vc and dep_vector:
        if hasattr(dep_vector, "raw_vc"):
            raw_vc_val = dep_vector.raw_vc
            attestation_vc = raw_vc_val.get("raw") if isinstance(raw_vc_val, dict) and "raw" in raw_vc_val else raw_vc_val
        elif isinstance(dep_vector, dict):
            attestation_vc = dep_vector.get("attestation_vc")

    if not attestation_vc and not dep_vector:
        # Not a dependent session
        return id_token

    # 2. Check revocation state
    is_revoked = is_credential_revoked(user_did)
    if hasattr(dep_vector, "revoked") and dep_vector.revoked:
        is_revoked = True
    elif isinstance(dep_vector, dict) and dep_vector.get("revoked"):
        is_revoked = True

    if is_revoked:
        raise DependentSessionRevokedError(
            f"Dependent session revoked: Credential for '{user_did}' has been revoked by parent authority."
        )

    # 3. Validate VC against parent DID verification engine
    try:
        val_result = validate_age_bracket_vc(attestation_vc)
    except CredentialValidationError as exc:
        err_str = str(exc).lower()
        if "revok" in err_str:
            raise DependentSessionRevokedError(str(exc)) from exc
        elif "expir" in err_str:
            raise ExpiredCredentialError(str(exc)) from exc
        else:
            token_err = TokenError("invalid_grant")
            token_err.description = str(exc)
            raise token_err from exc

    # 4. Extract verified claim fields
    bracket = val_result["bracket"]
    wot_distance = 1
    parent_did = val_result["parent_did"]
    issued_at = val_result["issued_at"]
    expires_at = val_result["expires_at"]

    # Raw VC payload preservation
    raw_vc = val_result.get("raw_payload") or attestation_vc

    # 5. Inject dep dictionary into JWT payload
    id_token["sub"] = user_did
    if "iss" not in id_token or not id_token["iss"]:
        id_token["iss"] = getattr(settings, "IDP_BASE_URL", "https://iyou.me")

    id_token["dep"] = {
        "bracket": bracket,
        "wot_distance": wot_distance,
        "parent_did": parent_did,
        "attestation_vc": raw_vc,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked": False,
    }

    if request is not None and hasattr(request, "session"):
        request.session["dep"] = id_token["dep"]

    return id_token
