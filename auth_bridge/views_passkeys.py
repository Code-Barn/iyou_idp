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
Passwordless WebAuthn/passkey ceremony endpoints.

Managed-tier identities authenticate with a passkey as their primary
factor; standard Django password authentication is never consulted on this
path.
"""

import json
import logging
import uuid
from typing import Any

from django.contrib.auth import login
from django.db import IntegrityError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from fido2.utils import websafe_encode

from .backend import evaluate_sovereign_admin_posture
from .models import PasskeyCredential, User
from .passkeys import (
    AttestedCredentialData,
    begin_authentication,
    begin_registration,
    complete_authentication,
    complete_registration,
    extract_assertion_counter,
    extract_raw_credential_id,
    extract_user_handle,
    rebuild_attested_credential,
)
from .views import cache

logger = logging.getLogger(__name__)

CEREMONY_TTL_SECONDS = 300


def _ceremony_key(kind: str, ceremony_id: str) -> str:
    return f"passkey:{kind}:{ceremony_id}"


def _store_ceremony(kind: str, payload: dict[str, Any]) -> str:
    ceremony_id = uuid.uuid4().hex
    cache.set(_ceremony_key(kind, ceremony_id), payload, timeout=CEREMONY_TTL_SECONDS)
    return ceremony_id


def _load_ceremony(kind: str, ceremony_id: Any) -> dict[str, Any] | None:
    if not isinstance(ceremony_id, str):
        return None
    return cache.get(_ceremony_key(kind, ceremony_id))


def _destroy_ceremony(kind: str, ceremony_id: str) -> None:
    cache.delete(_ceremony_key(kind, ceremony_id))


def _existing_attested_credentials(user: User) -> list[AttestedCredentialData]:
    rows = user.passkeys.all()
    return [
        rebuild_attested_credential(
            bytes(row.credential_id), bytes(row.public_key_cose), row.sign_count
        )
        for row in rows
    ]


@csrf_exempt
@require_POST
def passkey_register_begin(request: HttpRequest) -> HttpResponse:
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication_required"}, status=401)

    options, state = begin_registration(
        request.user, _existing_attested_credentials(request.user)
    )
    ceremony_id = _store_ceremony("reg", {"state": state, "user_id": str(request.user.id)})
    logger.info(
        "PASSKEY REG BEGIN: did=%s ceremony=%s", request.user.custodial_did, ceremony_id
    )
    return JsonResponse({"ceremony_id": ceremony_id, **options})


@csrf_exempt
@require_POST
def passkey_register_complete(request: HttpRequest) -> HttpResponse:
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication_required"}, status=401)

    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "malformed_json"}, status=400)

    ceremony_id = payload.pop("ceremony_id", None)
    stored = _load_ceremony("reg", ceremony_id)
    if stored is None:
        return JsonResponse({"error": "unknown_or_expired_ceremony"}, status=400)
    if stored.get("user_id") != str(request.user.id):
        return JsonResponse({"error": "ceremony_user_mismatch"}, status=400)

    try:
        credential_id, cose_public_key, sign_count = complete_registration(
            stored["state"], payload
        )
    except Exception as exc:
        logger.warning("PASSKEY REG FAILED: %s", exc)
        return JsonResponse({"error": "invalid_attestation"}, status=400)

    try:
        row = PasskeyCredential.objects.create(
            user=request.user,
            credential_id=credential_id,
            public_key_cose=cose_public_key,
            sign_count=sign_count,
            transports=payload.get("response", {}).get("transports") or [],
        )
    except IntegrityError:
        return JsonResponse({"error": "credential_already_registered"}, status=409)

    _destroy_ceremony("reg", ceremony_id)
    logger.info(
        "PASSKEY REGISTERED: did=%s credential=%s",
        request.user.custodial_did,
        bytes(credential_id).hex()[:16],
    )
    return JsonResponse({
        "status": "registered",
        "credential_id": websafe_encode(bytes(row.credential_id)),
    })


@csrf_exempt
@require_POST
def passkey_authenticate_begin(request: HttpRequest) -> HttpResponse:
    options, state = begin_authentication(None)
    ceremony_id = _store_ceremony("auth", {"state": state})
    return JsonResponse({"ceremony_id": ceremony_id, **options})


@csrf_exempt
@require_POST
def passkey_authenticate_complete(request: HttpRequest) -> HttpResponse:
    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "malformed_json"}, status=400)

    ceremony_id = payload.pop("ceremony_id", None)
    stored = _load_ceremony("auth", ceremony_id)
    if stored is None:
        return JsonResponse({"error": "unknown_or_expired_ceremony"}, status=400)

    try:
        raw_credential_id = extract_raw_credential_id(payload)
    except Exception:
        return JsonResponse({"error": "invalid_assertion"}, status=400)

    try:
        row = PasskeyCredential.objects.get(credential_id=raw_credential_id)
    except PasskeyCredential.DoesNotExist:
        return JsonResponse({"error": "unknown_credential"}, status=400)
    if not row.user.is_active:
        return JsonResponse({"error": "account_disabled"}, status=403)

    known_credentials = [
        rebuild_attested_credential(
            bytes(row.credential_id), bytes(row.public_key_cose), row.sign_count
        )
    ]
    try:
        complete_authentication(stored["state"], known_credentials, payload)
    except Exception as exc:
        logger.warning("PASSKEY ASSERTION FAILED: credential=%s err=%s", raw_credential_id.hex()[:16], exc)
        return JsonResponse({"error": "invalid_assertion"}, status=400)

    new_count = extract_assertion_counter(payload)
    if new_count != 0 and row.sign_count != 0 and new_count <= row.sign_count:
        logger.warning(
            "PASSKEY CLONE SUSPECTED: credential=%s stored=%d received=%d",
            raw_credential_id.hex()[:16],
            row.sign_count,
            new_count,
        )
        return JsonResponse({"error": "cloned_credential_detected"}, status=400)

    user_handle = extract_user_handle(payload)
    if user_handle is not None and user_handle != row.user.id.bytes:
        return JsonResponse({"error": "user_handle_mismatch"}, status=400)

    row.sign_count = max(new_count, 0)
    row.last_used_at = timezone.now()
    row.save(update_fields=["sign_count", "last_used_at"])
    _destroy_ceremony("auth", ceremony_id)

    user = evaluate_sovereign_admin_posture(row.user)
    login(request, user, backend="auth_bridge.backend.DIDAuthBackend")
    logger.info("PASSKEY LOGIN: did=%s via passkey", user.custodial_did)
    return JsonResponse({"status": "authenticated", "did": user.custodial_did})
