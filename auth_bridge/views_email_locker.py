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

import hashlib
import hmac
import json
import logging
import secrets
import uuid
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.core.validators import ValidationError, validate_email
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
import jwt
from oidc_provider.models import RSAKey

from .models import LinkedEmail
from .resilient_cache import cache

User = get_user_model()
logger = logging.getLogger(__name__)

VALID_LABELS = {"personal", "work", "alias"}


def issue_email_ownership_credential(user: Any, email: str, label: str) -> dict[str, Any]:
    now = timezone.now()
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    vc_payload: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://iyou.me/credentials/email-ownership/v1",
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", "EmailOwnershipCredential"],
        "issuer": "did:web:iyou.me",
        "issuanceDate": now.isoformat(),
        "credentialSubject": {
            "id": user.custodial_did,
            "email": email,
            "label": label,
            "verified_at": now.isoformat(),
        },
    }

    rsa_key = RSAKey.objects.first()
    if rsa_key:
        jwt_claims = {
            "sub": user.custodial_did,
            "iss": "did:web:iyou.me",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "vc": vc_payload,
        }
        signed_jws = jwt.encode(jwt_claims, rsa_key.key, algorithm="RS256")
        vc_payload["proof"] = {
            "type": "RsaSignature2018",
            "created": now.isoformat(),
            "verificationMethod": "did:web:iyou.me#keys-1",
            "proofPurpose": "assertionMethod",
            "jws": signed_jws,
        }
    else:
        canonical = json.dumps(vc_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig = hmac.new(settings.SECRET_KEY.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        vc_payload["proof"] = {
            "type": "HmacSha256Signature2020",
            "created": now.isoformat(),
            "verificationMethod": "did:web:iyou.me#keys-hmac",
            "proofPurpose": "assertionMethod",
            "proofValue": sig,
        }

    return vc_payload


@method_decorator(csrf_exempt, name="dispatch")
class ChallengeLinkEmailView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else request.POST.dict()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "invalid_payload", "error_description": "Invalid JSON payload."}, status=400)

        raw_email = data.get("email", "")
        if not raw_email or not isinstance(raw_email, str):
            return JsonResponse({"error": "missing_email", "error_description": "Email address is required."}, status=400)

        email = raw_email.strip().lower()
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({"error": "invalid_email", "error_description": "Invalid email address format."}, status=400)

        raw_label = data.get("label", "personal")
        label = raw_label.strip().lower() if isinstance(raw_label, str) else "personal"
        if label not in VALID_LABELS:
            label = "personal"

        if User.objects.filter(email=email).exists() or LinkedEmail.objects.filter(email=email).exists():
            return JsonResponse({"error": "email_already_claimed"}, status=409)

        otp = "".join(secrets.choice("0123456789") for _ in range(6))
        cache_payload = {
            "user_id": str(request.user.id),
            "otp": otp,
            "label": label,
        }
        cache.set(f"email_link_otp:{email}", json.dumps(cache_payload), timeout=300)

        subject = f"Your iYou email link verification code: {otp}"
        message = (
            f"Your verification code to link {email} to your iYou identity is: {otp}\n\n"
            f"This code will expire in 5 minutes.\n"
        )
        html_message = (
            f"<div style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;'>"
            f"<h2 style='color: #111827; margin-bottom: 16px;'>iYou Email Locker</h2>"
            f"<p style='color: #4b5563; font-size: 15px;'>Your verification code to link <strong>{email}</strong> is:</p>"
            f"<div style='background: #f3f4f6; border-radius: 8px; padding: 16px; text-align: center; margin: 24px 0;'>"
            f"<span style='font-size: 32px; font-weight: 700; letter-spacing: 6px; font-family: monospace; color: #4f46e5;'>{otp}</span>"
            f"</div>"
            f"<p style='color: #6b7280; font-size: 13px;'>This code will expire in 5 minutes.</p>"
            f"</div>"
        )
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@iyou.me")

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=[email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception:
            logger.exception("Failed to dispatch link email OTP to %s", email)

        logger.info("EMAIL LINK OTP DISPATCHED: email=%s user=%s", email, request.user.custodial_did)
        return JsonResponse({"success": True, "message": "Verification code dispatched."})


@method_decorator(csrf_exempt, name="dispatch")
class VerifyLinkEmailView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else request.POST.dict()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "invalid_payload", "error_description": "Invalid JSON payload."}, status=400)

        email = data.get("email", "").strip().lower() if isinstance(data.get("email"), str) else ""
        otp = data.get("otp", "").strip() if isinstance(data.get("otp"), str) else ""

        if not email or not otp:
            return JsonResponse({"error": "missing_parameters", "error_description": "Email and OTP are required."}, status=400)

        cached_raw = cache.get(f"email_link_otp:{email}")
        if not cached_raw:
            return JsonResponse({"error": "expired_or_invalid_otp", "error_description": "Verification code expired or not found."}, status=400)

        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw

        cached_user_id = str(cached.get("user_id", ""))
        if cached_user_id != str(request.user.id):
            return JsonResponse({"error": "user_mismatch", "error_description": "Verification code does not belong to current session."}, status=403)

        expected_otp = str(cached.get("otp", ""))
        if not hmac.compare_digest(otp, expected_otp):
            return JsonResponse({"error": "invalid_otp", "error_description": "Invalid verification code."}, status=400)

        cache.delete(f"email_link_otp:{email}")
        label = cached.get("label", "personal")

        if User.objects.filter(email=email).exists() or LinkedEmail.objects.filter(email=email).exists():
            return JsonResponse({"error": "email_already_claimed"}, status=409)

        linked_email, created = LinkedEmail.objects.get_or_create(
            email=email,
            defaults={"user": request.user, "label": label},
        )
        if not created and str(linked_email.user_id) != str(request.user.id):
            return JsonResponse({"error": "email_already_claimed"}, status=409)

        vc = issue_email_ownership_credential(request.user, email, label)
        logger.info("EMAIL LINK VERIFIED: email=%s linked to user=%s", email, request.user.custodial_did)

        return JsonResponse({
            "success": True,
            "email": email,
            "label": label,
            "vc": vc,
        })


@method_decorator(csrf_exempt, name="dispatch")
class ListLinkedEmailsView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        linked_emails = LinkedEmail.objects.filter(user=request.user).order_by("-verified_at")
        results = [
            {
                "id": str(item.id),
                "email": item.email,
                "label": item.label,
                "verified_at": item.verified_at.isoformat(),
                "is_public": item.is_public,
            }
            for item in linked_emails
        ]
        return JsonResponse({
            "success": True,
            "primary_email": request.user.email,
            "linked_emails": results,
        })


@method_decorator(csrf_exempt, name="dispatch")
class RemoveLinkedEmailView(View):
    def delete(self, request: HttpRequest, id: uuid.UUID) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        linked_email = LinkedEmail.objects.filter(id=id, user=request.user).first()
        if not linked_email:
            return JsonResponse({"error": "not_found", "error_description": "Linked email not found."}, status=404)

        email = linked_email.email
        linked_email.delete()
        logger.info("EMAIL LINK REMOVED: email=%s unlinked from user=%s", email, request.user.custodial_did)
        return JsonResponse({"success": True, "message": "Linked email removed."})
