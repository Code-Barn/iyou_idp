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
import re
import secrets
import uuid
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.core.validators import ValidationError, validate_email
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
import jwt
from oidc_provider.models import RSAKey

from .models import FederatedIdentity, LinkedEmail
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

        target_user = User.objects.filter(email=email).first()
        if target_user is not None:
            if target_user != request.user and target_user.is_active:
                if target_user.is_sovereign or target_user.account_tier == "sovereign":
                    return JsonResponse(
                        {
                            "error": "cannot_merge_sovereign_account",
                            "message": "Sovereign accounts cannot be merged via the web tier.",
                        },
                        status=403,
                    )

                otp = "".join(secrets.choice("0123456789") for _ in range(6))
                merge_payload = {
                    "source_user_id": str(target_user.id),
                    "dest_user_id": str(request.user.id),
                    "otp": otp,
                }
                cache.set(f"account_merge_otp:{email}", json.dumps(merge_payload), timeout=300)

                subject = f"Your iyou account consolidation code: {otp}"
                message = (
                    f"Your verification code to consolidate {email} into your active iyou session "
                    f"({request.user.email or request.user.custodial_did}) is: {otp}\n\n"
                    f"Confirming this code will transfer all linked OAuth logins and emails from {email} "
                    f"into your active identity and assign {email} as an alias.\n\n"
                    f"This code will expire in 5 minutes.\n\n"
                    f"— The iyou Identity Team\n"
                )
                html_message = (
                    f"<div style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;'>"
                    f"<h2 style='color: #111827; margin-bottom: 16px;'>iyou Account Consolidation</h2>"
                    f"<p style='color: #4b5563; font-size: 15px;'>Your verification code to consolidate <strong>{email}</strong> into your active session is:</p>"
                    f"<div style='background: #f3f4f6; border-radius: 8px; padding: 16px; text-align: center; margin: 24px 0;'>"
                    f"<span style='font-size: 32px; font-weight: 700; letter-spacing: 6px; font-family: monospace; color: #4f46e5;'>{otp}</span>"
                    f"</div>"
                    f"<p style='color: #6b7280; font-size: 13px;'>Confirming this code will consolidate this account into your active iyou session and transfer all linked logins.</p>"
                    f"<p style='color: #6b7280; font-size: 13px;'>This code will expire in 5 minutes.</p>"
                    f"<hr style='border: none; border-top: 1px solid #e5e7eb; margin: 24px 0 16px;'>"
                    f"<p style='color: #6b7280; font-size: 13px; margin: 0;'>— The iyou Identity Team</p>"
                    f"</div>"
                )
                from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "info@iyou.me")
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
                    logger.exception("Failed to dispatch account consolidation OTP to %s", email)

                logger.info(
                    "ACCOUNT MERGE OTP DISPATCHED: source_email=%s source_user=%s dest_user=%s",
                    email,
                    target_user.id,
                    request.user.id,
                )
                return JsonResponse(
                    {
                        "success": True,
                        "action": "merge_confirmation_required",
                        "message": "Account consolidation code dispatched to existing account.",
                    }
                )

            return JsonResponse({"error": "email_already_claimed"}, status=409)

        if LinkedEmail.objects.filter(email=email).exists():
            return JsonResponse({"error": "email_already_claimed"}, status=409)

        otp = "".join(secrets.choice("0123456789") for _ in range(6))
        cache_payload = {
            "user_id": str(request.user.id),
            "otp": otp,
            "label": label,
        }
        cache.set(f"email_link_otp:{email}", json.dumps(cache_payload), timeout=300)

        subject = f"Your iyou email link verification code: {otp}"
        message = (
            f"Your verification code to link {email} to your iyou identity is: {otp}\n\n"
            f"This code will expire in 5 minutes.\n\n"
            f"— The iyou Identity Team\n"
        )
        html_message = (
            f"<div style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;'>"
            f"<h2 style='color: #111827; margin-bottom: 16px;'>iyou Email Locker</h2>"
            f"<p style='color: #4b5563; font-size: 15px;'>Your verification code to link <strong>{email}</strong> is:</p>"
            f"<div style='background: #f3f4f6; border-radius: 8px; padding: 16px; text-align: center; margin: 24px 0;'>"
            f"<span style='font-size: 32px; font-weight: 700; letter-spacing: 6px; font-family: monospace; color: #4f46e5;'>{otp}</span>"
            f"</div>"
            f"<p style='color: #6b7280; font-size: 13px;'>This code will expire in 5 minutes.</p>"
            f"<hr style='border: none; border-top: 1px solid #e5e7eb; margin: 24px 0 16px;'>"
            f"<p style='color: #6b7280; font-size: 13px; margin: 0;'>— The iyou Identity Team</p>"
            f"</div>"
        )
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "info@iyou.me")

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
class ConfirmAccountMergeView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else request.POST.dict()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "invalid_payload", "error_description": "Invalid JSON payload."}, status=400)

        email = data.get("email", "").strip().lower() if isinstance(data.get("email"), str) else ""
        raw_otp = data.get("otp", "")
        otp = re.sub(r"\D", "", str(raw_otp))
        raw_alias_label = data.get("alias_label", "alias")
        alias_label = raw_alias_label.strip() if isinstance(raw_alias_label, str) and raw_alias_label.strip() else "alias"
        alias_label = alias_label[:50]

        if not email or not otp:
            return JsonResponse({"error": "missing_parameters", "error_description": "Email and OTP are required."}, status=400)

        cached_raw = cache.get(f"account_merge_otp:{email}")
        if not cached_raw:
            return JsonResponse(
                {"error": "expired_or_invalid_otp", "error_description": "Consolidation code expired or not found."},
                status=400,
            )

        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw

        cached_dest_user_id = str(cached.get("dest_user_id", ""))
        if cached_dest_user_id != str(request.user.id):
            return JsonResponse(
                {"error": "user_mismatch", "error_description": "Consolidation code does not belong to current session."},
                status=403,
            )

        expected_otp = str(cached.get("otp", ""))
        if not hmac.compare_digest(otp, expected_otp):
            return JsonResponse(
                {"error": "invalid_otp", "error_description": "Invalid consolidation code."},
                status=400,
            )

        source_user_id = cached.get("source_user_id")
        source_user = User.objects.filter(id=source_user_id).first()
        if not source_user or source_user.id == request.user.id:
            return JsonResponse({"error": "source_user_not_found"}, status=404)

        if source_user.is_sovereign or source_user.account_tier == "sovereign":
            return JsonResponse(
                {
                    "error": "cannot_merge_sovereign_account",
                    "message": "Sovereign accounts cannot be merged via the web tier.",
                },
                status=403,
            )

        source_email = source_user.email or email

        with transaction.atomic():
            # a. Transfer all FederatedIdentity rows from source_user to request.user
            FederatedIdentity.objects.filter(user=source_user).update(user=request.user)

            # b. Transfer all existing LinkedEmail rows from source_user to request.user (skip if duplicate)
            for linked in LinkedEmail.objects.filter(user=source_user):
                if linked.email.lower() == (request.user.email or "").lower():
                    linked.delete()
                    continue
                if LinkedEmail.objects.filter(user=request.user, email=linked.email).exists():
                    linked.delete()
                    continue
                linked.user = request.user
                linked.save(update_fields=["user"])

            # c. Create LinkedEmail(user=request.user, email=source_user.email, label=alias_label, is_public=False)
            absorbed_linked, _ = LinkedEmail.objects.update_or_create(
                email=source_email,
                defaults={
                    "user": request.user,
                    "label": alias_label,
                    "is_public": False,
                },
            )

            # d. Mark source_user.is_active = False, source_user.merged_into = request.user, and save
            source_user.is_active = False
            source_user.merged_into = request.user
            source_user.save(update_fields=["is_active", "merged_into", "updated_at"])

            # e. Invalidate active sessions for source_user in Redis / session store
            cache.delete(f"user_auth_method:{source_user.id}")
            try:
                for sess in Session.objects.filter(expire_date__gte=timezone.now()):
                    decoded = sess.get_decoded()
                    if str(decoded.get("_auth_user_id", "")) == str(source_user.id):
                        sess.delete()
            except Exception:
                logger.warning("Failed to scan session store during consolidation for user %s", source_user.id)

            # f. Mint and sign an EmailOwnershipCredential VC for the absorbed address using the IdP key
            vc = issue_email_ownership_credential(request.user, source_email, alias_label)

        cache.delete(f"account_merge_otp:{email}")
        logger.info(
            "ACCOUNT CONSOLIDATED: source_user=%s (%s) merged into dest_user=%s (%s) with label=%s",
            source_user.id,
            source_email,
            request.user.id,
            request.user.custodial_did,
            alias_label,
        )

        return JsonResponse(
            {
                "success": True,
                "message": "Account successfully consolidated.",
                "id": str(absorbed_linked.id),
                "email": source_email,
                "label": alias_label,
                "vc": vc,
            }
        )


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
        raw_otp = data.get("otp", "")
        otp = re.sub(r"\D", "", str(raw_otp))

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
    def get(self, request: HttpRequest, id: uuid.UUID) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        linked_email = LinkedEmail.objects.filter(id=id, user=request.user).first()
        if not linked_email:
            return JsonResponse({"error": "not_found", "error_description": "Linked email not found."}, status=404)

        vc = issue_email_ownership_credential(request.user, linked_email.email, linked_email.label)
        return JsonResponse({
            "success": True,
            "id": str(linked_email.id),
            "email": linked_email.email,
            "label": linked_email.label,
            "verified_at": linked_email.verified_at.isoformat(),
            "is_public": linked_email.is_public,
            "vc": vc,
        })

    def patch(self, request: HttpRequest, id: uuid.UUID) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        linked_email = LinkedEmail.objects.filter(id=id, user=request.user).first()
        if not linked_email:
            return JsonResponse({"error": "not_found", "error_description": "Linked email not found."}, status=404)

        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "invalid_payload"}, status=400)

        if "is_public" in data:
            linked_email.is_public = bool(data["is_public"])
            linked_email.save(update_fields=["is_public"])

        if "label" in data and data["label"] in VALID_LABELS:
            linked_email.label = data["label"]
            linked_email.save(update_fields=["label"])

        return JsonResponse({
            "success": True,
            "id": str(linked_email.id),
            "email": linked_email.email,
            "label": linked_email.label,
            "is_public": linked_email.is_public,
        })

    def post(self, request: HttpRequest, id: uuid.UUID) -> HttpResponse:
        return self.patch(request, id)

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


LinkedEmailDetailView = RemoveLinkedEmailView


@method_decorator(csrf_exempt, name="dispatch")
class ExportEmailCredentialView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        raw_email = request.GET.get("email")
        if not request.user.email:
            return JsonResponse({"error": "no_primary_email", "error_description": "No primary email claimed."}, status=404)
        if not raw_email or raw_email.strip().lower() == request.user.email.lower():
            target_email = request.user.email
            label = "primary"
        else:
            target_email = raw_email.strip().lower()
            linked = LinkedEmail.objects.filter(email=target_email, user=request.user).first()
            if not linked:
                return JsonResponse({"error": "not_found", "error_description": "Email not linked to account."}, status=404)
            label = linked.label

        vc = issue_email_ownership_credential(request.user, target_email, label)
        return JsonResponse({"success": True, "email": target_email, "label": label, "vc": vc})


@method_decorator(csrf_exempt, name="dispatch")
class ClaimPrimaryEmailChallengeView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)
        if request.user.email:
            return JsonResponse({"error": "primary_already_claimed"}, status=409)

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

        if User.objects.filter(email=email).exists() or LinkedEmail.objects.filter(email=email).exists():
            return JsonResponse({"error": "email_already_claimed"}, status=409)

        otp = "".join(secrets.choice("0123456789") for _ in range(6))
        cache.set(
            f"email_primary_otp:{email}",
            json.dumps({"user_id": str(request.user.id), "otp": otp}),
            timeout=300,
        )

        subject = f"Your iyou primary email verification code: {otp}"
        message = (
            f"Your verification code to claim {email} as your primary iyou email is: {otp}\n\n"
            f"This code will expire in 5 minutes.\n\n"
            f"— The iyou Identity Team\n"
        )
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "info@iyou.me")
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception:
            logger.exception("Failed to dispatch primary email claim OTP to %s", email)

        logger.info("PRIMARY EMAIL CLAIM OTP DISPATCHED: email=%s user=%s", email, request.user.custodial_did)
        return JsonResponse({"success": True, "action": "primary_claim_challenge_sent"})


@method_decorator(csrf_exempt, name="dispatch")
class VerifyPrimaryEmailView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication_required"}, status=401)

        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else request.POST.dict()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "invalid_payload", "error_description": "Invalid JSON payload."}, status=400)

        email = data.get("email", "").strip().lower() if isinstance(data.get("email"), str) else ""
        otp = re.sub(r"\D", "", str(data.get("otp", "")))
        if not email or len(otp) != 6:
            return JsonResponse(
                {"error": "missing_parameters", "error_description": "Email and a 6-digit OTP are required."},
                status=400,
            )

        cached_raw = cache.get(f"email_primary_otp:{email}")
        if not cached_raw:
            return JsonResponse(
                {"error": "expired_or_invalid_otp", "error_description": "Verification code expired or not found."},
                status=400,
            )

        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw
        if str(cached.get("user_id", "")) != str(request.user.id):
            return JsonResponse(
                {"error": "user_mismatch", "error_description": "Verification code does not belong to current session."},
                status=403,
            )

        if not hmac.compare_digest(otp, str(cached.get("otp", ""))):
            return JsonResponse({"error": "invalid_otp", "error_description": "Invalid verification code."}, status=400)

        cache.delete(f"email_primary_otp:{email}")

        try:
            with transaction.atomic():
                if User.objects.filter(email=email).exists() or LinkedEmail.objects.filter(email=email).exists():
                    return JsonResponse({"error": "email_already_claimed"}, status=409)
                request.user.email = email
                request.user.email_verified = True
                request.user.email_verified_at = timezone.now()
                request.user.save(update_fields=["email", "email_verified", "email_verified_at", "updated_at"])
        except IntegrityError:
            return JsonResponse({"error": "email_already_claimed"}, status=409)

        vc = issue_email_ownership_credential(request.user, email, "primary")
        logger.info("PRIMARY EMAIL CLAIMED: email=%s user=%s", email, request.user.custodial_did)
        return JsonResponse({"success": True, "email": email, "label": "primary", "vc": vc})
