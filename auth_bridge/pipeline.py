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
Smart-Merge OAuth Pipeline Controller

Handles inbound OAuth profile matching with email anti-collision
and security password verification walls. Prevents account splitting
and Sybil attacks by enforcing email-anchored identity resolution.
"""

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from .models import FederatedIdentity

User = get_user_model()

logger = logging.getLogger(__name__)


def process_oauth_identity(
    provider_name: str,
    provider_uid: str,
    email: str = "",
    email_verified: bool = False,
    claims: dict | None = None,
    request_user: Any = None,
    **kwargs: Any,
) -> dict:
    if not email and "verified_email" in kwargs:
        email = kwargs["verified_email"]

    if not email_verified:
        raise PermissionDenied("OAuth provider did not assert email verification.")

    email = email.strip().lower()
    if not email:
        raise ValueError("Missing email address for OAuth identity resolution.")

    fed_identity = FederatedIdentity.objects.filter(
        provider=provider_name,
        provider_user_id=provider_uid,
    ).first()

    if fed_identity:
        user = fed_identity.user
        if not user.email_verified:
            user.email_verified = True
            if not user.email_verified_at:
                user.email_verified_at = timezone.now()
            user.save(update_fields=["email_verified", "email_verified_at"])
        logger.info(
            "OAUTH MATCH: existing federated identity for %s provider=%s uid=%s",
            user.email,
            provider_name,
            provider_uid,
        )
        return {"action": "login", "user": user}

    existing_user = User.objects.filter(email=email).first()
    if not existing_user:
        from .models import LinkedEmail

        linked_entry = LinkedEmail.objects.filter(email=email).select_related("user").first()
        if linked_entry:
            existing_user = linked_entry.user
            logger.info(
                "OAUTH MATCH: resolved via LinkedEmail %s -> user %s",
                email,
                existing_user.email,
            )

    if existing_user:
        is_sovereign = bool(
            existing_user.is_sovereign or existing_user.account_tier == "sovereign"
        )
        if is_sovereign:
            is_authenticated = getattr(request_user, "is_authenticated", False)
            if not (is_authenticated and str(request_user.id) == str(existing_user.id)):
                logger.warning(
                    "OAUTH SOVEREIGN REJECT: attempted merge into sovereign account %s without cryptographic session",
                    existing_user.email,
                )
                raise PermissionDenied(
                    "Cannot link external OAuth provider to sovereign identity without cryptographic authorization."
                )

        if existing_user.has_usable_password():
            logger.info(
                "OAUTH GUARDRAIL: password verification required for %s provider=%s",
                email,
                provider_name,
            )
            return {
                "action": "require_password_verification",
                "user_id": str(existing_user.id),
                "email": existing_user.email,
                "pending_provider": provider_name,
                "pending_uid": provider_uid,
            }

        existing_user.set_unusable_password()
        if not existing_user.email_verified:
            existing_user.email_verified = True
            if not existing_user.email_verified_at:
                existing_user.email_verified_at = timezone.now()
        existing_user.save()

        FederatedIdentity.objects.get_or_create(
            user=existing_user,
            provider=provider_name,
            defaults={"provider_user_id": provider_uid},
        )
        logger.info(
            "OAUTH AUTO-LINK: linked %s to %s",
            provider_name,
            email,
        )
        return {"action": "login", "user": existing_user}

    new_user = User.objects.create_user(
        email=email,
        email_verified=True,
        email_verified_at=timezone.now(),
    )
    new_user.set_unusable_password()
    new_user.save()

    FederatedIdentity.objects.create(
        user=new_user,
        provider=provider_name,
        provider_user_id=provider_uid,
    )
    logger.info(
        "OAUTH NEW USER: created %s with %s federated identity",
        email,
        provider_name,
    )
    return {"action": "login", "user": new_user}


def confirm_password_and_link(
    user_id: str,
    password: str,
    provider_name: str,
    provider_uid: str,
) -> dict:
    """
    After require_password_verification, the user provides their password.
    This function validates it and completes the federation link.

    Returns dict with:
        - success: bool
        - user: User instance (on success)
        - error: str (on failure)
    """
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return {"success": False, "error": "User not found"}

    if not user.check_password(password):
        logger.warning(
            "OAUTH PASSWORD MISMATCH: failed verification for %s provider=%s",
            user.email, provider_name,
        )
        return {"success": False, "error": "Invalid password"}

    FederatedIdentity.objects.get_or_create(
        user=user,
        provider=provider_name,
        defaults={"provider_user_id": provider_uid},
    )
    logger.info(
        "OAUTH FEDERATION COMPLETE: linked %s to %s after password verification",
        user.email, provider_name,
    )
    return {"success": True, "user": user}
