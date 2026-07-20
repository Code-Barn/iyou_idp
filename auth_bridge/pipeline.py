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
from django.contrib.auth import get_user_model

from .models import FederatedIdentity

User = get_user_model()

logger = logging.getLogger(__name__)


def process_oauth_identity(provider_name: str, provider_uid: str, verified_email: str):
    """
    Handles inbound OAuth profile matching with email anti-collision
    and security password verification walls.

    Three-way resolution:
    1. Existing social link → direct login (identity already federated)
    2. Email match with existing account → require password verification
       if account has a usable password (prevents account takeover)
    3. No match → create new user with custodial DID

    Returns dict with:
        - action: "login" | "require_password_verification"
        - user: User instance (on login)
        - user_id, email, pending_provider, pending_uid (on require_password_verification)
    """
    fed_identity = FederatedIdentity.objects.filter(
        provider=provider_name,
        provider_user_id=provider_uid,
    ).first()

    if fed_identity:
        logger.info(
            "OAUTH MATCH: existing federated identity for %s provider=%s uid=%s",
            fed_identity.user.email, provider_name, provider_uid,
        )
        return {"action": "login", "user": fed_identity.user}

    existing_user = User.objects.filter(email=verified_email).first()

    if existing_user:
        if existing_user.has_usable_password():
            logger.info(
                "OAUTH GUARDRAIL: password verification required for %s provider=%s",
                verified_email, provider_name,
            )
            return {
                "action": "require_password_verification",
                "user_id": str(existing_user.id),
                "email": existing_user.email,
                "pending_provider": provider_name,
                "pending_uid": provider_uid,
            }

        FederatedIdentity.objects.create(
            user=existing_user,
            provider=provider_name,
            provider_user_id=provider_uid,
        )
        logger.info(
            "OAUTH AUTO-LINK: linked %s to %s (no usable password)",
            provider_name, verified_email,
        )
        return {"action": "login", "user": existing_user}

    new_user = User.objects.create_user(email=verified_email)
    FederatedIdentity.objects.create(
        user=new_user,
        provider=provider_name,
        provider_user_id=provider_uid,
    )
    logger.info(
        "OAUTH NEW USER: created %s with %s federated identity",
        verified_email, provider_name,
    )
    return {"action": "login", "user": new_user}


def confirm_password_and_link(user_id: str, password: str, provider_name: str, provider_uid: str):
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
