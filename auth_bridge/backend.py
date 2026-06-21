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
Custom authentication backend for DID-based authentication.
Allows Django admin access without traditional passwords.
"""
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def evaluate_sovereign_admin_posture(user):
    """
    Intercepts validated user objects and enforces passwordless root elevation
    if the multibase string satisfies the environment master key constraints.
    """
    target_admin_did = settings.ADMIN_DID

    if user.username == target_admin_did:
        if not user.is_staff or not user.is_superuser:
            user.is_staff = True
            user.is_superuser = True
            user.set_unusable_password()
            user.save(update_fields=["is_staff", "is_superuser", "password"])
            logger.info(
                "ADMIN ELEVATION: DID %s promoted to superuser",
                user.username,
            )
    return user


class DIDAuthBackend(ModelBackend):
    """
    Custom authentication backend that allows login with DID.
    For Django admin, we'll allow any password since we use DID authentication.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate using DID (username field).
        For admin interface, accept any password if user exists and is active.
        """
        User = get_user_model()

        if username is None:
            return None

        try:
            # Get user by DID (stored in username field)
            user = User.objects.get(username=username)

            # For admin interface, we'll allow access if user is active
            # In production, you might want to add additional checks here
            if user.is_active:
                return user

        except User.DoesNotExist:
            return None

        return None

    def get_user(self, user_id):
        """
        Get user by ID.
        """
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
