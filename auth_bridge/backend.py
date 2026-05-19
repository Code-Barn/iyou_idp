# Copyright (C) 2026 Byers Brands, LLC
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
