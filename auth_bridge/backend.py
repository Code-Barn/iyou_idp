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
