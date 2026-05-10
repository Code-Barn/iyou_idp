"""
Custom OIDC provider implementation for DID-based claims.
"""
from django.conf import settings


def custom_userinfo_claims(user, scope, claims, id_token=None, token=None, **kwargs):
    """
    Custom userinfo claims that use the DID as the subject claim.

    Args:
        user: The authenticated user (our custom User model)
        scope: OIDC scope requested
        claims: Claims being requested
        id_token: ID token if available
        token: Access token if available
        **kwargs: Additional arguments

    Returns:
        dict: Custom claims with DID as subject
    """
    # Import here to avoid circular imports
    from oidc_provider.lib import claims as oidc_claims

    # Start with default claims
    claims_dict = oidc_claims.default_userinfo_claims(user, scope, claims, id_token, token, **kwargs)
    
    # Override the sub claim with the user's DID (username field)
    claims_dict['sub'] = user.username  # DID is stored in username
    
    # Add additional DID-specific claims
    claims_dict['did'] = user.username
    claims_dict['preferred_username'] = user.username
    claims_dict['did_method'] = user.username.split(':')[1] if user.username.count(':') >= 2 else 'key'
    
    return claims_dict


def custom_id_token_claims(user, scope, claims, id_token=None, token=None, **kwargs):
    """
    Custom ID token claims that use the DID as the subject claim.
    
    Args:
        user: The authenticated user (our custom User model)
        scope: OIDC scope requested
        claims: Claims being requested
        id_token: ID token if available
        token: Access token if available
        **kwargs: Additional arguments
        
    Returns:
        dict: Custom ID token claims with DID as subject
    """
    # Import here to avoid circular imports
    from oidc_provider.lib import claims as oidc_claims
    
    # Start with default claims
    claims_dict = oidc_claims.default_id_token_claims(user, scope, claims, id_token, token, **kwargs)
    
    # Override the sub claim with the user's DID (username field)
    claims_dict['sub'] = user.username  # DID is stored in username
    
    # Add additional DID-specific claims
    claims_dict['did'] = user.username
    claims_dict['did_method'] = user.username.split(':')[1] if user.username.count(':') >= 2 else 'key'
    
    return claims_dict


def custom_scopes_claims(user, scope, claims, id_token=None, token=None, **kwargs):
    """
    Custom scopes claims handler.
    """
    from oidc_provider.lib import claims as oidc_claims
    return oidc_claims.default_scopes_claims(user, scope, claims, id_token, token, **kwargs)
