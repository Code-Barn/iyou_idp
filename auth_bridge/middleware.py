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
Session Revocation Interceptor Middleware (DEP-104).

If dep.revoked == true (checked against IssuedCredential revocation state
or kind:9112 RevocationTickets), immediately rejects the token refresh
or session validation with HTTP 403 DependentSessionRevoked.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse

from auth_bridge.tokens import is_credential_revoked

logger = logging.getLogger(__name__)


class DependentRevocationMiddleware:
    """
    Middleware interceptor rejecting token refreshes and authenticated sessions
    for revoked dependents with HTTP 403 DependentSessionRevoked.
    """

    def __init__(self, get_response: Any):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # 1. Token Endpoint Interception (token refresh or authorization_code)
        if request.path.rstrip("/").endswith("/openid/token"):
            grant_type = request.POST.get("grant_type")
            refresh_token = request.POST.get("refresh_token")
            code_val = request.POST.get("code")

            # Also inspect JSON bodies if submitted via application/json
            if not grant_type and request.body:
                try:
                    body_json = json.loads(request.body)
                    if isinstance(body_json, dict):
                        grant_type = body_json.get("grant_type")
                        refresh_token = refresh_token or body_json.get("refresh_token")
                        code_val = code_val or body_json.get("code")
                except Exception:
                    pass

            if grant_type == "refresh_token" and refresh_token:
                try:
                    from oidc_provider.models import Token

                    token_obj = Token.objects.filter(refresh_token=refresh_token).select_related("user").first()
                    if token_obj:
                        user_did = token_obj.user.custodial_did if token_obj.user else None
                        id_token_dic = token_obj.id_token or {}
                        dep_claim = id_token_dic.get("dep", {})
                        if dep_claim.get("revoked") is True or (user_did and is_credential_revoked(user_did)):
                            logger.warning("Revocation interceptor blocked refresh token for DID %s", user_did)
                            return self._revocation_response()
                except Exception as exc:
                    logger.debug("Error checking refresh token revocation: %s", exc)

            elif grant_type == "authorization_code" and code_val:
                try:
                    from oidc_provider.models import Code

                    code_obj = Code.objects.filter(code=code_val).select_related("user").first()
                    if code_obj and code_obj.user:
                        user_did = code_obj.user.custodial_did
                        if user_did and is_credential_revoked(user_did):
                            logger.warning("Revocation interceptor blocked token exchange for revoked DID %s", user_did)
                            return self._revocation_response()
                except Exception as exc:
                    logger.debug("Error checking auth code revocation: %s", exc)

        # 2. Session Validation Interception (authenticated user or session)
        if hasattr(request, "user") and request.user.is_authenticated:
            user_did = getattr(request.user, "custodial_did", None)
            if user_did:
                # Check session-persisted dep claim
                if hasattr(request, "session"):
                    dep_session = request.session.get("dep")
                    if isinstance(dep_session, dict) and dep_session.get("revoked") is True:
                        return self._revocation_response()

                # Check IssuedCredential and kind:9112 revocation tickets
                if is_credential_revoked(user_did):
                    logger.warning("Revocation interceptor blocked active session for DID %s", user_did)
                    return self._revocation_response()

        # 3. Bearer Token Authorization Validation
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:].strip()
            if access_token:
                try:
                    from oidc_provider.models import Token

                    token_obj = Token.objects.filter(access_token=access_token).select_related("user").first()
                    if token_obj and token_obj.user:
                        user_did = token_obj.user.custodial_did
                        id_token_dic = token_obj.id_token or {}
                        dep_claim = id_token_dic.get("dep", {})
                        if dep_claim.get("revoked") is True or (user_did and is_credential_revoked(user_did)):
                            logger.warning("Revocation interceptor blocked Bearer request for DID %s", user_did)
                            return self._revocation_response()
                except Exception as exc:
                    logger.debug("Error checking Bearer access token revocation: %s", exc)

        # 4. Explicit test / manual override flags
        if getattr(request, "dep_revoked", False) or request.META.get("HTTP_X_DEP_REVOKED") == "true":
            return self._revocation_response()

        return self.get_response(request)

    def _revocation_response(self) -> JsonResponse:
        """Construct canonical HTTP 403 DependentSessionRevoked response."""
        return JsonResponse(
            {
                "error": "DependentSessionRevoked",
                "error_description": "Dependent session has been revoked by parent authority.",
            },
            status=403,
            reason="DependentSessionRevoked",
        )


# Canonical alias matching directive naming
SessionRevocationInterceptor = DependentRevocationMiddleware
