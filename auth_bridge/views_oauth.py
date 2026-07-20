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
Tier 1 Managed Convenience — Inbound OAuth2 View Controllers.

Handles front-channel initiation and back-channel callback for Google,
Apple, and GitHub social logins.  Each authenticated profile is piped
through the anti-Sybil Smart-Merge pipeline (pipeline.py) and mapped
to a server-managed did:web custodial identity.

Biometric Alignment Hooks (WebAuthn — upcoming):
    At the terminal point of a successful OAuth session confirmation
    (see OAuthCallbackView._complete_login), a future WebAuthn
    challenge/response verification pass will intercept the session
    context.  This allows any Tier 1 managed account to register and
    append an OS-enclave hardware key (e.g. Touch ID, Windows Hello,
    YubiKey) to their relational identity baseline.  The hook point is
    marked with ``# WEBAUTHN_HOOK`` below — the credential matching
    routine will:
      1. Check whether the user has registered WebAuthn credentials.
      2. If yes, issue a ``PublicKeyCredentialRequestOptions`` challenge
         and redirect to a verification view before completing login.
      3. On successful assertion, store the credential authenticator
         data alongside the FederatedIdentity record to strengthen the
         account's anti-Sybil posture.
      4. If no credentials exist, skip directly to session finalisation.
"""

import base64
import json
import logging
import secrets
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib.auth import login
from django.http import HttpResponseRedirect, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from .pipeline import process_oauth_identity

logger = logging.getLogger(__name__)

SESSION_KEY_OAUTH_STATE = "oauth_state"
SESSION_KEY_OAUTH_PROVIDER = "oauth_provider"
SESSION_KEY_OIDC_NEXT = "oidc_pending_next"
SESSION_KEY_OAUTH_NEXT = "oauth_next"
STATE_TTL = 300


# ──────────────────────────────────────────────────────────────────────────────
# Provider-specific profile extractors
# ──────────────────────────────────────────────────────────────────────────────

def _extract_google_profile(token_response: dict, userinfo: dict) -> dict:
    id_token_claims = _decode_id_token(token_response.get("id_token", ""))
    return {
        "provider_uid": id_token_claims.get("sub") or userinfo.get("sub", ""),
        "email": id_token_claims.get("email") or userinfo.get("email", ""),
        "name": userinfo.get("name", ""),
    }


def _extract_github_profile(token_response: dict, userinfo: dict) -> dict:
    email = userinfo.get("email", "")
    if not email:
        email = _fetch_github_primary_email(token_response.get("access_token", ""))
    return {
        "provider_uid": str(userinfo.get("id", "")),
        "email": email,
        "name": userinfo.get("name") or userinfo.get("login", ""),
    }


def _extract_apple_profile(token_response: dict, userinfo: dict) -> dict:
    id_token_claims = _decode_id_token(token_response.get("id_token", ""))
    return {
        "provider_uid": id_token_claims.get("sub", ""),
        "email": id_token_claims.get("email", ""),
        "name": _build_apple_name(id_token_claims),
    }


_PROFILE_EXTRACTORS = {
    "google": _extract_google_profile,
    "github": _extract_github_profile,
    "apple": _extract_apple_profile,
}


# ──────────────────────────────────────────────────────────────────────────────
# JWT / token helpers
# ──────────────────────────────────────────────────────────────────────────────

def _decode_id_token(token: str) -> dict:
    if not token:
        return {}
    try:
        payload = token.split(".")[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        logger.warning("Failed to decode id_token")
        return {}


def _fetch_github_primary_email(access_token: str) -> str:
    try:
        resp = requests.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )
        resp.raise_for_status()
        for entry in resp.json():
            if entry.get("primary") and entry.get("verified"):
                return entry["email"]
    except requests.RequestException:
        logger.error("GitHub primary email fetch failed")
    return ""


def _build_apple_name(claims: dict) -> str:
    name_obj = claims.get("name", {})
    if isinstance(name_obj, dict):
        given = name_obj.get("firstName", "")
        family = name_obj.get("lastName", "")
        return f"{given} {family}".strip()
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# Views
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(csrf_exempt, name="dispatch")
class OAuthInitiateView(View):
    """
    Front-channel initiation for Tier 1 social logins.

    1. Validate the requested provider is configured.
    2. Generate a high-entropy ``state`` token.
    3. Persist state + provider in the session with a 300-second TTL.
    4. Store any pending OIDC ``next`` URL for post-login continuity.
    5. Redirect the user-agent to the provider's authorization endpoint.
    """

    def get(self, request, provider: str):
        provider_cfg = settings.OAUTH_PROVIDERS.get(provider)
        if not provider_cfg or not provider_cfg.get("client_id"):
            return JsonResponse(
                {"error": f"Unsupported or unconfigured provider: {provider}"},
                status=400,
            )

        state = secrets.token_urlsafe(32)
        request.session[SESSION_KEY_OAUTH_STATE] = state
        request.session[SESSION_KEY_OAUTH_PROVIDER] = provider
        request.session.set_expiry(STATE_TTL)

        next_url = request.GET.get("next", "")
        if next_url:
            request.session[SESSION_KEY_OAUTH_NEXT] = next_url

        callback_url = (
            f"{settings.IDP_BASE_URL}/auth/oauth/callback/{provider}/"
        )

        params = {
            "client_id": provider_cfg["client_id"],
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": provider_cfg["scope"],
            "state": state,
        }

        if provider == "google":
            params["access_type"] = "offline"
            params["prompt"] = "consent"

        if provider == "apple":
            params["response_mode"] = "form_post"

        authorization_url = (
            f"{provider_cfg['authorization_endpoint']}?{urlencode(params)}"
        )
        return HttpResponseRedirect(authorization_url)

    def post(self, request, provider: str):
        return self.get(request, provider)


@method_decorator(csrf_exempt, name="dispatch")
class OAuthCallbackView(View):
    """
    Back-channel callback for Tier 1 social logins.

    1. Validate the ``state`` parameter against the session to defeat CSRF.
    2. Exchange the authorization ``code`` for token set via back-channel POST.
    3. Extract the provider profile (unique ID, verified email, name).
    4. Feed the profile into the Smart-Merge pipeline (pipeline.py).
    5. Authenticate the Django session.
    6. Resume any pending OIDC authorization flow, or fall back to default.
    """

    def get(self, request, provider: str):
        return self._handle(request, provider)

    def post(self, request, provider: str):
        return self._handle(request, provider)

    # ── core handler ──────────────────────────────────────────────────────

    def _handle(self, request, provider: str):
        provider_cfg = settings.OAUTH_PROVIDERS.get(provider)
        if not provider_cfg:
            return JsonResponse({"error": "Unknown provider"}, status=400)

        stored_state = request.session.pop(SESSION_KEY_OAUTH_STATE, None)
        returned_state = (
            request.GET.get("state") or request.POST.get("state") or ""
        )

        if not stored_state or not secrets.compare_digest(stored_state, returned_state):
            logger.warning(
                "OAUTH STATE MISMATCH: provider=%s stored=%s returned=%s",
                provider,
                stored_state[:8] if stored_state else None,
                returned_state[:8] if returned_state else None,
            )
            return JsonResponse({"error": "Invalid or expired OAuth state"}, status=403)

        error = request.GET.get("error") or request.POST.get("error")
        if error:
            description = (
                request.GET.get("error_description", "")
                or request.POST.get("error_description", "")
            )
            logger.warning("OAUTH PROVIDER ERROR: provider=%s error=%s desc=%s", provider, error, description)
            return JsonResponse({"error": error, "detail": description}, status=400)

        code = request.GET.get("code") or request.POST.get("code")
        if not code:
            return JsonResponse({"error": "Missing authorization code"}, status=400)

        token_response = self._exchange_code(provider_cfg, code, provider)
        if token_response is None:
            return JsonResponse({"error": "Token exchange failed"}, status=502)

        userinfo = self._fetch_userinfo(provider_cfg, token_response)

        extractor = _PROFILE_EXTRACTORS.get(provider)
        if not extractor:
            return JsonResponse({"error": "No profile extractor for provider"}, status=500)

        profile = extractor(token_response, userinfo)

        if not profile.get("provider_uid") or not profile.get("email"):
            return JsonResponse(
                {"error": "Provider returned incomplete profile (missing ID or email)"},
                status=400,
            )

        result = process_oauth_identity(
            provider_name=provider,
            provider_uid=profile["provider_uid"],
            verified_email=profile["email"],
        )

        if result["action"] == "require_password_verification":
            return JsonResponse(
                {
                    "action": "require_password_verification",
                    "user_id": result["user_id"],
                    "email": result["email"],
                    "pending_provider": result["pending_provider"],
                    "pending_uid": result["pending_uid"],
                },
                status=409,
            )

        user = result["user"]

        if not user.is_active:
            return JsonResponse({"error": "User account is disabled"}, status=403)

        # ── WebAuthn hook point ──────────────────────────────────────────
        # WEBAUTHN_HOOK: Before calling login(), intercept here to check
        # whether `user` has registered WebAuthn credentials.  If credentials
        # exist, redirect to a challenge view instead of finalising the
        # session immediately.  This allows managed Tier 1 accounts to
        # strengthen their anti-Sybil posture with an OS-enclave hardware
        # key assertion before the session is established.

        return self._complete_login(request, user)

    # ── back-channel HTTP helpers ─────────────────────────────────────────

    def _exchange_code(self, provider_cfg: dict, code: str, provider: str) -> dict | None:
        callback_url = (
            f"{settings.IDP_BASE_URL}/auth/oauth/callback/{provider}/"
        )

        payload = {
            "client_id": provider_cfg["client_id"],
            "client_secret": provider_cfg["client_secret"],
            "code": code,
            "redirect_uri": callback_url,
            "grant_type": "authorization_code",
        }

        headers = {"Accept": "application/json"}

        try:
            resp = requests.post(
                provider_cfg["token_endpoint"],
                data=payload,
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            logger.exception("OAuth token exchange failed for provider=%s", provider)
            return None

    def _fetch_userinfo(self, provider_cfg: dict, token_response: dict) -> dict:
        userinfo_endpoint = provider_cfg.get("userinfo_endpoint")
        if not userinfo_endpoint:
            return {}

        access_token = token_response.get("access_token", "")
        if not access_token:
            return {}

        try:
            resp = requests.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            logger.exception("OAuth userinfo fetch failed for provider=%s", provider_cfg.get("client_id", ""))
            return {}

    # ── session finalisation ──────────────────────────────────────────────

    def _complete_login(self, request, user):
        login(request, user, backend="auth_bridge.backend.DIDAuthBackend")

        pending_next = request.session.pop(SESSION_KEY_OAUTH_NEXT, None)

        if pending_next:
            from .views import _build_oidc_redirect
            oidc_redirect = _build_oidc_redirect(pending_next, user)
            if oidc_redirect is not None:
                return HttpResponseRedirect(oidc_redirect)
            return HttpResponseRedirect(pending_next)

        return HttpResponseRedirect(settings.IDP_WUN_URL)
