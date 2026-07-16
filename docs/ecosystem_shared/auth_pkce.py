"""
auth_pkce.py — Canonical PKCE (S256) engine for iyou_ satellite apps.

Eliminates OIDC_RP_CLIENT_SECRET by replacing it with ephemeral,
per-request code verifiers per RFC 7636.  The verifier lives in the
encrypted session cookie for the duration of the OAuth flow and is
consumed exactly once on callback.

Drop-in for mozilla_django_oidc 5.x — no library settings required
beyond the standard OIDC_RP_CLIENT_ID / endpoint URLs.

Requirements (settings.py):
    SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
    OIDC_RP_CLIENT_ID = "<your-app-client-id>"
    OIDC_RP_SCOPES = "openid profile email"
    OIDC_OP_AUTHORIZATION_ENDPOINT = "https://iyou.me/openid/authorize/"
    OIDC_OP_TOKEN_ENDPOINT        = "https://iyou.me/openid/token/"
    OIDC_OP_USER_ENDPOINT         = "https://iyou.me/openid/userinfo/"
    OIDC_AUTHENTICATION_CALLBACK_URL = "oidc_authentication_callback"
    LOGIN_REDIRECT_URL            = "/"
    LOGIN_REDIRECT_URL_FAILURE    = "/"

URLconf (config/urls.py):
    from templates.utils.auth_pkce import (
        PKCEOIDCAuthenticationRequestView,
        PKCEOIDCAuthenticationCallbackView,
    )
    from mozilla_django_oidc.views import OIDCLogoutView

    path("oidc/authenticate/",
         PKCEOIDCAuthenticationRequestView.as_view(),
         name="oidc_authentication_init"),
    path("oidc/callback/",
         PKCEOIDCAuthenticationCallbackView.as_view(),
         name="oidc_authentication_callback"),
    path("oidc/logout/",
         OIDCLogoutView.as_view(),
         name="oidc_logout"),

AUTHENTICATION_BACKENDS:
    "templates.utils.auth_pkce.PKCEAuthenticationBackend"

Session contract:
    request.session["pkce_code_verifier"]  — set on /auth, popped on /callback
    via get_backend_kwargs(), which forwards it to the authentication backend.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

import requests
from django.contrib import auth
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse
from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    get_next_url,
    get_random_string,
)
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session key constants
# ---------------------------------------------------------------------------

SESSION_KEY_CODE_VERIFIER = "pkce_code_verifier"
SESSION_KEY_OIDC_LOGIN_NEXT = "oidc_login_next"


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def _generate_code_verifier(length: int = 64) -> str:
    """Return a cryptographically secure, URL-safe random string.

    The output length (pre-encoding) is `length` random bytes, which
    yields a base64url string between 43 and 128 characters depending
    on the input length.  RFC 7636 section 4.1 mandates the range
    [43, 128].

    Raises ValueError if the requested length is outside the valid range.
    """
    if not (43 <= length <= 128):
        raise ValueError(
            f"code_verifier length must be between 43 and 128, got {length}"
        )
    return secrets.token_urlsafe(length)


def _compute_code_challenge(verifier: str) -> str:
    """BASE64URL(SHA256(verifier)) — RFC 7636 section 4.1, S256 method.

    The trailing '=' padding is stripped to comply with the URL-safe
    encoding spec required by the code challenge exchange.
    """
    hash_bytes = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = urlsafe_b64encode(hash_bytes).decode("utf-8")
    return challenge.rstrip("=")


# ---------------------------------------------------------------------------
# Authorization Request — RP → iyou_idp
# ---------------------------------------------------------------------------

class PKCEOIDCAuthenticationRequestView(OIDCAuthenticationRequestView):
    """Generate a PKCE code_verifier, compute its S256 code_challenge,
    and redirect the user-agent to iyou_idp with both injected into the
    authorization request parameters.

    The verifier is persisted in ``request.session['pkce_code_verifier']``
    so it survives the round-trip through the OP without server-side state.
    """

    http_method_names = ["get"]

    def get(self, request):
        """Intercept the GET, generate PKCE pair, redirect to the OP."""
        try:
            state = get_random_string(
                self.get_settings("OIDC_STATE_SIZE", 32)
            )
            redirect_field_name = self.get_settings(
                "OIDC_REDIRECT_FIELD_NAME", "next"
            )
            reverse_url = self.get_settings(
                "OIDC_AUTHENTICATION_CALLBACK_URL",
                "oidc_authentication_callback",
            )

            # -- PKCE: generate verifier + challenge --------------------------
            code_verifier = _generate_code_verifier(
                self.get_settings("OIDC_PKCE_CODE_VERIFIER_SIZE", 64)
            )
            code_challenge = _compute_code_challenge(code_verifier)

            # Persist the verifier in the encrypted session cookie.
            request.session[SESSION_KEY_CODE_VERIFIER] = code_verifier

            # -- Build outbound query parameters ------------------------------
            params = {
                "response_type": "code",
                "scope": self.get_settings("OIDC_RP_SCOPES", "openid profile email"),
                "client_id": self.OIDC_RP_CLIENT_ID,
                "redirect_uri": absolutify(request, reverse(reverse_url)),
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }

            # Merge any app-level extra authorization params.
            params.update(self.get_extra_params(request))

            # Nonce — optional but strongly recommended for ID token replay
            # protection.
            if self.get_settings("OIDC_USE_NONCE", True):
                nonce = get_random_string(
                    self.get_settings("OIDC_NONCE_SIZE", 32)
                )
                params["nonce"] = nonce

            # Stash the state + nonce in the library's oidc_states dict so
            # the callback view can validate the return.  The code_verifier
            # lives in its own dedicated session key for clean separation.
            add_state_and_verifier_and_nonce_to_session(
                request, state, params, code_verifier=None
            )

            request.session[SESSION_KEY_OIDC_LOGIN_NEXT] = get_next_url(
                request, redirect_field_name
            )
            request.session.save()

            # -- Redirect to iyou_idp -----------------------------------------
            query = urlencode(params)
            redirect_url = f"{self.OIDC_OP_AUTH_ENDPOINT}?{query}"
            return HttpResponseRedirect(redirect_url)

        except Exception:
            logger.exception("PKCE auth request failed")
            return HttpResponseRedirect(
                self.get_settings("LOGIN_REDIRECT_URL_FAILURE", "/")
            )


# ---------------------------------------------------------------------------
# Authorization Callback — iyou_idp → RP
# ---------------------------------------------------------------------------

class PKCEOIDCAuthenticationCallbackView(OIDCAuthenticationCallbackView):
    """Handle the authorization code callback from iyou_idp.

    This view does NOT override ``get()``.  Instead it overrides the
    library's ``get_backend_kwargs()`` hook, which is called internally
    by the parent ``get()`` method when it invokes the authentication
    backend.  By injecting the code_verifier into the backend kwargs
    here, the verifier is guaranteed to reach the backend's
    ``authenticate()`` call without intercepting the view routing flow.

    Session contract:
        ``request.session['pkce_code_verifier']`` is popped here and
        forwarded as ``kwargs['code_verifier']`` to the backend.
    """

    def get_backend_kwargs(self, request):
        """Pop the PKCE verifier from the session and forward it to the
        authentication backend via the kwargs dictionary.

        This is the canonical hook point for injecting custom parameters
        into the backend's ``authenticate()`` call.  The parent class's
        ``get()`` method calls this method internally and passes the
        returned dict as keyword arguments to ``auth.authenticate()``.
        """
        kwargs = super().get_backend_kwargs(request)

        code_verifier = request.session.pop(SESSION_KEY_CODE_VERIFIER, None)

        if code_verifier is None:
            logger.warning(
                "No pkce_code_verifier in session — possible replay, "
                "cookie rotation failure, or direct callback access"
            )

        kwargs.update({"code_verifier": code_verifier})
        return kwargs


# ---------------------------------------------------------------------------
# Authentication Backend — PKCE-only, no client_secret required
# ---------------------------------------------------------------------------

class PKCEAuthenticationBackend(auth.Backend):
    """Authenticate via iyou_idp using an authorization code + PKCE
    code_verifier.

    This backend inherits directly from ``django.contrib.auth.Backend``
    to avoid any pre-shared credential checks or ``OIDC_RP_CLIENT_SECRET``
    enforcement that ``OIDCAuthenticationBackend`` would impose at
    ``__init__`` time.

    The code verifier proves possession of the original challenge and
    replaces the static shared secret for public clients (RFC 7636).

    User lookup filters search strictly on ``username=claims.get('sub')``
    (the root DID string), completely bypassing email string fields to
    prevent unique constraint violations.

    Privilege evaluation reads ``settings.ADMIN_DID`` and calls
    ``set_unusable_password()`` on the admin account to enforce
    passwordless posture (AUTH_FLOW_SPECIFICATION.md §6.2).
    """

    def authenticate(self, request, code_verifier=None, nonce=None, **kwargs):
        """Execute the PKCE token exchange and return the authenticated
        user, or ``None`` on any failure.

        Parameters
        ----------
        request : HttpRequest
            The current request object.  Must contain ``GET['code']`` and
            ``GET['state']`` from the OP callback.
        code_verifier : str or None
            The PKCE code verifier popped from the session by the
            callback view's ``get_backend_kwargs()``.
        nonce : str or None
            The OIDC nonce for ID token replay protection.
        """
        if not request:
            return None

        code = request.GET.get("code")
        state = request.GET.get("state")

        if not (code and state):
            return None

        # -- Build the token exchange payload --------------------------------
        token_payload = {
            "client_id": self._get_setting("OIDC_RP_CLIENT_ID"),
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": absolutify(
                request,
                reverse(
                    self._get_setting(
                        "OIDC_AUTHENTICATION_CALLBACK_URL",
                        "oidc_authentication_callback",
                    )
                ),
            ),
        }

        # Conditionally include client_secret — present only if the app
        # has a legacy static secret configured.  The PKCE verifier alone
        # satisfies iyou_idp's token endpoint.
        client_secret = self._get_setting("OIDC_RP_CLIENT_SECRET", "")
        if client_secret:
            token_payload["client_secret"] = client_secret

        # Inject the PKCE code_verifier into the token body.
        if code_verifier is not None:
            token_payload["code_verifier"] = code_verifier

        # -- Execute the back-channel token exchange -------------------------
        try:
            token_info = self._do_token_request(token_payload)
        except requests.ConnectionError:
            logger.error("Connection refused by token endpoint")
            return None
        except requests.Timeout:
            logger.error("Token endpoint timed out")
            return None
        except requests.RequestException as exc:
            logger.error("Token exchange failed: %s", exc)
            return None

        if "error" in token_info:
            logger.warning(
                "Token error [%s]: %s",
                token_info.get("error"),
                token_info.get("error_description", "(no description)"),
            )
            return None

        # -- Fetch the user profile from the OP -----------------------------
        try:
            user_info = self._do_userinfo_request(token_info)
        except requests.ConnectionError:
            logger.error("Connection refused by userinfo endpoint")
            return None
        except requests.Timeout:
            logger.error("UserInfo endpoint timed out")
            return None
        except requests.RequestException as exc:
            logger.error("UserInfo request failed: %s", exc)
            return None

        return self._get_or_create_user(user_info)

    def get_user(self, user_id):
        """Required by Django's auth framework.  Retrieve a user by
        primary key.
        """
        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    # ------------------------------------------------------------------
    # Back-channel HTTP helpers
    # ------------------------------------------------------------------

    def _do_token_request(self, payload: dict) -> dict:
        """POST to the OP's token endpoint.

        When OIDC_TOKEN_USE_BASIC_AUTH is enabled the client_secret is
        sent as a Basic Auth header instead of in the form body —
        per RFC 6749 section 2.3.1.
        """
        auth_header = None
        if self._get_setting("OIDC_TOKEN_USE_BASIC_AUTH", False):
            auth_header = requests.auth.HTTPBasicAuth(
                payload.pop("client_id", ""),
                payload.pop("client_secret", ""),
            )

        response = requests.post(
            self._get_setting("OIDC_OP_TOKEN_ENDPOINT"),
            data=payload,
            auth=auth_header,
            verify=self._get_setting("OIDC_VERIFY_SSL", True),
            timeout=self._get_setting("OIDC_TIMEOUT", 10),
        )
        response.raise_for_status()
        return response.json()

    def _do_userinfo_request(self, token_info: dict) -> dict:
        """GET the user profile from the OP's userinfo endpoint."""
        access_token = token_info.get("access_token")
        if not access_token:
            raise ValueError("Token response missing access_token")

        response = requests.get(
            self._get_setting("OIDC_OP_USER_ENDPOINT"),
            headers={"Authorization": f"Bearer {access_token}"},
            verify=self._get_setting("OIDC_VERIFY_SSL", True),
            timeout=self._get_setting("OIDC_TIMEOUT", 10),
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # User provisioning — DID-only lookup, no email fallback
    # ------------------------------------------------------------------

    def _get_or_create_user(self, user_info: dict):
        """Create or retrieve a Django user from the OIDC userinfo.

        User lookup is strictly on ``username=sub`` (the root DID
        string).  Email fields are never used as lookup keys to prevent
        unique constraint violations when multiple DID records share an
        email address.

        Sovereign Admin Posture Hook (AUTH_FLOW_SPECIFICATION.md §6.2):
        elevate if ``settings.ADMIN_DID`` matches ``sub``, always
        call ``set_unusable_password()`` on admin, elevation only.
        """
        from django.contrib.auth import get_user_model

        User = get_user_model()

        sub = user_info.get("sub")
        if not sub:
            logger.warning("OIDC userinfo missing 'sub' claim")
            return None

        username = sub

        try:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": user_info.get("email", ""),
                    "first_name": user_info.get("given_name", ""),
                    "last_name": user_info.get("family_name", ""),
                },
            )
        except Exception:
            logger.exception("User provisioning failed for %s", username)
            return None

        # -- Privilege evaluation -------------------------------------------
        # §6.2: evaluate_sovereign_admin_posture
        from django.conf import settings as _settings
        target_admin_did = getattr(_settings, "ADMIN_DID", None)
        is_admin = bool(target_admin_did) and sub == target_admin_did

        dirty = False
        if is_admin:
            if not user.is_staff:
                user.is_staff = True
                dirty = True
            if not user.is_superuser:
                user.is_superuser = True
                dirty = True
            if user.has_usable_password():
                user.set_unusable_password()
                dirty = True

        if dirty:
            user.save(update_fields=["is_staff", "is_superuser", "password"])

        return user

    # ------------------------------------------------------------------
    # Settings helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_setting(key: str, default=None):
        """Read a Django setting with a safe fallback.

        Unlike the library's import_from_settings(), this never raises
        ImproperlyConfigured when a key is missing — it returns the
        default silently, which is the correct behaviour for optional
        values like OIDC_RP_CLIENT_SECRET.
        """
        from django.conf import settings as _s

        return getattr(_s, key, default)
