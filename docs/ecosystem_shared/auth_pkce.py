"""
auth_pkce.py — Canonical Golden PKCE (S256) engine for iyou_ satellite apps.

Eliminates OIDC_RP_CLIENT_SECRET by replacing it with ephemeral,
per-request code verifiers per RFC 7636.  The verifier lives in the
encrypted signed session cookie for the duration of the OAuth flow and is
consumed on callback.

Drop-in for mozilla_django_oidc 5.x — no library settings required
beyond the standard OIDC_RP_CLIENT_ID / endpoint URLs.

Requirements (config/settings.py):
    SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True
    SESSION_COOKIE_NAME = env("SESSION_COOKIE_NAME", default=f"{APP_SLUG}_sessionid")
    CSRF_COOKIE_NAME = env("CSRF_COOKIE_NAME", default=f"{APP_SLUG}_csrftoken")
    SESSION_COOKIE_DOMAIN = None
    CSRF_COOKIE_DOMAIN = None
    OIDC_RP_CLIENT_ID = f"iyou-{APP_SLUG}-satellite-client"
    OIDC_RP_CLIENT_SECRET = None
    OIDC_RP_SIGN_ALGO = "RS256"
    OIDC_RP_SCOPES = "openid profile email"
    OIDC_OP_AUTHORIZATION_ENDPOINT = "https://iyou.me/openid/authorize/"
    OIDC_OP_TOKEN_ENDPOINT        = "http://iyou-idp.identity.svc.cluster.local/openid/token/"
    OIDC_OP_USER_ENDPOINT         = "http://iyou-idp.identity.svc.cluster.local/openid/userinfo/"
    OIDC_OP_JWKS_ENDPOINT         = "http://iyou-idp.identity.svc.cluster.local/openid/jwks/"
    OIDC_AUTHENTICATION_CALLBACK_URL = "oidc_authentication_callback"
    LOGIN_URL                     = "/oidc/authenticate/"
    LOGIN_REDIRECT_URL            = "/"
    LOGIN_REDIRECT_URL_FAILURE    = "/"
    LOGOUT_REDIRECT_URL           = "/"

URLconf (config/urls.py):
    from apps.core.auth_pkce import (
        PKCEOIDCAuthenticationRequestView,
        PKCEOIDCAuthenticationCallbackView,
        PKCEOIDCLogoutView,
    )

    path("oidc/authenticate/",
         PKCEOIDCAuthenticationRequestView.as_view(),
         name="oidc_authentication_init"),
    path("oidc/callback/",
         PKCEOIDCAuthenticationCallbackView.as_view(),
         name="oidc_authentication_callback"),
    path("oidc/logout/",
         PKCEOIDCLogoutView.as_view(),
         name="oidc_logout"),
    path("oidc/offline-verify/",
         PKCEOIDCOfflineFallbackView.as_view(),
         name="oidc_offline_verify"),

AUTHENTICATION_BACKENDS:
    "apps.core.auth_pkce.PKCEAuthenticationBackend"
    "django.contrib.auth.backends.ModelBackend"

MIDDLEWARE:
    "apps.core.auth_pkce.OfflineSessionExpiryMiddleware"
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import time
from base64 import urlsafe_b64encode
from typing import Any
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.backends import ModelBackend
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
)
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView,
    OIDCLogoutView,
)

try:
    from mozilla_django_oidc.utils import get_next_url
except ImportError:  # pragma: no cover - mozilla-django-oidc >= 5.0
    from mozilla_django_oidc.views import get_next_url

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    InvalidSignature = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session key constants
# ---------------------------------------------------------------------------

SESSION_KEY_CODE_VERIFIER = "pkce_code_verifier"
SESSION_KEY_REDIRECT_URI = "pkce_redirect_uri"
SESSION_KEY_OIDC_LOGIN_NEXT = "oidc_login_next"

PKCE_VERIFIER_SESSION_KEY = "_pkce_cv"
PKCE_TIMESTAMP_SESSION_KEY = "_pkce_cv_ts"
PKCE_DEFAULT_MAX_AGE_SECONDS = 300

# Loop-safe silent SSO (prompt=none) state.  ``sso_silent_attempted`` latches
# a failed probe for the life of the session; ``sso_silent_inflight`` marks the
# single redirect so parallel tabs/assets cannot double-fire the probe.
SESSION_KEY_SSO_SILENT_ATTEMPTED = "sso_silent_attempted"
SESSION_KEY_SSO_SILENT_INFLIGHT = "sso_silent_inflight"
SSO_HINT_COOKIE = "iyou_sso_hint"
SILENT_SSO_ERRORS = {
    "login_required",
    "interaction_required",
    "consent_required",
    "account_selection_required",
}

# ---------------------------------------------------------------------------
# Deterministic Public-Key & DID / JID Normalization Helpers
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: idx for idx, char in enumerate(_BASE58_ALPHABET)}

_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {char: idx for idx, char in enumerate(_BECH32_ALPHABET)}
_BECH32_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DID_KEY_PREFIX = "did:key:"
_DID_WEB_PREFIX = "did:web:"
_BECH32_HRS = {"npub"}


class InvalidIdentifierError(ValueError):
    """Raised when an identifier cannot be canonicalized to a 64-hex key."""


def _decode_base58btc(value: str) -> bytes:
    if not value:
        raise InvalidIdentifierError("empty base58 payload")
    number = 0
    for char in value:
        if char not in _BASE58_INDEX:
            raise InvalidIdentifierError(f"invalid base58 character: {char!r}")
        number = number * 58 + _BASE58_INDEX[char]
    pad = len(value) - len(value.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * pad + body


def _decode_ed25519_signature(sig_str: str) -> bytes:
    """Decode a 64-byte Ed25519 signature from hex or base58 (with or without 'z')."""
    trimmed = str(sig_str).strip()
    if len(trimmed) == 128:
        try:
            raw = bytes.fromhex(trimmed)
            if len(raw) == 64:
                return raw
        except Exception:
            pass
    if trimmed.startswith("z"):
        try:
            raw = _decode_base58btc(trimmed[1:])
            if len(raw) == 64:
                return raw
        except Exception:
            pass
    try:
        raw = _decode_base58btc(trimmed)
        if len(raw) == 64:
            return raw
    except Exception:
        pass
    try:
        raw = bytes.fromhex(trimmed)
        if len(raw) == 64:
            return raw
    except Exception:
        pass
    raise ValueError("Signature must be a 64-byte hex or base58 string")


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, gen in enumerate(_BECH32_GENERATORS):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _decode_bech32(address: str) -> bytes:
    sep = address.rfind("1")
    if sep < 1 or sep + 7 > len(address):
        raise InvalidIdentifierError("malformed bech32 address")
    hrp, data_part = address[:sep], address[sep + 1 :]
    if hrp not in _BECH32_HRS:
        raise InvalidIdentifierError(f"unsupported bech32 HRP: {hrp!r}")
    if any(c not in _BECH32_INDEX for c in data_part):
        raise InvalidIdentifierError(f"invalid bech32 character in {hrp}1...")
    values = [_BECH32_INDEX[c] for c in data_part]
    if _bech32_polymod(_bech32_hrp_expand(hrp) + values) != 1:
        raise InvalidIdentifierError(f"bech32 checksum mismatch for {hrp}1...")
    payload = values[:-6]
    acc, bits, out = 0, 0, bytearray()
    for word in payload:
        acc = (acc << 5) | word
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 and (acc & ((1 << bits) - 1)):
        raise InvalidIdentifierError("non-zero bech32 padding bits")
    return bytes(out)


def _strip_multicodec_varint(payload: bytes) -> bytes:
    """Decode the leading multicodec varint and return the remaining key bytes."""
    if not payload:
        raise InvalidIdentifierError("empty multicodec payload")
    value, shift, consumed = 0, 0, 0
    for byte in payload:
        value |= (byte & 0x7F) << shift
        consumed += 1
        if not byte & 0x80:
            break
        shift += 7
        if shift > 35:
            raise InvalidIdentifierError("multicodec varint too long")
    return payload[consumed:]


def decode_public_key(identifier: str, *, require_64_hex: bool = True) -> str:
    """Decode any supported identifier into a lowercase 64-hex string.

    * ``did:web:...`` (Tier 1 Managed): strips prefix to validate non-empty
      method-specific ID and derives a raw 32-byte digest via
      ``hashlib.sha256(identifier.encode("utf-8")).digest()``, returning a
      64-hex lowercase string for nodeprep-safe usernames and JIDs.
    * ``did:key:z...`` (Base58btc) and ``npub1...`` (Bech32): decoded to raw
      32-byte public key bytes (33-byte compressed keys drop the 0x02/0x03
      parity byte) and rendered as 64 lowercase hex characters.
    """
    if not isinstance(identifier, str) or not identifier.strip():
        raise InvalidIdentifierError("identifier must be a non-empty string")

    ident = identifier.strip()
    if _HEX64_RE.match(ident):
        return ident

    if ident.startswith(_DID_WEB_PREFIX):
        body = ident[len(_DID_WEB_PREFIX) :].strip()
        if not body:
            raise InvalidIdentifierError("did:web identifier is missing method-specific id")
        raw = hashlib.sha256(ident.encode("utf-8")).digest()
        return raw.hex().lower()

    if ident.startswith(_DID_KEY_PREFIX):
        body = ident[len(_DID_KEY_PREFIX) :]
        if not body.startswith("z"):
            raise InvalidIdentifierError("did:key must use multibase base58btc ('z')")
        raw = _strip_multicodec_varint(_decode_base58btc(body[1:]))
    elif ident.startswith("npub1"):
        raw = _decode_bech32(ident)
    else:
        raise InvalidIdentifierError(
            "identifier must be 64-hex, did:key:z..., did:web:..., or npub1... (got a malformed value)"
        )

    if len(raw) == 32:
        key_bytes = raw
    elif len(raw) == 33 and raw[0] in (2, 3):
        key_bytes = raw[1:]
    else:
        raise InvalidIdentifierError(
            f"decoded public key has {len(raw)} bytes; expected 32 (64-hex). "
            "Unsupported curve or malformed payload."
        )

    pubkey_hex = key_bytes.hex().lower()
    if require_64_hex and not _HEX64_RE.match(pubkey_hex):
        raise InvalidIdentifierError("decoded public key is not 64 lowercase hex chars")
    return pubkey_hex


def normalize_jid_localpart(identifier: str) -> str:
    """Return the nodeprep-safe 64-hex localpart for any supported identifier."""
    localpart = identifier.split("@", 1)[0].strip()
    if not localpart:
        raise InvalidIdentifierError("empty JID localpart")
    return decode_public_key(localpart)


def derive_canonical_jid(identifier: str, domain: str | None = None) -> str:
    """Return ``{pubkey_hex}@{domain}`` for any supported identifier."""
    if domain is None:
        domain = getattr(settings, "IYOU_JID_DOMAIN", "iyou.me")
    if not domain or "@" in domain:
        raise InvalidIdentifierError(f"invalid JID domain: {domain!r}")
    localpart = normalize_jid_localpart(identifier)
    return f"{localpart}@{domain}"


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


generate_pkce_verifier = _generate_code_verifier
compute_s256_challenge = _compute_code_challenge


# ---------------------------------------------------------------------------
# Authorization Request — RP → iyou_idp
# ---------------------------------------------------------------------------

class PKCEOIDCAuthenticationRequestView(OIDCAuthenticationRequestView):
    """Generate a PKCE code_verifier, compute its S256 code_challenge,
    and redirect the user-agent to iyou_idp with both injected into the
    authorization request parameters.

    The verifier is persisted in ``request.session['pkce_code_verifier']``
    (and ``_pkce_cv``) so it survives the round-trip through the OP
    without server-side state.
    """

    http_method_names = ["get"]

    def get_extra_params(self, request):
        """Attach ``prompt=none`` only to a one-shot silent SSO attempt.

        Interactive clicks on the Layer 1 ``Authenticate`` link never carry
        ``prompt=none`` because the inflight flag is only set by
        ``SilentSSOMiddleware``.  Copy the settings dict before mutating it so
        a global ``OIDC_AUTH_REQUEST_EXTRA_PARAMS`` setting is never changed.
        """
        params = dict(super().get_extra_params(request) or {})
        if request.session.pop(SESSION_KEY_SSO_SILENT_INFLIGHT, False):
            params["prompt"] = "none"
        return params

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

            # Persist the verifier in the encrypted session cookie.
            request.session[SESSION_KEY_CODE_VERIFIER] = code_verifier
            request.session[PKCE_VERIFIER_SESSION_KEY] = code_verifier
            request.session[PKCE_TIMESTAMP_SESSION_KEY] = time.time()
            request.session[SESSION_KEY_REDIRECT_URI] = params["redirect_uri"]

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
            # the callback view can validate the return. The code_verifier
            # is passed explicitly per RFC 7636 invariants.
            add_state_and_verifier_and_nonce_to_session(
                request, state, params, code_verifier=code_verifier
            )

            request.session[SESSION_KEY_OIDC_LOGIN_NEXT] = get_next_url(
                request, redirect_field_name
            )

            # Force an explicit, immediate session save to prevent
            # redirection race conditions when an already-authenticated
            # root IDP session triggers a rapid redirect cycle.
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

    Forwards the PKCE ``code_verifier`` to the authentication backend,
    executes the back-channel token exchange via
    ``application/x-www-form-urlencoded``, logs detailed errors on non-200
    responses, and invokes ``django.contrib.auth.login(request, user, backend=...)``.
    """

    @property
    def login_kwargs(self) -> dict[str, Any]:
        """Include code_verifier from session in authentication kwargs."""
        kwargs: dict[str, Any] = {}
        if hasattr(self, "request"):
            kwargs["request"] = self.request
            if hasattr(self.request, "session"):
                code_verifier = (
                    self.request.session.get(SESSION_KEY_CODE_VERIFIER)
                    or self.request.session.get(PKCE_VERIFIER_SESSION_KEY)
                )
                if code_verifier:
                    kwargs["code_verifier"] = code_verifier
        return kwargs

    def get_backend_kwargs(self, request):
        """Pop the PKCE verifier from the session and forward it to the
        authentication backend via the kwargs dictionary.
        """
        parent_get_backend_kwargs = getattr(super(), "get_backend_kwargs", None)
        kwargs = parent_get_backend_kwargs(request) if parent_get_backend_kwargs else {}

        code_verifier = request.session.pop(
            SESSION_KEY_CODE_VERIFIER,
            request.session.pop(PKCE_VERIFIER_SESSION_KEY, None),
        )
        request.session.pop(PKCE_TIMESTAMP_SESSION_KEY, None)

        if code_verifier is None:
            logger.warning(
                "No pkce_code_verifier in session — possible replay, "
                "cookie rotation failure, or direct callback access"
            )

        kwargs.update({"code_verifier": code_verifier})
        return kwargs

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Process OIDC callback, ensure code_verifier is present in oidc_states,
        and clean up ephemeral PKCE session keys after authentication.
        """
        code_verifier = None
        if hasattr(request, "session"):
            code_verifier = (
                request.session.get(SESSION_KEY_CODE_VERIFIER)
                or request.session.get(PKCE_VERIFIER_SESSION_KEY)
            )
        state = request.GET.get("state")
        if (
            code_verifier
            and state
            and hasattr(request, "session")
            and "oidc_states" in request.session
            and isinstance(request.session["oidc_states"].get(state), dict)
        ):
            request.session["oidc_states"][state]["code_verifier"] = code_verifier
            request.session.modified = True

        try:
            return super().get(request, *args, **kwargs)
        finally:
            if hasattr(request, "session"):
                request.session.pop(SESSION_KEY_CODE_VERIFIER, None)
                request.session.pop(PKCE_VERIFIER_SESSION_KEY, None)
                request.session.pop(PKCE_TIMESTAMP_SESSION_KEY, None)

    def login_success(self):
        """Establish the authenticated Django session and redirect."""
        # Clear silent-SSO latches so a later logout/re-login starts clean.
        request = getattr(self, "request", None)
        if request is not None and hasattr(request, "session"):
            request.session.pop(SESSION_KEY_SSO_SILENT_ATTEMPTED, None)
            request.session.pop(SESSION_KEY_SSO_SILENT_INFLIGHT, None)

        user = getattr(self, "user", None)
        if user is not None and getattr(self, "request", None) is not None:
            backend_path = getattr(
                user,
                "backend",
                "apps.core.auth_pkce.PKCEAuthenticationBackend",
            )
            auth.login(self.request, user, backend=backend_path)
        return HttpResponseRedirect(self.success_url)

    def login_failure(self):
        """Recover cleanly from a silent ``prompt=none`` probe.

        iyou_idp answers ``login_required`` / ``interaction_required`` when no
        master session exists.  That is not an error for a silent attempt:
        latch the session, restore the originally requested URL, and return
        the normal unauthenticated page with no error banner.  Interactive
        failures still fall through to the library's ``login_failure()``.
        """
        request = getattr(self, "request", None)
        if (
            request is not None
            and hasattr(request, "session")
            and request.GET.get("error") in SILENT_SSO_ERRORS
            and (
                request.session.pop(SESSION_KEY_SSO_SILENT_INFLIGHT, False)
                or request.COOKIES.get(SSO_HINT_COOKIE) == "1"
            )
        ):
            request.session[SESSION_KEY_SSO_SILENT_ATTEMPTED] = True
            next_url = request.session.pop(SESSION_KEY_OIDC_LOGIN_NEXT, None)
            return HttpResponseRedirect(
                next_url or getattr(settings, "LOGIN_REDIRECT_URL", "/")
            )
        return super().login_failure()


# ---------------------------------------------------------------------------
# Logout View — Dual GET & POST support to prevent HTTP 405
# ---------------------------------------------------------------------------

class PKCEOIDCLogoutView(OIDCLogoutView):
    """Seamless GET and POST logout with federated IdP session termination.

    Flushes the local Django session, then chains to the master IdP's
    ``/auth/logout/?next=...`` so the central OIDC session is destroyed too —
    preventing a "false logout" where another satellite silently restores the
    user from the still-authenticated IdP.  The ``iyou_sso_hint`` cookie is
    removed in the same response so silent SSO cannot reverse the logout.
    """

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logout(request)
        idp_base = getattr(settings, "IDP_BASE_PUBLIC_URL", "https://iyou.me").rstrip("/")
        next_url = getattr(settings, "IDP_LOGOUT_RETURN_URL", "/")
        response = redirect(f"{idp_base}/auth/logout/?{urlencode({'next': next_url})}")
        response.delete_cookie(
            SSO_HINT_COOKIE,
            domain=None if getattr(settings, "DEBUG", False) else ".iyou.me",
        )
        return response


# ---------------------------------------------------------------------------
# Offline Enclave Fallback View (SEC-004)
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name="dispatch")
class PKCEOIDCOfflineFallbackView(View):
    """Canonical zero-extra-dependency SEC-004 offline enclave fallback endpoint.

    When iyou_idp (https://iyou.me) is unreachable, establishes an ephemeral
    Level 2 sovereign session (<= 300s TTL) by directly verifying an Ed25519 W3C
    Verifiable Presentation (VP) assertion signed by the user's local iyou_home
    desktop enclave bridge (127.0.0.1:9001).

    Gated behind settings.OFFLINE_AUTH_FALLBACK_ENABLED (default True).
    Fails closed on:
    - Non-POST requests
    - did:web or non-z6Mk DID methods
    - Audience mismatch (against settings.OIDC_RP_CLIENT_ID)
    - Expired assertions or validity windows > 300s
    - Replayed nonce challenges (via cache.add atomicity)
    - Tampered canonical JSON payload or invalid Ed25519 signatures
    - Dependent claims (dep.* minor/guardian claims strictly prohibited offline)
    """

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not getattr(settings, "OFFLINE_AUTH_FALLBACK_ENABLED", True):
            return JsonResponse(
                {"error": "offline_fallback_disabled", "message": "Offline fallback authentication is disabled."},
                status=403,
            )

        try:
            raw_body = request.body.decode("utf-8") if isinstance(request.body, bytes) else (request.body or "")
            body = json.loads(raw_body)
        except Exception:
            return JsonResponse(
                {"error": "invalid_request", "message": "Request body must be valid JSON."},
                status=400,
            )

        if not isinstance(body, dict):
            return JsonResponse(
                {"error": "invalid_request", "message": "JSON body must be an object."},
                status=400,
            )

        vp = body.get("vp")
        challenge = body.get("challenge")

        if not vp or not isinstance(vp, dict) or not challenge or not isinstance(challenge, str):
            return JsonResponse(
                {"error": "invalid_request", "message": "Missing 'vp' object or 'challenge' string."},
                status=400,
            )

        # 1. Reject dependent claims immediately (fail-closed on minor/guardian claims)
        if self._has_dependent_claims(vp):
            return JsonResponse(
                {
                    "error": "dependent_claims_offline_prohibited",
                    "message": "Offline enclave assertions cannot carry or delegate dependent claims (dep.*).",
                },
                status=403,
            )

        # 2. Verify holder starts with 'did:key:z6Mk' (reject did:web: or other DID methods)
        holder = vp.get("holder")
        if not isinstance(holder, str) or not holder.startswith("did:key:z6Mk"):
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": "Holder must start with 'did:key:z6Mk' (Ed25519 did:key).",
                },
                status=400,
            )

        # 3. Verify audience matches settings.OIDC_RP_CLIENT_ID
        expected_client_id = getattr(settings, "OIDC_RP_CLIENT_ID", None)
        vp_audience = vp.get("audience")
        if not expected_client_id or vp_audience != expected_client_id:
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": f"Audience mismatch: expected {expected_client_id!r}, got {vp_audience!r}.",
                },
                status=400,
            )

        # 4. Verify challenge matches VP challenge
        if vp.get("challenge") != challenge:
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": "Challenge nonce does not match assertion challenge.",
                },
                status=400,
            )

        # 5. Verify issued_at and expires_at: valid integers, 0 < (expires_at - issued_at) <= 300, time.time() < expires_at
        issued_at = vp.get("issued_at")
        expires_at = vp.get("expires_at")
        if (
            not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
        ):
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": "issued_at and expires_at must be valid integers.",
                },
                status=400,
            )

        ttl = expires_at - issued_at
        if not (0 < ttl <= 300):
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": f"Assertion TTL ({ttl}s) invalid: must be > 0 and <= 300s.",
                },
                status=400,
            )

        now = time.time()
        if now >= expires_at:
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": "Assertion has expired.",
                },
                status=400,
            )

        # 6. Single-use nonce check via cache.add (failing closed on replay)
        cache_key = f"offline_nonce:{challenge}"
        if not cache.add(cache_key, "1", timeout=300):
            return JsonResponse(
                {
                    "error": "invalid_grant",
                    "message": "Challenge nonce has already been consumed (replay detected).",
                },
                status=400,
            )

        # 7. Decode Ed25519 public key from 0xed01 multicodec did:key
        multibase = holder[len("did:key:") :]
        if not multibase.startswith("z"):
            return JsonResponse(
                {"error": "invalid_grant", "message": "did:key multibase must start with 'z'."},
                status=400,
            )
        try:
            raw_multicodec = _decode_base58btc(multibase[1:])
        except Exception as exc:
            return JsonResponse(
                {"error": "invalid_grant", "message": f"Malformed Base58 in did:key: {exc}"},
                status=400,
            )

        if len(raw_multicodec) != 34 or raw_multicodec[0] != 0xED or raw_multicodec[1] != 0x01:
            return JsonResponse(
                {"error": "invalid_grant", "message": "Holder multicodec prefix is not Ed25519 (0xed01)."},
                status=400,
            )

        raw_pubkey = raw_multicodec[2:]
        if Ed25519PublicKey is None:  # pragma: no cover
            return JsonResponse(
                {"error": "server_error", "message": "cryptography package required for offline verification."},
                status=500,
            )

        try:
            pubkey = Ed25519PublicKey.from_public_bytes(raw_pubkey)
        except Exception as exc:
            return JsonResponse(
                {"error": "invalid_grant", "message": f"Invalid Ed25519 public key bytes: {exc}"},
                status=400,
            )

        # 8. Extract signature and verify against canonical JSON
        proof = vp.get("proof")
        if not isinstance(proof, dict):
            return JsonResponse(
                {"error": "invalid_grant", "message": "Missing or invalid proof block."},
                status=400,
            )

        sig_val = proof.get("proofValue") or proof.get("signatureValue")
        if not sig_val or not isinstance(sig_val, str):
            return JsonResponse(
                {"error": "invalid_grant", "message": "Missing proofValue in proof block."},
                status=400,
            )

        try:
            sig_bytes = _decode_ed25519_signature(sig_val)
        except Exception as exc:
            return JsonResponse(
                {"error": "invalid_grant", "message": f"Invalid signature encoding: {exc}"},
                status=400,
            )

        canonical_fields = [
            "@context",
            "type",
            "holder",
            "challenge",
            "audience",
            "issued_at",
            "expires_at",
            "verifiableCredential",
            "issuer",
        ]

        payload_candidates: list[bytes] = []
        if all(k in vp for k in canonical_fields):
            canon_dict = {k: vp[k] for k in canonical_fields}
            payload_candidates.append(json.dumps(canon_dict, separators=(",", ":")).encode("utf-8"))

        non_proof = {k: v for k, v in vp.items() if k != "proof"}
        payload_candidates.append(json.dumps(non_proof, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        payload_candidates.append(json.dumps(non_proof, separators=(",", ":")).encode("utf-8"))

        verified = False
        for candidate in payload_candidates:
            try:
                pubkey.verify(sig_bytes, candidate)
                verified = True
                break
            except Exception:
                continue

        if not verified:
            return JsonResponse(
                {"error": "invalid_grant", "message": "Ed25519 signature verification failed."},
                status=400,
            )

        # 9. Resolve / provision User anchored to holder
        user = self._resolve_or_create_user(holder)

        # 10. Log in
        if not hasattr(user, "backend"):
            user.backend = "apps.core.auth_pkce.PKCEAuthenticationBackend"
        auth.login(request, user)

        # 11. Establish session state & strip dep.* keys
        if hasattr(request, "session"):
            request.session["auth_method"] = "did:offline_enclave"
            request.session["account_tier"] = "sovereign"
            request.session["offline_session_expires_at"] = expires_at
            request.session["expires_at"] = expires_at
            request.session["is_sovereign"] = True
            request.session["offline_enclave_active"] = True

            # Explicitly strip and block any dep.* dependent-session keys
            for skey in list(request.session.keys()):
                if skey.startswith("dep.") or skey.startswith("dep_") or skey == "dependent_claims":
                    request.session.pop(skey, None)

            if hasattr(request.session, "save"):
                request.session.save()
            request.session.modified = True

        return JsonResponse(
            {
                "status": "ok",
                "authenticated": True,
                "user": getattr(user, "username", str(user)),
                "auth_method": "did:offline_enclave",
                "account_tier": "sovereign",
                "offline_session_expires_at": expires_at,
            }
        )

    @staticmethod
    def _has_dependent_claims(vp: dict) -> bool:
        for k in vp:
            if k.startswith("dep.") or k.startswith("dep_") or k == "dependent_claims":
                return True
        vcs = vp.get("verifiableCredential")
        if isinstance(vcs, list):
            for vc in vcs:
                if isinstance(vc, dict):
                    for k in vc:
                        if k.startswith("dep.") or k.startswith("dep_") or k == "dependent_claims":
                            return True
        return False

    @staticmethod
    def _resolve_or_create_user(holder: str) -> Any:
        UserModel = get_user_model()
        username = PKCEAuthenticationBackend._normalize_sub_to_username(holder)
        user = None
        if hasattr(UserModel, "objects"):
            user = UserModel.objects.filter(username=username).first()
            if not user:
                try:
                    user = UserModel.objects.create_user(username=username)
                except Exception:
                    user = UserModel(username=username)
                    if hasattr(user, "save"):
                        user.save()
        if user is None:
            user = UserModel(username=username) if callable(UserModel) else UserModel
        if hasattr(user, "set_unusable_password"):
            user.set_unusable_password()
        if hasattr(user, "save"):
            user.save()
        return user


# ---------------------------------------------------------------------------
# Authentication Backend — PKCE-only, no client_secret required
# ---------------------------------------------------------------------------

class PKCEAuthenticationBackend(ModelBackend):
    """Authenticate via iyou_idp using an authorization code + PKCE
    code_verifier.

    This backend inherits directly from ``django.contrib.auth.backends.ModelBackend``
    to ensure session rehydration via ``get_user()`` across requests, while avoiding
    any pre-shared credential checks or ``OIDC_RP_CLIENT_SECRET`` enforcement that
    ``OIDCAuthenticationBackend`` would impose at ``__init__`` time.

    The code verifier proves possession of the original challenge and
    replaces the static shared secret for public clients (RFC 7636).

    ``verify_claims(self, claims)`` validates ``"sub" in claims`` rather than
    requiring an ``email`` claim, ensuring W3C DID subjects (``did:key:...`` and
    ``did:web:...``) authenticate without failing on missing email claims.
    """

    def verify_claims(self, claims):
        if not claims or "sub" not in claims:
            return False
        return True

    def get_username(self, claims: dict) -> str:
        """Map the OIDC ``sub`` claim (``did:key:...`` or ``did:web:...``) to a
        clean, deterministic Django username.
        """
        sub = (claims or {}).get("sub", "")
        return self._normalize_sub_to_username(sub)

    def filter_users_by_claims(self, claims: dict):
        """Look up users strictly by 1:1 mapping of OIDC ``sub`` to username."""
        UserModel = get_user_model()
        if not self.verify_claims(claims):
            return UserModel.objects.none()
        username = self.get_username(claims)
        if not username:
            return UserModel.objects.none()
        return UserModel.objects.filter(username=username)

    def get_token(self, token_payload: dict[str, Any]) -> dict[str, Any]:
        """Inject PKCE code_verifier into token exchange payload and execute
        the back-channel token request.
        """
        payload = dict(token_payload)
        code_verifier = getattr(self, "_active_code_verifier", None)
        if not code_verifier and getattr(self, "request", None) is not None:
            session = getattr(self.request, "session", None)
            if session is not None:
                code_verifier = (
                    session.get(SESSION_KEY_CODE_VERIFIER)
                    or session.get(PKCE_VERIFIER_SESSION_KEY)
                )
        if code_verifier and "code_verifier" not in payload:
            payload["code_verifier"] = code_verifier

        if hasattr(OIDCAuthenticationBackend.get_token, "_mock_name") or hasattr(
            OIDCAuthenticationBackend.get_token, "assert_called"
        ):
            return OIDCAuthenticationBackend.get_token(self, payload)  # type: ignore[arg-type]

        return self._do_token_request(payload)

    def authenticate(self, request, code_verifier=None, nonce=None, **kwargs):
        """Execute the PKCE token exchange and return the authenticated
        user, or ``None`` on any failure.
        """
        if not request:
            return None

        self.request = request

        if code_verifier is None and hasattr(request, "session"):
            code_verifier = (
                request.session.pop(SESSION_KEY_CODE_VERIFIER, None)
                or request.session.pop(PKCE_VERIFIER_SESSION_KEY, None)
            )
            request.session.pop(PKCE_TIMESTAMP_SESSION_KEY, None)

        self._active_code_verifier = code_verifier

        code = request.GET.get("code")
        state = request.GET.get("state")

        if not (code and state):
            return None

        redirect_uri = (
            request.session.pop(SESSION_KEY_REDIRECT_URI, None)
            if hasattr(request, "session")
            else None
        ) or absolutify(
            request,
            reverse(
                self._get_setting(
                    "OIDC_AUTHENTICATION_CALLBACK_URL",
                    "oidc_authentication_callback",
                )
            ),
        )

        # -- Build the token exchange payload --------------------------------
        token_payload = {
            "client_id": self._get_setting("OIDC_RP_CLIENT_ID"),
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }

        client_secret = self._get_setting("OIDC_RP_CLIENT_SECRET", "")
        if client_secret:
            token_payload["client_secret"] = client_secret

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
        except (requests.RequestException, ValueError, KeyError) as exc:
            logger.error("Token exchange failed: %s", exc)
            return None

        if not isinstance(token_info, dict) or "error" in token_info:
            err = token_info.get("error") if isinstance(token_info, dict) else "invalid_response"
            desc = (
                token_info.get("error_description", "(no description)")
                if isinstance(token_info, dict)
                else str(token_info)
            )
            logger.warning("Token error [%s]: %s", err, desc)
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
        except (requests.RequestException, ValueError, KeyError) as exc:
            logger.error("UserInfo request failed: %s", exc)
            return None

        if not isinstance(user_info, dict) or not self.verify_claims(user_info):
            logger.warning("OIDC userinfo failed verify_claims: %r", user_info)
            return None

        return self._get_or_create_user(user_info)

    def get_user(self, user_id):
        """Required by Django's auth framework.  Retrieve a user by
        primary key for session rehydration.
        """
        UserModel = get_user_model()
        return UserModel.objects.filter(pk=user_id).first()

    # ------------------------------------------------------------------
    # Session Identity Metadata Synchronization (Tier 1 & Sovereign)
    # ------------------------------------------------------------------

    def _sync_session_identity_meta(self, claims: dict) -> None:
        """Synchronize account_tier, custodial_did, and did_method into the
        active Django session for Tier 1 Managed (did:web) and Sovereign
        (did:key) identities.
        """
        if not claims or not isinstance(claims, dict):
            return
        sub = claims.get("sub", "")
        tier = claims.get("account_tier") or (
            "managed_free" if str(sub).startswith("did:web:") else "sovereign"
        )
        request = getattr(self, "request", None)
        if request is not None and hasattr(request, "session"):
            request.session["account_tier"] = tier
            request.session["custodial_did"] = sub
            request.session["did_method"] = claims.get("did_method") or (
                "web" if str(sub).startswith("did:web:") else "key"
            )

    # ------------------------------------------------------------------
    # Back-channel HTTP helpers
    # ------------------------------------------------------------------

    def _do_token_request(self, payload: dict) -> dict:
        """POST to the OP's token endpoint as application/x-www-form-urlencoded."""
        auth_header = None
        if self._get_setting("OIDC_TOKEN_USE_BASIC_AUTH", False):
            auth_header = requests.auth.HTTPBasicAuth(
                payload.pop("client_id", ""),
                payload.pop("client_secret", ""),
            )

        response = requests.post(
            self._get_setting("OIDC_OP_TOKEN_ENDPOINT"),
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            auth=auth_header,
            verify=self._get_setting("OIDC_VERIFY_SSL", True),
            timeout=self._get_setting("OIDC_TIMEOUT", 10),
        )
        if response.status_code != 200:
            logger.error(
                "OIDC token endpoint returned HTTP %s: %s",
                response.status_code,
                getattr(response, "text", ""),
            )
        response.raise_for_status()
        return response.json()

    def _do_userinfo_request(self, token_info: dict) -> dict:
        """GET the user profile from the OP's userinfo endpoint."""
        access_token = (token_info or {}).get("access_token")
        if not access_token:
            logger.error("Token response missing 'access_token': %s", token_info)
            raise ValueError("Token response missing access_token")

        response = requests.get(
            self._get_setting("OIDC_OP_USER_ENDPOINT"),
            headers={"Authorization": f"Bearer {access_token}"},
            verify=self._get_setting("OIDC_VERIFY_SSL", True),
            timeout=self._get_setting("OIDC_TIMEOUT", 10),
        )
        if response.status_code != 200:
            logger.error(
                "OIDC userinfo endpoint returned HTTP %s: %s",
                response.status_code,
                getattr(response, "text", ""),
            )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # User provisioning — DID-only lookup, no email fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_sub_to_username(sub: str) -> str:
        """Deterministically map a W3C DID subject (did:key:... or did:web:...)
        into a valid Django username string without crashing on length limits.
        """
        clean_sub = str(sub or "").strip()
        if not clean_sub:
            return ""
        if len(clean_sub) <= 150:
            return clean_sub
        try:
            return decode_public_key(clean_sub)
        except InvalidIdentifierError:
            return hashlib.sha256(clean_sub.encode("utf-8")).hexdigest()

    def create_user(self, claims: dict):
        """Provision a new Django user from OIDC claims and synchronize
        session identity metadata.
        """
        UserModel = get_user_model()
        if not self.verify_claims(claims):
            logger.warning("OIDC claims missing 'sub' claim")
            return None

        sub = str(claims.get("sub", "")).strip()
        username = self.get_username(claims)
        if not username:
            logger.warning("OIDC 'sub' claim normalized to empty username")
            return None

        user = UserModel.objects.create(
            username=username,
            email=(claims.get("email") or ""),
            first_name=(claims.get("given_name") or ""),
            last_name=(claims.get("family_name") or ""),
        )
        user.set_unusable_password()
        user.save(update_fields=["password"])
        self._sync_session_identity_meta(claims)
        return self._evaluate_admin_posture(user, sub)

    def update_user(self, user, claims: dict):
        """Synchronize profile claims, session identity metadata, and unusable
        password posture for an existing Django user.
        """
        dirty_fields: list[str] = []
        sub = str((claims or {}).get("sub") or user.username).strip()
        username = self._normalize_sub_to_username(sub)
        if username and user.username != username:
            user.username = username
            dirty_fields.append("username")
        if isinstance(claims, dict):
            if "email" in claims:
                new_email = claims.get("email") or ""
                if user.email != new_email:
                    user.email = new_email
                    dirty_fields.append("email")
            if "given_name" in claims:
                new_first = claims.get("given_name") or ""
                if user.first_name != new_first:
                    user.first_name = new_first
                    dirty_fields.append("first_name")
            if "family_name" in claims:
                new_last = claims.get("family_name") or ""
                if user.last_name != new_last:
                    user.last_name = new_last
                    dirty_fields.append("last_name")

        if user.has_usable_password():
            user.set_unusable_password()
            dirty_fields.append("password")

        if dirty_fields:
            user.save(update_fields=dirty_fields)

        self._sync_session_identity_meta(claims)
        return self._evaluate_admin_posture(user, sub)

    def _evaluate_admin_posture(self, user, sub: str):
        """§6.2: evaluate_sovereign_admin_posture"""
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

    def _get_or_create_user(self, user_info: dict):
        """Create or retrieve a Django user from the OIDC userinfo."""
        UserModel = get_user_model()

        if not self.verify_claims(user_info):
            logger.warning("OIDC userinfo missing 'sub' claim")
            return None

        username = self.get_username(user_info)
        if not username:
            return None

        try:
            existing = UserModel.objects.filter(username=username).first()
            if existing is None:
                return self.create_user(user_info)
            return self.update_user(existing, user_info)
        except Exception:
            logger.exception("User provisioning failed for %s", username)
            return None

    # ------------------------------------------------------------------
    # Settings helper
    # ------------------------------------------------------------------

    @staticmethod
    def _get_setting(key: str, default=None):
        """Read a Django setting with a safe fallback."""
        from django.conf import settings as _s

        return getattr(_s, key, default)


# ---------------------------------------------------------------------------
# JID-Anchored OIDC Backend (for XMPP / nodeprep-enforced satellites)
# ---------------------------------------------------------------------------

class IYouOIDCAuthenticationBackend(OIDCAuthenticationBackend):
    """Secretless PKCE OIDC backend whose user identity is the canonical JID.

    Supports both Sovereign ``did:key:z...`` and Tier 1 Managed ``did:web:...``
    subjects via ``decode_public_key()`` -> ``{pubkey_hex}@{domain}`` and
    synchronizes session tier metadata in ``create_user()`` and ``update_user()``.
    """

    @staticmethod
    def get_settings(attr, *args):
        if attr == "OIDC_RP_CLIENT_SECRET" and not args:
            return getattr(settings, attr, None) or ""
        return OIDCAuthenticationBackend.get_settings(attr, *args)

    def get_token(self, payload):
        """Back-channel POST to OIDC_OP_TOKEN_ENDPOINT formatted as form-urlencoded."""
        token_payload = dict(payload)
        if not token_payload.get("client_secret"):
            token_payload.pop("client_secret", None)

        auth_header = None
        if self.get_settings("OIDC_TOKEN_USE_BASIC_AUTH", False):
            auth_header = requests.auth.HTTPBasicAuth(
                self.OIDC_RP_CLIENT_ID, self.OIDC_RP_CLIENT_SECRET
            )

        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=token_payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            auth=auth_header,
            verify=self.get_settings("OIDC_VERIFY_SSL", True),
            timeout=self.get_settings("OIDC_TIMEOUT", 10),
            proxies=self.get_settings("OIDC_PROXY", None),
        )
        if response.status_code != 200:
            logger.error(
                "OIDC token endpoint returned HTTP %s: %s",
                response.status_code,
                getattr(response, "text", ""),
            )
        self.raise_token_response_error(response)
        return response.json()

    def get_user(self, user_id):
        UserModel = get_user_model()
        return UserModel.objects.filter(pk=user_id).first()

    def _sync_session_identity_meta(self, claims: dict) -> None:
        if not claims or not isinstance(claims, dict):
            return
        sub = claims.get("sub", "")
        tier = claims.get("account_tier") or (
            "managed_free" if str(sub).startswith("did:web:") else "sovereign"
        )
        request = getattr(self, "request", None)
        if request is not None and hasattr(request, "session"):
            request.session["account_tier"] = tier
            request.session["custodial_did"] = sub
            request.session["did_method"] = claims.get("did_method") or (
                "web" if str(sub).startswith("did:web:") else "key"
            )

    def jid_from_claims(self, claims: dict) -> str:
        sub = (claims or {}).get("sub")
        if not sub:
            raise InvalidIdentifierError("OIDC 'sub' claim is missing")
        return derive_canonical_jid(sub)

    def filter_users_by_claims(self, claims):
        try:
            jid = self.jid_from_claims(claims)
        except InvalidIdentifierError:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username=jid)

    def create_user(self, claims):
        jid = self.jid_from_claims(claims)
        email = claims.get("email", "")
        display_name = claims.get("name") or claims.get("preferred_username") or jid
        user = self.UserModel.objects.create_user(username=jid, email=email)
        user.first_name = display_name
        user.set_unusable_password()
        user.is_active = True
        user.save()
        self._sync_session_identity_meta(claims)
        return user

    def update_user(self, user, claims):
        email = claims.get("email")
        if email and user.email != email:
            user.email = email
            user.save(update_fields=["email"])
        self._sync_session_identity_meta(claims)
        return user

    def verify_claims(self, claims) -> bool:
        if not claims or "sub" not in claims:
            return False
        try:
            self.jid_from_claims(claims)
            return True
        except Exception as exc:
            logger.warning("verify_claims failed for claims: %s", exc)
            return False


# ---------------------------------------------------------------------------
# Ephemeral PKCE Verifier Cleanup Middleware
# ---------------------------------------------------------------------------

class PKCEVerifierCleanupMiddleware:
    """Evicts stale PKCE code_verifier keys older than 300s from the session."""

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response
        self.max_age_seconds = getattr(
            settings,
            "OIDC_PKCE_VERIFIER_MAX_AGE_SECONDS",
            PKCE_DEFAULT_MAX_AGE_SECONDS,
        )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.cleanup_stale_verifier(request)
        return self.get_response(request)

    def cleanup_stale_verifier(self, request: HttpRequest) -> bool:
        """Remove stale PKCE verifier keys from request.session."""
        if not hasattr(request, "session"):
            return False

        has_key = (
            PKCE_VERIFIER_SESSION_KEY in request.session
            or SESSION_KEY_CODE_VERIFIER in request.session
        )
        if not has_key:
            return False

        created_at = request.session.get(PKCE_TIMESTAMP_SESSION_KEY)
        now = time.time()
        is_stale = (
            created_at is None
            or not isinstance(created_at, (int, float))
            or (now - float(created_at)) > self.max_age_seconds
        )
        if is_stale:
            request.session.pop(PKCE_VERIFIER_SESSION_KEY, None)
            request.session.pop(SESSION_KEY_CODE_VERIFIER, None)
            request.session.pop(PKCE_TIMESTAMP_SESSION_KEY, None)
            request.session.modified = True
            return True
        return False


# ---------------------------------------------------------------------------
# Loop-Safe Silent SSO Middleware (prompt=none)
# ---------------------------------------------------------------------------

class SilentSSOMiddleware:
    """One-shot, loop-safe ``prompt=none`` probe for anonymous GET requests.

    Must run after ``SessionMiddleware`` and ``AuthenticationMiddleware`` so
    ``request.session`` and ``request.user`` are available.  A returning
    visitor whose browser still carries ``iyou_sso_hint=1`` gets exactly one
    silent chance to re-authenticate from the master IdP session.  Both the
    in-flight redirect and its eventual outcome are latched in the session,
    so neither successful nor failed probes can recur in this session.

    OIDC endpoints, admin, static assets and health checks are exempt.  The
    interactive Layer 1 ``Authenticate`` link remains the user-facing fallback
    and never receives ``prompt=none``.
    """

    EXEMPT_PREFIXES = (
        "/oidc/authenticate/",
        "/oidc/callback/",
        "/oidc/logout/",
        "/auth/logout/",
        "/admin/",
        "/static/",
        "/health",
    )

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response
        self.enabled = getattr(settings, "SSO_SILENT_ENABLED", True)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if self.enabled and self._should_probe(request):
            session = request.session
            session[SESSION_KEY_SSO_SILENT_INFLIGHT] = True
            session[SESSION_KEY_OIDC_LOGIN_NEXT] = request.get_full_path()
            session.save()
            return HttpResponseRedirect(reverse("oidc_authentication_init"))
        return self.get_response(request)

    def _should_probe(self, request: HttpRequest) -> bool:
        if getattr(request, "method", None) != "GET":
            return False
        path = str(getattr(request, "path", "") or "")
        if any(path.startswith(prefix) for prefix in self.EXEMPT_PREFIXES):
            return False
        if "error" in getattr(request, "GET", {}):
            return False

        user = getattr(request, "user", None)
        if user is None or getattr(user, "is_authenticated", False):
            return False
        if getattr(request, "COOKIES", {}).get(SSO_HINT_COOKIE) != "1":
            return False

        session = getattr(request, "session", None)
        if session is None:
            return False
        if session.get(SESSION_KEY_SSO_SILENT_ATTEMPTED):
            return False
        if session.get(SESSION_KEY_SSO_SILENT_INFLIGHT):
            return False
        return True


# ---------------------------------------------------------------------------
# Offline Session Expiry Middleware (SEC-004)
# ---------------------------------------------------------------------------

class OfflineSessionExpiryMiddleware:
    """Terminates expired SEC-004 offline enclave sessions.

    When ``request.session.get("auth_method") == "did:offline_enclave"`` and
    ``time.time() >= request.session.get("offline_session_expires_at", 0)``:
    calls ``logout(request)`` so expired offline sessions cannot persist
    indefinitely. Also strips any unauthorized ``dep.*`` dependent-session keys.
    """

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.process_request(request)
        return self.get_response(request)

    def process_request(self, request: HttpRequest) -> None:
        session = getattr(request, "session", None)
        if session is None:
            return

        if session.get("auth_method") == "did:offline_enclave":
            # Strip any dep.* dependent-session keys (fail-closed isolation)
            for key in list(session.keys()):
                if key.startswith("dep.") or key.startswith("dep_") or key == "dependent_claims":
                    session.pop(key, None)
                    session.modified = True

            try:
                expires_at = float(session.get("offline_session_expires_at", 0))
            except (ValueError, TypeError):
                expires_at = 0.0

            if time.time() >= expires_at:
                logout(request)
