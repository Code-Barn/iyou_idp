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
import re
import secrets
import time
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.backends import ModelBackend
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, resolve_url
from django.urls import reverse
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    get_next_url,
    get_random_string,
)
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView,
    OIDCLogoutView,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session key constants
# ---------------------------------------------------------------------------

SESSION_KEY_CODE_VERIFIER = "pkce_code_verifier"
SESSION_KEY_OIDC_LOGIN_NEXT = "oidc_login_next"

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
            request.session["pkce_redirect_uri"] = params["redirect_uri"]

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
# Logout View — Dual GET & POST support to prevent HTTP 405
# ---------------------------------------------------------------------------

class PKCEOIDCLogoutView(OIDCLogoutView):
    """Seamless GET and POST logout view preventing HTTP 405 Method Not Allowed.
    Flushes the local Django session and redirects to LOGOUT_REDIRECT_URL.
    """

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logout(request)
        redirect_url = getattr(settings, "LOGOUT_REDIRECT_URL", "/")
        return redirect(redirect_url)


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

    User lookup filters search strictly on ``username=claims.get('sub')``
    (the root DID string), completely bypassing email string fields to
    prevent unique constraint violations.

    Privilege evaluation reads ``settings.ADMIN_DID`` and calls
    ``set_unusable_password()`` on user creation and on admin elevation to
    enforce passwordless posture (AUTH_FLOW_SPECIFICATION.md §6.2).
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

        self.request = request

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

    def create_user(self, claims: dict):
        """Provision a new Django user from OIDC claims and synchronize
        session identity metadata.
        """
        UserModel = get_user_model()
        sub = (claims or {}).get("sub")
        if not sub:
            logger.warning("OIDC claims missing 'sub' claim")
            return None

        user = UserModel.objects.create(
            username=sub,
            email=claims.get("email", ""),
            first_name=claims.get("given_name", ""),
            last_name=claims.get("family_name", ""),
        )
        user.set_unusable_password()
        user.save(update_fields=["password"])
        self._sync_session_identity_meta(claims)
        return self._evaluate_admin_posture(user, sub)

    def update_user(self, user, claims: dict):
        """Synchronize session identity metadata and evaluate admin posture
        for an existing Django user.
        """
        self._sync_session_identity_meta(claims)
        sub = (claims or {}).get("sub") or user.username
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
        """Create or retrieve a Django user from the OIDC userinfo.

        User lookup is strictly on ``username=sub`` (the root DID
        string).  Email fields are never used as lookup keys to prevent
        unique constraint violations when multiple DID records share an
        email address.

        Sovereign Admin Posture Hook (AUTH_FLOW_SPECIFICATION.md §6.2):
        elevate if ``settings.ADMIN_DID`` matches ``sub``, always
        call ``set_unusable_password()`` on admin, elevation only.
        """
        UserModel = get_user_model()

        sub = user_info.get("sub")
        if not sub:
            logger.warning("OIDC userinfo missing 'sub' claim")
            return None

        username = sub

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
        """Read a Django setting with a safe fallback.

        Unlike the library's import_from_settings(), this never raises
        ImproperlyConfigured when a key is missing — it returns the
        default silently, which is the correct behaviour for optional
        values like OIDC_RP_CLIENT_SECRET.
        """
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
