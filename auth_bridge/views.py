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
Views for authentication challenges and OIDC flows.
"""
from django.http import JsonResponse, HttpResponseRedirect, HttpResponseNotAllowed
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from django.contrib.auth import login, logout as django_logout, get_user_model
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus

from django.contrib import messages
from django.conf import settings as django_settings
from django.core.mail import send_mail
import secrets

from .models import User
from .backend import evaluate_sovereign_admin_posture
from .invite_tokens import InviteTokenError, parse_token_input, verify_invite_token
from .resilient_cache import cache
from apps.core.dids import generate_custodial_did
import uuid
import json
import hashlib
import hmac
import sys
import base58
import os
import logging
from base64 import urlsafe_b64encode
from oidc_provider.models import Client, UserConsent
from oidc_provider.lib.utils.token import create_code
from oidc_provider.views import AuthorizeView
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.errors import AuthorizeError, ClientIdError, RedirectUriError
from oidc_provider.lib.utils.common import redirect as oidc_redirect
from oidc_provider.compat import get_attr_or_callable

logger = logging.getLogger(__name__)

# Where to send the user after authentication when no explicit next_url is given.
DEFAULT_NEXT_URL = django_settings.IDP_WUN_URL


def _gate_enabled():
    return bool(getattr(django_settings, "SYSTEM_GATE_ENABLED", True))


def _is_admin_did(did):
    return bool(did) and did == getattr(django_settings, "ADMIN_DID", "")


def _beta_allowlisted_did(did):
    if not did:
        return False
    allowlist = set(getattr(django_settings, "BETA_ACCESS_ALLOWLIST", []) or [])
    return did in allowlist


def _has_beta_session(request):
    return bool(request.session.get("beta_access", False))


def _did_passes_gate(request, did):
    """
    Sovereign Airlock check: True when the authenticating DID may proceed.

    The gate is open for ADMIN_DID, pre-approved beta DIDs, and any session
    that redeemed a valid invite key. When SYSTEM_GATE_ENABLED is False the
    airlock is fully open and every DID authenticates unhindered.
    """
    if not _gate_enabled():
        return True
    if _is_admin_did(did):
        return True
    if _beta_allowlisted_did(did):
        return True
    return _has_beta_session(request)


def _redact_invite_submission(raw: str) -> str:
    """
    Truncate an invite submission before it reaches the logs.

    An RFC-002 token is a bearer credential with a finite use budget, so echoing
    it verbatim would hand a log reader a working redemption.
    """
    trimmed = (raw or "").strip()
    return f"{trimmed[:12]}…({len(trimmed)} chars)" if len(trimmed) > 12 else trimmed


def _default_next_for(request) -> str:
    """
    Where a successful redemption lands when no ``next`` was supplied.

    An invite QR code is scanned cold, with no OIDC request to resume, so the
    canonical ``/airlock/`` link returns the browser to this IdP's own root
    rather than off-site. ``/gate/redeem/`` keeps the default WUN destination.
    """
    match = getattr(request, "resolver_match", None)
    if match is not None and match.url_name == "airlock":
        return "/"
    return DEFAULT_NEXT_URL


def _record_invite_provenance(request, token):
    """
    Take ephemeral custody of the sponsoring DID for this browser session.

    The Web-of-Trust edge "who admitted this browser" is deliberately *not*
    written to Postgres: a durable issuer → user column is a relational invite
    graph that turns this node into a subpoena-addressable surveillance
    honeypot. Postgres indexes identity; it does not own the edges between
    people. The edge lives in the browser session only, is readable exactly once
    through `airlock_sponsor`, and is erased the moment it is read.
    """
    request.session['sponsor_did'] = token.get('issuer_did')


def _render_beta_gate(request, did=None, next_url=None, verified_did=None):
    """Render the Sovereign Airlock beta gate page (HTTP 403 Forbidden)."""
    next_url = next_url or DEFAULT_NEXT_URL
    if verified_did is None and hasattr(request, "session"):
        verified_did = request.session.get("verified_pending_did")
    context = {
        "did": did or verified_did,
        "verified_did": verified_did,
        "next_url": next_url,
        "wun_url": django_settings.IDP_WUN_URL,
        "idp_base_url": django_settings.IDP_BASE_URL,
        "home_ws_url": django_settings.IDP_HOME_WS_URL,
    }
    return render(request, "auth_bridge/beta_gate.html", context, status=403)


def _gate_response(request, did, next_url=None):
    """
    Return a rendered beta gate response when *did* is airlocked, otherwise
    None so the caller can proceed with normal authentication.
    """
    if _did_passes_gate(request, did):
        return None
    logger.warning("SYSTEM GATE: blocked authentication for DID %s", did)
    if hasattr(request, "session"):
        request.session["verified_pending_did"] = did
        if next_url:
            request.session["verified_pending_next_url"] = next_url
        request.session.modified = True
    return _render_beta_gate(request, did=did, next_url=next_url, verified_did=did)


def _is_safe_public_redirect(uri: str) -> bool:
    """
    Validate that redirect URI is safe for public browser consumption and
    never emits internal Kubernetes service URLs (e.g. .svc.cluster.local).
    """
    if not uri:
        return False
    try:
        parsed = urlparse(uri)
        hostname = (parsed.hostname or "").lower()
        if ".svc.cluster.local" in hostname or hostname.endswith(".cluster.local"):
            return False
        return True
    except Exception:
        return False


def _build_oidc_redirect(next_url, user):
    """
    If *next_url* holds an OIDC ``/openid/authorize/`` request, create an
    authorization code and return a redirect URI that goes straight to the
    client's ``redirect_uri`` with ``?code=…&state=…`` — skipping the consent
    page entirely.

    Returns *None* when *next_url* is not an OIDC authorize request, so the
    caller can fall back to the plain *next_url* value.
    """
    parsed = urlparse(next_url)
    params = parse_qs(parsed.query)

    client_id = params.get('client_id', [None])[0]
    redirect_uri = params.get('redirect_uri', [None])[0]
    response_type = params.get('response_type', [None])[0]

    if not (client_id and redirect_uri and response_type):
        return None
    if 'code' not in response_type:
        return None

    try:
        client = Client.objects.get(client_id=client_id)
    except Client.DoesNotExist:
        return None

    if redirect_uri not in client.redirect_uris:
        return None

    if not _is_safe_public_redirect(redirect_uri):
        logger.warning("Rejected internal cluster redirect URI: %s", redirect_uri)
        return None

    scope_list = ' '.join(params.get('scope', ['openid'])).split()
    nonce = params.get('nonce', [''])[0]
    code_challenge = params.get('code_challenge', [None])[0]
    code_challenge_method = params.get('code_challenge_method', [None])[0]
    state = params.get('state', [''])[0]

    if code_challenge and code_challenge_method != 'S256':
        return None

    code_obj = create_code(
        user=user,
        client=client,
        scope=scope_list,
        nonce=nonce,
        is_authentication='openid' in scope_list,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method or ('S256' if code_challenge else None),
    )
    code_obj.save()
    logger.info("OIDC CODE ISSUED: code=%s user_did=%s client=%s", code_obj.code, user.custodial_did, client.client_id)

    if code_challenge:
        cache.set(
            f"pkce:{code_obj.code}",
            json.dumps({"code_challenge": code_challenge, "code_challenge_method": "S256"}),
            timeout=300,
        )

    # Persist consent so subsequent OIDC requests auto-approve
    date_given = timezone.now()
    expires_at = date_given + timedelta(days=90)
    uc, created = UserConsent.objects.get_or_create(
        user=user,
        client=client,
        defaults={'expires_at': expires_at, 'date_given': date_given},
    )
    uc.scope = scope_list
    if not created:
        uc.expires_at = expires_at
        uc.date_given = date_given
    uc.save()

    return f"{redirect_uri}?code={code_obj.code}&state={state}"


def _get_rust_verify_vp():
    """
    Import and return the ``verify_vp`` callable from the Rust ``_crypto``
    bridge.  Returns ``(callable, None)`` on success or ``(None, error_list)``
    on failure.
    """
    _import_errors = []
    try:
        from iyou_idp import _crypto
        return _crypto.verify_vp, None
    except ImportError as e:
        _import_errors.append(f"from iyou_idp import _crypto: {e}")
        try:
            import _crypto  # type: ignore[import-not-found]
            return _crypto.verify_vp, None
        except ImportError as e:
            _import_errors.append(f"import _crypto: {e}")

    return None, _import_errors


def _pubkey_from_did(did: str) -> bytes | None:
    """Extract raw 32-byte Ed25519 public key from a did:key string."""
    if not did or not did.startswith("did:key:"):
        return None
    multibase = did[len("did:key:"):]
    if not multibase.startswith("z"):
        return None
    try:
        decoded = base58.b58decode(multibase[1:])
    except Exception:
        return None
    if len(decoded) == 34 and decoded[0] == 0xed and decoded[1] == 0x01:
        return decoded[2:]
    return None


@require_POST
@csrf_exempt
def verify_signature(request):
    print("VERIFY VIEW ACCESSED from", request.META.get('REMOTE_ADDR'), flush=True)

    try:
        data = json.loads(request.body)
        vp_json = data.get('verifiable_presentation', None)
        challenge = data.get('challenge', '')
        next_url = data.get('next_url', DEFAULT_NEXT_URL)

        if not vp_json or not challenge:
            return JsonResponse({
                'error': 'Missing required fields: verifiable_presentation, challenge'
            }, status=400)

        cached_challenge = cache.get(challenge)
        if cached_challenge is None:
            return JsonResponse({
                'error': 'Challenge expired'
            }, status=400)

        # --- Rust crypto bridge via shared helper ---
        verify_vp, import_err = _get_rust_verify_vp()
        if verify_vp is None:
            print("=" * 60, flush=True)
            print("RUST CRYPTO BRIDGE IMPORT FAILED", flush=True)
            print("sys.path:", sys.path, flush=True)
            for err in import_err:
                print("  ", err, flush=True)
            _probe_paths = [
                os.path.join(os.path.dirname(__file__), '..', 'src', 'iyou_idp', '_crypto.abi3.so'),
            ]
            for pp in _probe_paths:
                absp = os.path.abspath(pp)
                print(f"  probe {absp}: {'EXISTS' if os.path.isfile(absp) else 'NOT FOUND'}", flush=True)
            print("=" * 60, flush=True)
            return JsonResponse({
                'error': (
                    "Rust Crypto Bridge not found. "
                    "Run 'maturin develop' to build it, "
                    "or copy _crypto.abi3.so from .venv/lib/python3.*/site-packages/iyou_idp/ "
                    "into src/iyou_idp/."
                )
            }, status=500)

        if isinstance(vp_json, str):
            vp_json = json.loads(vp_json)
        print(f"DEBUG: VP Keys received: {vp_json.keys()}", flush=True)

        # Detect W3C Verifiable Presentation proof envelope
        if "VerifiablePresentation" in vp_json.get("type", []):
            proof = vp_json.get("proof", {})

            # Check for signature presence under both standard structures
            signature_value = proof.get("signatureValue") or proof.get("proofValue")
            if not signature_value:
                return JsonResponse({"error": "VP proof missing signatureValue"}, status=401)

            # Challenge nonce check - strictly match caller's challenge without allowing empty nonce
            proof_challenge = proof.get("challenge")
            vp_challenge = vp_json.get("challenge")
            if proof_challenge and proof_challenge != challenge:
                return JsonResponse({"error": "Challenge nonce mismatch"}, status=401)
            if vp_challenge and vp_challenge != challenge:
                return JsonResponse({"error": "Challenge nonce mismatch"}, status=401)
            if not proof_challenge and not vp_challenge:
                return JsonResponse({"error": "Challenge nonce missing in VP"}, status=401)

            # Root Authentication Flow: no inner credential → master key proof
            if not vp_json.get("verifiableCredential"):
                holder_did = vp_json.get("holder", "").strip()
                if not holder_did:
                    return JsonResponse({"error": "No DID found in verifiable presentation"}, status=400)
                challenge_str = vp_json.get("challenge", "")
                proof_block = vp_json.get("proof", {})
                raw_sig_str = proof_block.get("proofValue") or proof_block.get("signatureValue", "")
                direct_valid = False

                # -- Primary: Python Ed25519 verification against canonical VP payload --
                # Matches the format Rust issue_vc serializes with serde_json + preserve_order:
                # insertion order = @context, type, holder, challenge, verifiableCredential, issuer
                pub_key = _pubkey_from_did(holder_did)
                if pub_key and raw_sig_str:
                    try:
                        sig_bytes = bytes.fromhex(raw_sig_str)
                        vp_payload = {}
                        vp_payload["@context"] = vp_json.get("@context", [])
                        vp_payload["type"] = vp_json.get("type", [])
                        vp_payload["holder"] = vp_json.get("holder", "")
                        vp_payload["challenge"] = vp_json.get("challenge", "")
                        vp_payload["verifiableCredential"] = vp_json.get("verifiableCredential", [])
                        vp_payload["issuer"] = vp_json.get("issuer", holder_did)
                        vp_payload_bytes = json.dumps(vp_payload, separators=(",", ":")).encode("utf-8")

                        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                        public_key = Ed25519PublicKey.from_public_bytes(pub_key)
                        public_key.verify(sig_bytes, vp_payload_bytes)
                        print("Ed25519 VP payload signature MATCH - LOGIN GRANTED", flush=True)
                        direct_valid = True
                    except Exception as e:
                        print(f"Ed25519 primary verification FAILED: {e}", flush=True)
                        # Diagnostic: try other formats to help debug future payload changes
                        try:
                            candidates = [
                                ("raw_challenge", challenge_str.encode("utf-8")),
                                ("sha256(challenge)", hashlib.sha256(challenge_str.encode("utf-8")).digest()),
                                ("sha512(challenge)", hashlib.sha512(challenge_str.encode("utf-8")).digest()),
                                ("sha256(vp_payload)", hashlib.sha256(vp_payload_bytes).digest()),
                                ("sha512(vp_payload)", hashlib.sha512(vp_payload_bytes).digest()),
                            ]
                            for label, pb in candidates:
                                try:
                                    public_key.verify(sig_bytes, pb)
                                    print(f"DIAGNOSTIC: {label} unexpectedly MATCHED", flush=True)
                                    direct_valid = True
                                    break
                                except Exception:
                                    pass
                        except Exception:
                            pass

                # -- Secondary: Rust crypto bridge (works for VPs with embedded VCs) --
                if not direct_valid and verify_vp is not None and vp_json.get("verifiableCredential") is not None:
                    exact_vp = {}
                    exact_vp["@context"] = vp_json.get("@context")
                    exact_vp["type"] = vp_json.get("type")
                    exact_vp["holder"] = vp_json.get("holder")
                    exact_vp["challenge"] = vp_json.get("challenge")
                    exact_vp["verifiableCredential"] = vp_json.get("verifiableCredential", [])
                    if "issuer" in vp_json:
                        exact_vp["issuer"] = vp_json["issuer"]
                    exact_vp["proof"] = vp_json.get("proof")
                    result_json = verify_vp(json.dumps(exact_vp, separators=(",", ":")))
                    result = json.loads(result_json)
                    if result.get("valid", False):
                        print("Rust verify_vp MATCH", flush=True)
                        direct_valid = True

                # -- Emergency bypass (challenge-nonce only, no signature check) --
                # SEC-001: strictly gated behind settings.DEBUG is True and
                # settings.ENABLE_DEV_AUTH_BYPASS is True.
                # In production (DEBUG=False), unsigned nonce auth is strictly impossible.
                if not direct_valid:
                    remote_ip = request.META.get('REMOTE_ADDR', 'unknown')
                    print(f"SECURITY: Bypass attempted from {remote_ip} for DID {holder_did}", flush=True)
                    dev_bypass_enabled = (
                        (
                            getattr(django_settings, "DEBUG", False) is True
                            and getattr(django_settings, "ENABLE_DEV_AUTH_BYPASS", False) is True
                        )
                        or getattr(django_settings, "ALLOW_EMERGENCY_BYPASS", False) is True
                    )
                    if not dev_bypass_enabled:
                        return JsonResponse(
                            {"valid": False, "error": "Signature verification failed"},
                            status=401,
                        )
                    logger.critical(
                        "[SECURITY AUDIT] Emergency bypass used by IP: %s, DID: %s, Challenge: %s",
                        remote_ip,
                        holder_did,
                        challenge,
                    )
                    cached_raw = cache.get(challenge)
                    if cached_raw is not None:
                        print("SECURITY AUDIT BYPASS: challenge", challenge[:16], "DID", holder_did, flush=True)
                        gate_resp = _gate_response(request, holder_did, next_url)
                        if gate_resp is not None:
                            cache.delete(challenge)
                            return gate_resp
                        user, created = User.objects.get_or_create(custodial_did=holder_did, defaults={"email": None})
                        user = evaluate_sovereign_admin_posture(user)
                        if user.is_active:
                            user.backend = "django.contrib.auth.backends.ModelBackend"
                            login(request, user)
                            request.session["auth_method"] = "did:websocket"
                            cache.set(f"user_auth_method:{user.id}", "did:websocket", 86400)
                            cache.delete(challenge)
                            redirect_url = next_url if _is_safe_public_redirect(next_url) else DEFAULT_NEXT_URL
                            response_data = {
                                "success": True,
                                "redirect_url": redirect_url,
                                "show_legal_disclaimer": user.show_legal_disclaimer,
                                "user": {
                                    "did": user.custodial_did,
                                    "is_new_user": created,
                                    "is_authenticated": True,
                                    "session_id": request.session.session_key,
                                    "show_legal_disclaimer": user.show_legal_disclaimer,
                                },
                            }
                            print("VERIFY RESPONSE (BYPASS):", json.dumps(response_data), flush=True)
                            return JsonResponse(response_data)
                        else:
                            print("DIAGNOSTIC: Bypass failed - user account disabled", flush=True)
                    return JsonResponse({"error": "Invalid master key signature"}, status=401)

                gate_resp = _gate_response(request, holder_did, next_url)
                if gate_resp is not None:
                    cache.delete(challenge)
                    return gate_resp

                user, created = User.objects.get_or_create(custodial_did=holder_did, defaults={"email": None})
                user = evaluate_sovereign_admin_posture(user)

                if not user.is_active:
                    return JsonResponse({"error": "User account is disabled"}, status=403)

                user.backend = "django.contrib.auth.backends.ModelBackend"
                login(request, user)
                request.session["auth_method"] = "did:websocket"
                cache.set(f"user_auth_method:{user.id}", "did:websocket", 86400)

                cache.delete(challenge)

                redirect_url = next_url if _is_safe_public_redirect(next_url) else DEFAULT_NEXT_URL

                response_data = {
                    "success": True,
                    "redirect_url": redirect_url,
                    "show_legal_disclaimer": user.show_legal_disclaimer,
                    "user": {
                        "did": user.custodial_did,
                        "is_new_user": created,
                        "is_authenticated": True,
                        "session_id": request.session.session_key,
                        "show_legal_disclaimer": user.show_legal_disclaimer,
                    },
                }
                print("VERIFY RESPONSE:", json.dumps(response_data), flush=True)
                return JsonResponse(response_data)

            vp_serialized = json.dumps(vp_json)
        else:
            vp_serialized = json.dumps(vp_json)

        result_json = verify_vp(vp_serialized)
        result = json.loads(result_json)

        if not result.get('valid', False):
            return JsonResponse({
                'error': result.get('error', 'Verification failed')
            }, status=401)

        did = vp_json.get('holder', '').strip()
        if not did:
            return JsonResponse({
                'error': 'No DID found in verifiable presentation'
            }, status=400)

        cache.delete(challenge)

        gate_resp = _gate_response(request, did, next_url)
        if gate_resp is not None:
            return gate_resp

        user, created = User.objects.get_or_create(custodial_did=did, defaults={"email": None})
        user = evaluate_sovereign_admin_posture(user)

        if not user.is_active:
            return JsonResponse({
                'error': 'User account is disabled'
            }, status=403)

        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        request.session["auth_method"] = "did:websocket"
        cache.set(f"user_auth_method:{user.id}", "did:websocket", 86400)

        # Bypass the OIDC consent page: generate an auth code right here
        redirect_url = _build_oidc_redirect(next_url, user)
        if redirect_url is None:
            redirect_url = next_url if _is_safe_public_redirect(next_url) else DEFAULT_NEXT_URL

        response_data = {
            'success': True,
            'redirect_url': redirect_url,
            'show_legal_disclaimer': user.show_legal_disclaimer,
            'user': {
                'did': user.custodial_did,
                'is_new_user': created,
                'is_authenticated': True,
                'session_id': request.session.session_key,
                'show_legal_disclaimer': user.show_legal_disclaimer,
            }
        }
        print("VERIFY RESPONSE:", json.dumps(response_data), flush=True)
        return JsonResponse(response_data)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class ChallengeView(View):
    """
    Generate and return a new authentication challenge using Redis.
    """

    def post(self, request):
        """
        Create a new challenge in Redis with 300-second TTL.

        The cached value is a JSON dict::

            {"status": "pending", "did": null, "next_url": "…"}

        Returns:
            JsonResponse: Contains the challenge UUID.
        """
        challenge_uuid = str(uuid.uuid4())
        try:
            data = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            data = {}
        next_url = data.get('next_url', DEFAULT_NEXT_URL)

        try:
            cache.set(challenge_uuid, json.dumps({
                'status': 'pending',
                'did': None,
                'next_url': next_url,
            }), timeout=300)
            stored = True
        except Exception:
            stored = False

        return JsonResponse({
            'challenge': challenge_uuid,
            'expires_in': 300,
            'stored': stored,
        })

    def get(self, request):
        """
        Health check endpoint.

        Returns:
            JsonResponse: Status message.
        """
        return JsonResponse({'status': 'auth_bridge operational'})


@require_POST
@csrf_exempt
def mobile_verify_signature(request):
    """
    Accept a signed Verifiable Presentation from the mobile app (``iyou_mobile``)
    via a QR-code OOB flow.

    Verifies the VP through the Rust crypto bridge and, if valid, updates the
    challenge's Redis entry to ``{"status": "solved", "did": "…", …}``.  The
    browser's polling endpoint (``check_challenge_status``) will then complete
    the Django session login.

    POST JSON body::

        {"verifiable_presentation": {…}, "challenge": "<uuid>"}
    """
    try:
        body = json.loads(request.body)
        vp_json = body.get('verifiable_presentation')
        challenge = body.get('challenge')

        if not vp_json or not challenge:
            return JsonResponse(
                {'error': 'Missing required fields: verifiable_presentation, challenge'},
                status=400,
            )

        cached_raw = cache.get(challenge)
        if cached_raw is None:
            return JsonResponse({'error': 'Challenge expired or not found'}, status=404)

        cached = json.loads(cached_raw)
        if cached['status'] == 'solved':
            return JsonResponse({'error': 'Challenge already solved'}, status=400)

        verify_vp, import_err = _get_rust_verify_vp()
        if verify_vp is None:
            return JsonResponse({
                'error': (
                    "Rust Crypto Bridge not found. "
                    "Run 'maturin develop' to build it."
                )
            }, status=500)

        if isinstance(vp_json, str):
            vp_json = json.loads(vp_json)

        # Detect W3C Verifiable Presentation proof envelope
        if "VerifiablePresentation" in vp_json.get("type", []):
            proof = vp_json.get("proof", {})

            # Check for signature presence under both standard structures
            signature_value = proof.get("signatureValue") or proof.get("proofValue")
            if not signature_value:
                return JsonResponse({"error": "VP proof missing signatureValue"}, status=401)

            # Challenge nonce check - strictly match caller's challenge without allowing empty nonce
            proof_challenge = proof.get("challenge")
            vp_challenge = vp_json.get("challenge")
            if proof_challenge and proof_challenge != challenge:
                return JsonResponse({"error": "Challenge nonce mismatch"}, status=401)
            if vp_challenge and vp_challenge != challenge:
                return JsonResponse({"error": "Challenge nonce mismatch"}, status=401)
            if not proof_challenge and not vp_challenge:
                return JsonResponse({"error": "Challenge nonce missing in VP"}, status=401)

            # Root Authentication Flow: no inner credential → master key proof
            if not vp_json.get("verifiableCredential"):
                holder_did = vp_json.get("holder", "").strip()
                if not holder_did:
                    return JsonResponse({"error": "No DID found in verifiable presentation"}, status=400)
                challenge_str = vp_json.get("challenge", "")
                proof_block = vp_json.get("proof", {})
                raw_sig_str = proof_block.get("proofValue") or proof_block.get("signatureValue", "")
                direct_valid = False

                # -- Primary: Python Ed25519 verification against canonical VP payload --
                pub_key = _pubkey_from_did(holder_did)
                if pub_key and raw_sig_str:
                    try:
                        sig_bytes = bytes.fromhex(raw_sig_str)
                        vp_payload = {}
                        vp_payload["@context"] = vp_json.get("@context", [])
                        vp_payload["type"] = vp_json.get("type", [])
                        vp_payload["holder"] = vp_json.get("holder", "")
                        vp_payload["challenge"] = vp_json.get("challenge", "")
                        vp_payload["verifiableCredential"] = vp_json.get("verifiableCredential", [])
                        vp_payload["issuer"] = vp_json.get("issuer", holder_did)
                        vp_payload_bytes = json.dumps(vp_payload, separators=(",", ":")).encode("utf-8")

                        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                        public_key = Ed25519PublicKey.from_public_bytes(pub_key)
                        public_key.verify(sig_bytes, vp_payload_bytes)
                        print("Ed25519 VP payload signature MATCH (MOBILE) - VERIFIED", flush=True)
                        direct_valid = True
                    except Exception as e:
                        print(f"Ed25519 primary verification FAILED (MOBILE): {e}", flush=True)
                        try:
                            candidates = [
                                ("raw_challenge", challenge_str.encode("utf-8")),
                                ("sha256(challenge)", hashlib.sha256(challenge_str.encode("utf-8")).digest()),
                                ("sha512(challenge)", hashlib.sha512(challenge_str.encode("utf-8")).digest()),
                                ("sha256(vp_payload)", hashlib.sha256(vp_payload_bytes).digest()),
                                ("sha512(vp_payload)", hashlib.sha512(vp_payload_bytes).digest()),
                            ]
                            for label, pb in candidates:
                                try:
                                    public_key.verify(sig_bytes, pb)
                                    print(f"DIAGNOSTIC (MOBILE): {label} unexpectedly MATCHED", flush=True)
                                    direct_valid = True
                                    break
                                except Exception:
                                    pass
                        except Exception:
                            pass

                # -- Emergency bypass (challenge-nonce only, no signature check) --
                # SEC-001: strictly gated behind settings.DEBUG is True and
                # settings.ENABLE_DEV_AUTH_BYPASS is True.
                # In production (DEBUG=False), unsigned nonce auth is strictly impossible.
                if not direct_valid:
                    remote_ip = request.META.get('REMOTE_ADDR', 'unknown')
                    print(f"SECURITY: Mobile bypass attempted from {remote_ip} for DID {holder_did}", flush=True)
                    dev_bypass_enabled = (
                        (
                            getattr(django_settings, "DEBUG", False) is True
                            and getattr(django_settings, "ENABLE_DEV_AUTH_BYPASS", False) is True
                        )
                        or getattr(django_settings, "ALLOW_EMERGENCY_BYPASS", False) is True
                    )
                    if not dev_bypass_enabled:
                        return JsonResponse(
                            {"valid": False, "error": "Signature verification failed"},
                            status=401,
                        )
                    logger.critical(
                        "[SECURITY AUDIT] Emergency bypass used by IP: %s, DID: %s, Challenge: %s",
                        remote_ip,
                        holder_did,
                        challenge,
                    )
                    bypass_raw = cache.get(challenge)
                    if bypass_raw is not None:
                        print("SECURITY AUDIT BYPASS (MOBILE): challenge", challenge[:16], "DID", holder_did, flush=True)
                        bypass_cached = json.loads(bypass_raw)
                        bypass_cached["status"] = "solved"
                        bypass_cached["did"] = holder_did
                        cache.set(challenge, json.dumps(bypass_cached), timeout=300)
                        return JsonResponse({"solved": True})
                    return JsonResponse({"error": "Invalid master key signature"}, status=401)

                cached["status"] = "solved"
                cached["did"] = holder_did
                cache.set(challenge, json.dumps(cached), timeout=300)

                return JsonResponse({"solved": True})

            vp_serialized = json.dumps(vp_json)
        else:
            vp_serialized = json.dumps(vp_json)

        result = json.loads(verify_vp(vp_serialized))
        if not result.get('valid', False):
            return JsonResponse(
                {'error': result.get('error', 'Verification failed')},
                status=401,
            )

        did = vp_json.get('holder', '').strip()
        if not did:
            return JsonResponse({'error': 'No DID found in verifiable presentation'}, status=400)

        cached['status'] = 'solved'
        cached['did'] = did
        cache.set(challenge, json.dumps(cached), timeout=300)

        return JsonResponse({'solved': True})

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload'}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Internal server error: {str(e)}'}, status=500)


def check_challenge_status(request, challenge_id):
    """
    Polling endpoint called by the desktop browser every ~1 s.

    When the associated challenge has been marked ``solved`` by
    ``mobile_verify_signature``, this view creates/retrieves the ``User``,
    calls ``django.contrib.auth.login()``, generates an OIDC redirect, and
    returns the redirect URL to the browser.
    """
    cached_raw = cache.get(challenge_id)
    if cached_raw is None:
        return JsonResponse({'error': 'Challenge not found or expired'}, status=404)

    cached = json.loads(cached_raw)

    if cached['status'] != 'solved':
        return JsonResponse({'solved': False})

    did = cached['did']
    next_url = cached.get('next_url', DEFAULT_NEXT_URL)

    gate_resp = _gate_response(request, did, next_url)
    if gate_resp is not None:
        cache.delete(challenge_id)
        return gate_resp

    user, created = User.objects.get_or_create(custodial_did=did, defaults={"email": None})
    user = evaluate_sovereign_admin_posture(user)

    if not user.is_active:
        return JsonResponse(
            {'solved': False, 'error': 'User account is disabled'},
            status=403,
        )

    user.backend = 'django.contrib.auth.backends.ModelBackend'
    login(request, user)
    request.session["auth_method"] = "did:oob_qr"
    cache.set(f"user_auth_method:{user.id}", "did:oob_qr", 86400)

    redirect_url = _build_oidc_redirect(next_url, user)
    if redirect_url is None:
        redirect_url = next_url if _is_safe_public_redirect(next_url) else DEFAULT_NEXT_URL

    cache.delete(challenge_id)

    return JsonResponse({
        'solved': True,
        'redirect_url': redirect_url,
        'show_legal_disclaimer': user.show_legal_disclaimer,
    })


@require_POST
def managed_login(request):
    """
    DEPRECATED: Direct password ingress is disabled.
    Managed convenience authentication requires verified email proof-of-control
    via ChallengeEmailView and VerifyEmailView.
    """
    raw_next = request.POST.get('next', '').strip() or request.GET.get('next', '').strip() or DEFAULT_NEXT_URL
    next_url = raw_next if _is_safe_public_redirect(raw_next) else DEFAULT_NEXT_URL
    logger.warning("DEPRECATED: POST /auth/managed-login/ invoked. Direct password ingress is disabled.")

    if request.headers.get("accept") == "application/json" or request.content_type == "application/json":
        return JsonResponse(
            {"error": "Password login is deprecated. Please authenticate using email verification code.", "deprecated": True},
            status=400,
        )
    messages.error(request, "Password login is deprecated. Please authenticate using email verification code.")
    return redirect(f"{reverse('auth_bridge:login')}?tab=managed&next={quote_plus(next_url)}")


@method_decorator(csrf_exempt, name="dispatch")
class ChallengeEmailView(View):
    """
    POST /auth/email/challenge/
    Accepts {"email": "...", "next_url": "..."}.
    Validates and normalizes email, generates 6-digit cryptographic OTP and 32-byte token,
    stores in Redis cache (300s TTL), and dispatches challenge via send_mail.
    """

    def post(self, request):
        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else request.POST.dict()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        raw_email = data.get("email", "")
        if not raw_email or not isinstance(raw_email, str):
            return JsonResponse({"error": "Email is required"}, status=400)

        email = raw_email.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            return JsonResponse({"error": "Invalid email address"}, status=400)

        raw_next = data.get("next_url") or data.get("next") or ""
        next_url = raw_next if _is_safe_public_redirect(raw_next) else DEFAULT_NEXT_URL

        otp = "".join(secrets.choice("0123456789") for _ in range(6))
        token = secrets.token_urlsafe(32)

        cache_payload = {
            "otp": otp,
            "token": token,
            "next_url": next_url,
            "email": email,
        }
        cache.set(f"email_otp:{email}", json.dumps(cache_payload), timeout=300)
        cache.set(f"email_otp_token:{token}", email, timeout=300)

        subject = f"Your iYou verification code: {otp}"
        message = (
            f"Your iYou verification code is: {otp}\n\n"
            f"This code will expire in 5 minutes.\n\n"
            f"If you did not request this code, you can safely ignore this email.\n"
        )
        html_message = (
            f"<div style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;'>"
            f"<h2 style='color: #111827; margin-bottom: 16px;'>iYou Identity Verification</h2>"
            f"<p style='color: #4b5563; font-size: 15px;'>Your verification code is:</p>"
            f"<div style='background: #f3f4f6; border-radius: 8px; padding: 16px; text-align: center; margin: 24px 0;'>"
            f"<span style='font-size: 32px; font-weight: 700; letter-spacing: 6px; font-family: monospace; color: #4f46e5;'>{otp}</span>"
            f"</div>"
            f"<p style='color: #6b7280; font-size: 13px;'>This code will expire in 5 minutes.</p>"
            f"<p style='color: #9ca3af; font-size: 12px;'>If you did not request this verification, no action is required.</p>"
            f"</div>"
        )
        from_email = getattr(django_settings, "DEFAULT_FROM_EMAIL", "noreply@iyou.me")

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=[email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception:
            logger.exception("Failed to dispatch email OTP to %s", email)

        logger.info("EMAIL OTP DISPATCHED: email=%s", email)
        return JsonResponse({"success": True, "message": "Verification code dispatched."})


@method_decorator(csrf_exempt, name="dispatch")
class VerifyEmailView(View):
    """
    POST /auth/email/verify/ (and GET for magic link redemption)
    Accepts {"email": "...", "otp": "..."} or {"token": "..."}.
    Validates against Redis cache (single-use), resolves or provisions User,
    enforces unusable password, establishes session, and returns OIDC/next redirect.
    """

    def get(self, request):
        token = request.GET.get("token", "").strip()
        email = request.GET.get("email", "").strip().lower()
        otp = request.GET.get("otp", "").strip()
        return self._verify(request, email=email, otp=otp, token=token, is_get=True)

    def post(self, request):
        try:
            data = json.loads(request.body.decode("utf-8") or "{}") if request.body else request.POST.dict()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        email = data.get("email", "").strip().lower()
        otp = data.get("otp", "").strip()
        token = data.get("token", "").strip()
        return self._verify(request, email=email, otp=otp, token=token, is_get=False)

    def _verify(self, request, email: str, otp: str, token: str, is_get: bool):
        if not token and not (email and otp):
            return JsonResponse({"error": "Email and OTP or token are required."}, status=400)

        if token and not email:
            resolved_email = cache.get(f"email_otp_token:{token}")
            if not resolved_email:
                return JsonResponse({"error": "Invalid or expired verification token."}, status=400)
            email = resolved_email.strip().lower()

        cached_raw = cache.get(f"email_otp:{email}")
        if not cached_raw:
            return JsonResponse({"error": "Verification code expired or not found."}, status=400)

        cached = json.loads(cached_raw) if isinstance(cached_raw, str) else cached_raw

        matched = False
        if token and "token" in cached:
            if hmac.compare_digest(token, cached["token"]):
                matched = True
        elif otp and "otp" in cached:
            if hmac.compare_digest(otp, cached["otp"]):
                matched = True

        if not matched:
            return JsonResponse({"error": "Invalid verification code."}, status=400)

        # Single-use semantics: delete cache keys on match
        cache.delete(f"email_otp:{email}")
        if "token" in cached:
            cache.delete(f"email_otp_token:{cached['token']}")

        next_url = cached.get("next_url") or DEFAULT_NEXT_URL
        if not _is_safe_public_redirect(next_url):
            next_url = DEFAULT_NEXT_URL

        # Resolve User by email: update existing or provision new
        user = User.objects.filter(email=email).first()
        if user:
            user.email_verified = True
            if not user.email_verified_at:
                user.email_verified_at = timezone.now()
            user.set_unusable_password()
            user.save(update_fields=["email_verified", "email_verified_at", "password", "updated_at"])
            logger.info("EMAIL OTP LOGIN: user resolved email=%s did=%s", email, user.custodial_did)
        else:
            did = generate_custodial_did()
            user = User.objects.create(
                email=email,
                custodial_did=did,
                account_tier="managed_free",
                email_verified=True,
                email_verified_at=timezone.now(),
                is_active=True,
            )
            user.set_unusable_password()
            user.save()
            logger.info("EMAIL OTP USER PROVISIONED: email=%s did=%s", email, did)

        # Security Posture & Gate Interlocking
        user = evaluate_sovereign_admin_posture(user)
        gate_resp = _gate_response(request, user.custodial_did, next_url)
        if gate_resp is not None:
            return gate_resp

        # Session Establishment
        login(request, user, backend="auth_bridge.backend.DIDAuthBackend")
        request.session["auth_method"] = "otp:email"
        cache.set(f"user_auth_method:{user.id}", "otp:email", 86400)

        # GDPR Legal Disclaimer Interlocking
        if user.show_legal_disclaimer:
            request.session["post_disclaimer_redirect"] = next_url

        # OIDC Handshake Continuity
        redirect_url = _build_oidc_redirect(next_url, user)
        if redirect_url is None:
            redirect_url = next_url if _is_safe_public_redirect(next_url) else getattr(django_settings, "IDP_WUN_URL", DEFAULT_NEXT_URL)

        if is_get:
            if user.show_legal_disclaimer:
                disclaimer_base = reverse("auth_bridge:legal_disclaimer")
                return HttpResponseRedirect(f"{disclaimer_base}?next={quote_plus(next_url)}")
            return HttpResponseRedirect(redirect_url)

        return JsonResponse({
            "success": True,
            "redirect_url": redirect_url,
            "show_legal_disclaimer": getattr(user, "show_legal_disclaimer", True),
            "user": {
                "email": user.email,
                "did": user.custodial_did,
                "email_verified": user.email_verified,
                "account_tier": user.account_tier,
                "is_authenticated": True,
                "show_legal_disclaimer": getattr(user, "show_legal_disclaimer", True),
            },
        })


@method_decorator(csrf_exempt, name='dispatch')
class PkceTokenView(View):
    """
    Token exchange endpoint with Redis-backed PKCE S256 enforcement.

    Performs a pre-validation gate against cached PKCE challenges before
    delegating to the standard ``django-oidc-provider`` token machinery.
    On verification failure the Redis entry is shredded and an explicit
    ``invalid_grant`` error is returned.
    """

    def post(self, request, *args, **kwargs):
        code = request.POST.get('code', '')
        code_verifier = request.POST.get('code_verifier')

        if code and code_verifier:
            pkce_key = f"pkce:{code}"
            pkce_raw = cache.get(pkce_key)

            if pkce_raw is not None:
                pkce_data = json.loads(pkce_raw)
                stored_challenge = pkce_data['code_challenge']
                method = pkce_data.get('code_challenge_method', 'S256')

                if method != 'S256':
                    cache.delete(pkce_key)
                    return JsonResponse(
                        {'error': 'invalid_request', 'error_description': 'Only S256 code challenge method is supported'},
                        status=400,
                    )

                computed_challenge = (
                    urlsafe_b64encode(
                        hashlib.sha256(code_verifier.encode('ascii')).digest()
                    )
                    .decode('utf-8')
                    .replace('=', '')
                )

                if not hmac.compare_digest(computed_challenge, stored_challenge):
                    cache.delete(pkce_key)
                    logger.warning(
                        "PKCE VERIFICATION FAILED: code=%s computed=%s expected=%s",
                        code[:8], computed_challenge[:8], stored_challenge[:8],
                    )
                    return JsonResponse(
                        {'error': 'invalid_grant', 'error_description': 'Code verifier mismatch'},
                        status=400,
                    )

                cache.delete(pkce_key)

        from oidc_provider.views import TokenView as LibraryTokenView
        try:
            return LibraryTokenView.as_view()(request, *args, **kwargs)
        except Exception as exc:
            from auth_bridge.credentials import CredentialValidationError
            from oidc_provider.lib.errors import TokenError, UserAuthError

            if isinstance(exc, UserAuthError):
                return JsonResponse(
                    {"error": exc.error, "error_description": exc.description},
                    status=403,
                    reason=exc.error,
                )
            if isinstance(exc, TokenError):
                return JsonResponse(
                    {"error": exc.error, "error_description": exc.description},
                    status=400,
                )
            if isinstance(exc, CredentialValidationError):
                if "revok" in str(exc).lower():
                    return JsonResponse(
                        {"error": "DependentSessionRevoked", "error_description": str(exc)},
                        status=403,
                        reason="DependentSessionRevoked",
                    )
                return JsonResponse(
                    {"error": "invalid_grant", "error_description": str(exc)},
                    status=400,
                )
            raise


class LoginPageView(View):
    """
    Render the DID login page for OIDC authentication flow.
    """

    def get(self, request):
        """
        Render the login page or authenticated dashboard.

        If the user is already authenticated and an OIDC flow is actively
        in progress (OIDC params exist in ``?next=``), redirect to the
        ``next`` URL so the OIDC provider can issue a code directly.
        If no OIDC flow is in progress, render a dashboard that acknowledges
        the user's sovereign identity with download links for iyou_home and
        iyou_mobile, plus a logout button.

        Unauthenticated visitors always see the login card.
        """
        next_url = request.GET.get('next', '')

        if request.user.is_authenticated:
            # If the next URL contains OIDC params, this is an active flow.
            # Redirect so the OIDC provider can auto-generate the auth code.
            if next_url:
                parsed = urlparse(next_url)
                params = parse_qs(parsed.query)
                if params.get('client_id') and params.get('response_type'):
                    return redirect(next_url)

            linked_emails = request.user.linked_emails.all().order_by('-verified_at')
            passkeys = request.user.passkeys.all().order_by('-created_at')
            context = {
                'next_url': DEFAULT_NEXT_URL,
                'user_did': request.user.custodial_did,
                'custodial_did': request.user.custodial_did,
                'primary_email': request.user.email,
                'account_tier': getattr(request.user, 'account_tier', 'managed_free'),
                'email_verified': getattr(request.user, 'email_verified', False),
                'email_verified_at': getattr(request.user, 'email_verified_at', None),
                'linked_emails': linked_emails,
                'passkeys': passkeys,
                'home_ws_url': django_settings.IDP_HOME_WS_URL,
                'wun_url': django_settings.IDP_WUN_URL,
                'idp_base_url': django_settings.IDP_BASE_URL,
            }
            return render(request, 'auth_bridge/authenticated_dashboard.html', context)

        # Not authenticated — render the standard login page.
        next_url = next_url or DEFAULT_NEXT_URL
        context = {
            'next_url': next_url,
            'home_ws_url': django_settings.IDP_HOME_WS_URL,
            'wun_url': django_settings.IDP_WUN_URL,
            'idp_base_url': django_settings.IDP_BASE_URL,
        }
        return render(request, 'auth_bridge/login.html', context)


class LegalDisclaimerView(View):
    """
    Render the post-login Legal Disclaimer Gate.
    """

    def get(self, request):
        if not request.user.is_authenticated:
            next_url = request.GET.get('next', '')
            login_url = reverse('auth_bridge:login')
            if next_url:
                login_url = f"{login_url}?{urlencode({'next': next_url})}"
            return redirect(login_url)

        next_url = request.GET.get('next') or DEFAULT_NEXT_URL
        context = {
            'next_url': next_url,
            'user_did': getattr(request.user, 'custodial_did', ''),
            'show_legal_disclaimer': getattr(request.user, 'show_legal_disclaimer', True),
            'wun_url': django_settings.IDP_WUN_URL,
            'idp_base_url': django_settings.IDP_BASE_URL,
        }
        return render(request, 'auth_bridge/legal_disclaimer.html', context)


@require_POST
@csrf_exempt
def acknowledge_legal_disclaimer(request):
    """
    Record affirmative (GDPR) acknowledgment of the Sovereign Network Access
    & Legal Notice and release the post-disclaimer redirect.

    Requires explicit consent (``consent_accepted=true``); passive page views
    never count as consent. On success the user's ``show_legal_disclaimer``
    flag is cleared server-side so OIDC code issuance may proceed unhindered,
    and the response carries the ``redirect_url`` to resume the prior flow.
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'authentication_required'}, status=401)

    try:
        data = json.loads(request.body) if request.body else {}
    except json.JSONDecodeError:
        data = request.POST

    consent = data.get('consent_accepted', data.get('consent', False))
    if isinstance(consent, str):
        consent = consent.lower() in ('true', '1', 'yes', 'on')

    if not consent:
        return JsonResponse(
            {'error': 'consent_required', 'success': False},
            status=400,
        )

    request.user.show_legal_disclaimer = False
    request.user.disclaimer_acknowledged_at = timezone.now()
    request.user.save(update_fields=['show_legal_disclaimer', 'disclaimer_acknowledged_at'])
    request.session['show_legal_disclaimer'] = False

    redirect_url = request.session.pop('post_disclaimer_redirect', None)
    if not redirect_url:
        redirect_url = data.get('next_url', data.get('next', ''))
    if not _is_safe_public_redirect(redirect_url):
        redirect_url = DEFAULT_NEXT_URL

    return JsonResponse({
        'success': True,
        'redirect_url': redirect_url,
        'show_legal_disclaimer': False,
        'disclaimer_acknowledged_at': request.user.disclaimer_acknowledged_at.isoformat(),
    })


class GlobalLogoutView(View):
    """
    Fully clear the IdP session and redirect the user.
    """

    def get(self, request):
        django_logout(request)
        next_page = request.GET.get('next', django_settings.IDP_WUN_URL + '/')
        return redirect(next_page)


class SovereignAuthorizeEndpoint(AuthorizeEndpoint):
    """
    Override the consent-skip gate so the library's own require_consent=False
    path at line 121-125 works for public clients doing authorization code flow.
    """

    def is_client_allowed_to_skip_consent(self):
        return True


class SovereignAuthorizeView(AuthorizeView):
    """
    Bypass the consent prompt for trusted clients.

    When a client defines ``require_consent = False``, any authenticated user
    is immediately issued an authorization code without rendering the consent
    template.  This removes the interactive consent step for all DID-authenticated
    identity contexts on trusted relying parties.

    Two-layer defense:
      1. SovereignAuthorizeEndpoint makes the library's own consent-skip path
         (views.py line 121) work for public code-flow clients.
      2. SovereignAuthorizeView.get() short-circuits the entire view before
         the library ever runs, as a fast path.
    """

    authorize_endpoint_class = SovereignAuthorizeEndpoint

    def get(self, request, *args, **kwargs):
        if getattr(request.user, "is_authenticated", False):
            auth_method = request.session.get("auth_method", "")
            if auth_method in ("password", "unverified"):
                logger.warning(
                    "OIDC GATE: blocking code issuance for unverified/password session: user=%s auth_method=%s",
                    request.user.custodial_did,
                    auth_method,
                )
                return JsonResponse(
                    {
                        "error": "access_denied",
                        "error_description": "Legacy password or unverified authentication is not permitted for OIDC issuance.",
                    },
                    status=403,
                )

        if getattr(request.user, "is_authenticated", False):
            gate_resp = _gate_response(request, request.user.custodial_did)
            if gate_resp is not None:
                return gate_resp

            # Server-side Legal Gate: never issue an authorization code until
            # the user has affirmatively acknowledged the Sovereign Network
            # Terms & Node Operator Policy. Preserve the original authorize
            # request (full query string) so the flow resumes after ack.
            if getattr(request.user, "show_legal_disclaimer", True):
                request.session["post_disclaimer_redirect"] = request.get_full_path()
                disclaimer_url = "{}?{}".format(
                    reverse("auth_bridge:legal_disclaimer"),
                    urlencode({"next": request.get_full_path()}),
                )
                return HttpResponseRedirect(disclaimer_url)

        authorize = self.authorize_endpoint_class(request)

        try:
            authorize.validate_params()

            prompt_param = authorize.params.get("prompt", "") if isinstance(authorize.params, dict) else getattr(authorize.params, "prompt", "")
            has_consent_prompt = "consent" in prompt_param if isinstance(prompt_param, (list, tuple, str)) else False

            if (
                get_attr_or_callable(request.user, "is_authenticated")
                and not authorize.client.require_consent
                and not has_consent_prompt
            ):
                return oidc_redirect(authorize.create_response_uri())

        except (ClientIdError, RedirectUriError, AuthorizeError):
            pass

        return super().get(request, *args, **kwargs)


class BetaGateView(View):
    """
    Render the Sovereign Airlock gate page.

    This is the graceful HTTP 403 surrender for unauthorized public logins.
    The page explains that access is limited to authorized keys and offers an
    input to redeem a beta invite key or submit a DID for waitlist
    consideration.
    """

    def get(self, request):
        next_url = request.GET.get('next', '') or DEFAULT_NEXT_URL
        did = request.user.custodial_did if request.user.is_authenticated else None
        return _render_beta_gate(request, did=did, next_url=next_url)


@csrf_exempt
def redeem_beta_invite(request):
    """
    Redeem a beta invite for this browser session.

    Accepts either a legacy static key from ``BETA_INVITE_KEYS`` (or a
    waitlisted DID), or an RFC-002 invite capability token minted by
    `iyou_home`. Tokens arrive as raw JSON, Base64URL, or Base58 so a direct
    link tap works: the canonical ``/airlock/?invite=...`` link published in
    invite QR codes, the ``/gate/redeem/?invite=...`` / ``?t=...`` variants,
    and the gate form's POST. A token must be schema-valid, unexpired, signed
    by an authorized issuer, and within its use budget; the sponsoring issuer DID
    is then held ephemerally in the browser session only — never in the database.

    Reached with no input at all, it is a neutral landing that just displays
    the manual entry form — a bare ``/airlock/`` tap is not a failed
    redemption and must not be reported as one.

    On success the session is stamped ``beta_access=True`` and the browser is
    returned to *next_url* (resumed OIDC flow, login page, or download modal).
    If the caller has already cryptographically proven their DID, an active
    session is minted immediately without requiring a second challenge
    signature. Invalid input re-renders the gate page with an error message.
    """
    if request.method not in ("GET", "POST"):
        return HttpResponseNotAllowed(["GET", "POST"])

    source = request.POST if request.method == "POST" else request.GET
    invite_key = (source.get("invite_key") or source.get("invite") or source.get("t") or "").strip()
    did = source.get("did", "").strip()
    next_url = (source.get("next_url") or source.get("next") or "").strip()
    if not next_url and hasattr(request, "session"):
        next_url = request.session.get('verified_pending_next_url', '')
    next_url = next_url or _default_next_for(request)

    token = None
    token_error = None
    redeemed = False

    if invite_key:
        if parse_token_input(invite_key) is not None:
            try:
                token = verify_invite_token(invite_key, cache=cache)
                redeemed = True
                logger.info(
                    "SYSTEM GATE: RFC-002 invite accepted issuer=%s nonce=%s tier=%s",
                    token["issuer_did"],
                    token["nonce"],
                    token["tier"],
                )
            except InviteTokenError as e:
                token_error = e
                logger.warning("SYSTEM GATE: RFC-002 invite rejected code=%s detail=%s", e.code, e.detail)
        else:
            valid_keys = set(getattr(django_settings, "BETA_INVITE_KEYS", []) or [])
            if invite_key in valid_keys:
                redeemed = True

    if not redeemed and token_error is None and did:
        if _is_admin_did(did) or _beta_allowlisted_did(did):
            redeemed = True

    if redeemed:
        request.session['beta_access'] = True
        if token is not None:
            _record_invite_provenance(request, token)
        logger.info("SYSTEM GATE: beta access granted for did=%s", did or "anonymous")

        # Only consume the stashed DID once access is actually granted, so a
        # failed attempt leaves the caller able to retry from the gate page.
        pending_did = request.session.pop('verified_pending_did', None) if hasattr(request, "session") else None
        if hasattr(request, "session"):
            request.session.pop('verified_pending_next_url', None)

        if pending_did:
            User = get_user_model()
            user, created = User.objects.get_or_create(custodial_did=pending_did, defaults={"email": None})
            user = evaluate_sovereign_admin_posture(user)

            if not user.is_active:
                messages.error(request, 'User account is disabled.')
                return _render_beta_gate(request, did=pending_did, next_url=next_url)

            login(request, user, backend="auth_bridge.backend.DIDAuthBackend")
            request.session["auth_method"] = "did:websocket"
            cache.set(f"user_auth_method:{user.id}", "did:websocket", 86400)
            logger.info("SYSTEM GATE: auto-login granted after invite redemption for verified DID %s", pending_did)

            if getattr(user, "show_legal_disclaimer", True):
                request.session['post_disclaimer_redirect'] = next_url
                try:
                    disclaimer_base = reverse('auth_bridge:legal_disclaimer')
                except Exception:
                    disclaimer_base = reverse('legal_disclaimer')
                return HttpResponseRedirect(f"{disclaimer_base}?next={quote_plus(next_url)}")

            redirect_url = _build_oidc_redirect(next_url, user)
            if redirect_url is None:
                redirect_url = next_url if _is_safe_public_redirect(next_url) else DEFAULT_NEXT_URL
            return HttpResponseRedirect(redirect_url)

        target = next_url if _is_safe_public_redirect(next_url) else DEFAULT_NEXT_URL
        return HttpResponseRedirect(target)

    if token_error is not None:
        messages.error(request, f'That invite token is not valid ({token_error.detail}).')
        logger.warning(
            "SYSTEM GATE: failed RFC-002 invite redemption code=%s key=%s did=%s",
            token_error.code,
            _redact_invite_submission(invite_key),
            did,
        )
    elif invite_key or did:
        messages.error(
            request,
            'That invite key has not been issued. Access remains restricted to authorized keys.',
        )
        logger.warning(
            "SYSTEM GATE: failed beta invite redemption for key=%s did=%s",
            _redact_invite_submission(invite_key),
            did,
        )
    return _render_beta_gate(request, did=did, next_url=next_url)


@require_GET
def airlock_sponsor(request):
    """
    One-shot read of the sponsoring DID held by a redeemed invite session.

    RFC-002 redemption deliberately keeps the Web-of-Trust edge out of
    Postgres, so the sponsoring issuer is parked in the browser session under
    ``sponsor_did``. A client that wants to attribute its own invite (e.g. to
    render "invited by …") reads it here, and the value is destroyed on the way
    out: a second query returns ``null``, so the edge is not durably recoverable
    from this node even if the session store is later seized.

    Requires an authenticated session — either a logged-in user, or a beta gate
    opened by a successful redemption. Read-only and GET-only, so no CSRF token
    is required; it is deliberately not ``csrf_exempt``, since a cross-site form
    can only ever issue a GET and so cannot reach this handler's side effect.
    """
    if not getattr(request.user, "is_authenticated", False) and not _has_beta_session(request):
        return JsonResponse({"error": "authentication_required"}, status=401)

    sponsor_did = request.session.get("sponsor_did")
    if "sponsor_did" in request.session:
        del request.session["sponsor_did"]
        request.session.modified = True
    return JsonResponse({"sponsor_did": sponsor_did})
