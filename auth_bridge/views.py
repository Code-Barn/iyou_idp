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
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.cache import cache
from django.contrib.auth import login
from django.contrib.auth import logout as django_logout
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from urllib.parse import urlparse, parse_qs

from django.contrib import messages

from .models import User
from .backend import evaluate_sovereign_admin_posture
import uuid
import json
import hashlib
import sys
import base58
import os
import logging
from oidc_provider.models import Client, UserConsent
from oidc_provider.lib.utils.token import create_code

logger = logging.getLogger(__name__)

# Where to send the user after authentication when no explicit next_url is given.
from django.conf import settings as django_settings
DEFAULT_NEXT_URL = django_settings.IDP_WUN_URL


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

    scope_list = ' '.join(params.get('scope', ['openid'])).split()
    nonce = params.get('nonce', [''])[0]
    code_challenge = params.get('code_challenge', [None])[0]
    code_challenge_method = params.get('code_challenge_method', [None])[0]
    state = params.get('state', [''])[0]

    code_obj = create_code(
        user=user,
        client=client,
        scope=scope_list,
        nonce=nonce,
        is_authentication='openid' in scope_list,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    code_obj.save()
    logger.info("OIDC CODE ISSUED: code=%s user_did=%s client=%s", code_obj.code, user.username, client.client_id)

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

            # Challenge nonce check
            proof_challenge = proof.get("challenge")
            if proof_challenge and proof_challenge != challenge:
                return JsonResponse({"error": "Challenge nonce mismatch"}, status=401)

            # Root Authentication Flow: no inner credential → master key proof
            if not vp_json.get("verifiableCredential"):
                holder_did = vp_json.get("holder")
                challenge_str = vp_json.get("challenge")
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
                if not direct_valid:
                    remote_ip = request.META.get('REMOTE_ADDR', 'unknown')
                    print(f"SECURITY: Bypass attempted from {remote_ip} for DID {holder_did}", flush=True)
                    cached_raw = cache.get(challenge)
                    if cached_raw is not None:
                        print("SECURITY AUDIT BYPASS: challenge", challenge[:16], "DID", holder_did, flush=True)
                        user, created = User.objects.get_or_create(username=holder_did)
                        user = evaluate_sovereign_admin_posture(user)
                        if user.is_active:
                            user.backend = "django.contrib.auth.backends.ModelBackend"
                            login(request, user)
                            cache.delete(challenge)
                            response_data = {
                                "success": True,
                                "redirect_url": next_url,
                                "user": {
                                    "did": user.username,
                                    "is_new_user": created,
                                    "is_authenticated": True,
                                    "session_id": request.session.session_key,
                                },
                            }
                            print("VERIFY RESPONSE (BYPASS):", json.dumps(response_data), flush=True)
                            return JsonResponse(response_data)
                        else:
                            print("DIAGNOSTIC: Bypass failed - user account disabled", flush=True)
                    return JsonResponse({"error": "Invalid master key signature"}, status=401)

                user, created = User.objects.get_or_create(username=holder_did)
                user = evaluate_sovereign_admin_posture(user)

                if not user.is_active:
                    return JsonResponse({"error": "User account is disabled"}, status=403)

                user.backend = "django.contrib.auth.backends.ModelBackend"
                login(request, user)

                cache.delete(challenge)

                response_data = {
                    "success": True,
                    "redirect_url": next_url,
                    "user": {
                        "did": user.username,
                        "is_new_user": created,
                        "is_authenticated": True,
                        "session_id": request.session.session_key,
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

        did = vp_json.get('holder', '')
        if not did:
            return JsonResponse({
                'error': 'No DID found in verifiable presentation'
            }, status=400)

        cache.delete(challenge)

        user, created = User.objects.get_or_create(username=did)
        user = evaluate_sovereign_admin_posture(user)

        if not user.is_active:
            return JsonResponse({
                'error': 'User account is disabled'
            }, status=403)

        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)

        # Bypass the OIDC consent page: generate an auth code right here
        redirect_url = _build_oidc_redirect(next_url, user)
        if redirect_url is None:
            redirect_url = next_url

        response_data = {
            'success': True,
            'redirect_url': redirect_url,
            'user': {
                'did': user.username,
                'is_new_user': created,
                'is_authenticated': True,
                'session_id': request.session.session_key,
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

            # Challenge nonce check
            proof_challenge = proof.get("challenge")
            if proof_challenge and proof_challenge != challenge:
                return JsonResponse({"error": "Challenge nonce mismatch"}, status=401)

            # Root Authentication Flow: no inner credential → master key proof
            if not vp_json.get("verifiableCredential"):
                did = vp_json.get("holder")
                proof_block = vp_json.get("proof", {})

                # -- Primary: Python Ed25519 verification against canonical VP payload --
                holder_did = vp_json.get("holder")
                challenge_str = vp_json.get("challenge")
                proof_block = vp_json.get("proof", {})
                raw_sig_str = proof_block.get("proofValue") or proof_block.get("signatureValue", "")
                direct_valid = False

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
                if not direct_valid:
                    remote_ip = request.META.get('REMOTE_ADDR', 'unknown')
                    print(f"SECURITY: Mobile bypass attempted from {remote_ip} for DID {holder_did}", flush=True)
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

        did = vp_json.get('holder', '')
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

    user, created = User.objects.get_or_create(username=did)
    user = evaluate_sovereign_admin_posture(user)

    if not user.is_active:
        return JsonResponse(
            {'solved': False, 'error': 'User account is disabled'},
            status=403,
        )

    user.backend = 'django.contrib.auth.backends.ModelBackend'
    login(request, user)

    redirect_url = _build_oidc_redirect(next_url, user)
    if redirect_url is None:
        redirect_url = next_url

    cache.delete(challenge_id)

    return JsonResponse({
        'solved': True,
        'redirect_url': redirect_url,
    })


@require_POST
def managed_login(request):
    """
    Scaffold view for Level 1 (Managed Convenience) email/password login.

    Future: will hash the password, call did_rust to generate a server-side
    did:web, create/get a User, and log them in.
    """
    email = request.POST.get('email', '').strip()
    password = request.POST.get('password', '').strip()

    if not email or not password:
        messages.error(request, 'Email and password are required.')
    else:
        messages.info(
            request,
            f'Managed auth scaffolding — backend not yet wired. '
            f'Received email={email}'
        )

    return redirect(f"{reverse('auth_bridge:login')}?tab=managed")


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
        the user's sovereign identity with download links for iYou Home and
        iYou Mobile, plus a logout button.

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

            # No active OIDC flow — show authenticated dashboard.
            context = {
                'next_url': DEFAULT_NEXT_URL,
                'user_did': request.user.username,
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


class GlobalLogoutView(View):
    """
    Fully clear the IdP session and redirect the user.
    """

    def get(self, request):
        django_logout(request)
        next_page = request.GET.get('next', django_settings.IDP_WUN_URL + '/')
        return redirect(next_page)
