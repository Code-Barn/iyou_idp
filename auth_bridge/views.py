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
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
from urllib.parse import urlparse, parse_qs

from .models import User
import uuid
import json
import sys
import logging
from oidc_provider.models import Client, UserConsent
from oidc_provider.lib.utils.token import create_code

logger = logging.getLogger(__name__)


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


@require_POST
@csrf_exempt
def verify_signature(request):
    print("VERIFY VIEW ACCESSED from", request.META.get('REMOTE_ADDR'), flush=True)

    try:
        data = json.loads(request.body)
        vp_json = data.get('verifiable_presentation', None)
        challenge = data.get('challenge', '')
        next_url = data.get('next_url', '/')

        if not vp_json or not challenge:
            return JsonResponse({
                'error': 'Missing required fields: verifiable_presentation, challenge'
            }, status=400)

        cached_challenge = cache.get(challenge)
        if cached_challenge is None:
            return JsonResponse({
                'error': 'Challenge expired'
            }, status=400)

        # --- Rust crypto bridge import with fallback paths ---
        verify_vp = None
        _import_errors = []
        try:
            from iyou_idp import _crypto
            verify_vp = _crypto.verify_vp
        except ImportError as e:
            _import_errors.append(f"from iyou_idp import _crypto: {e}")
            try:
                import _crypto  # type: ignore[import-not-found]
                verify_vp = _crypto.verify_vp
            except ImportError as e:
                _import_errors.append(f"import _crypto: {e}")

        if verify_vp is None:
            print("=" * 60, flush=True)
            print("RUST CRYPTO BRIDGE IMPORT FAILED", flush=True)
            print("sys.path:", sys.path, flush=True)
            for err in _import_errors:
                print("  ", err, flush=True)
            # Check if the compiled .so even exists on disk
            import os
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

        result_json = verify_vp(json.dumps(vp_json))
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
        
        Returns:
            JsonResponse: Contains the challenge UUID.
        """
        challenge_uuid = str(uuid.uuid4())
        # Store in Redis with 300-second expiry
        cache.set(challenge_uuid, 'pending', timeout=300)
        
        return JsonResponse({
            'challenge': challenge_uuid,
            'expires_in': 300,
        })

    def get(self, request):
        """
        Health check endpoint.
        
        Returns:
            JsonResponse: Status message.
        """
        return JsonResponse({'status': 'auth_bridge operational'})


class LoginPageView(View):
    """
    Render the DID login page for OIDC authentication flow.
    """
    
    def get(self, request):
        """
        Render the login page with Tailwind CSS.
        
        Args:
            request: HTTP request object
            
        Returns:
            HTTP response with login page template
        """
        # Get the 'next' parameter from the URL (OIDC redirect URI)
        next_url = request.GET.get('next', '/')
        
        context = {
            'next_url': next_url,
            'page_title': 'Sovereign Login',
            'description': 'Authenticate with your Decentralized Identifier',
        }
        
        return render(request, 'auth_bridge/login.html', context)
