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

from .models import User
import uuid
import json


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

        from iyou_idp._crypto import verify_vp
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

        response_data = {
            'success': True,
            'redirect_url': next_url,
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
