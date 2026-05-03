"""
Views for authentication challenges and OIDC flows.
"""
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.contrib.auth import login, authenticate
from django.middleware.csrf import get_token
from django.shortcuts import render, redirect
from django.urls import reverse
from .models import User
import uuid
import json


@method_decorator(csrf_exempt, name='dispatch')
class ChallengeView(View):
    """
    Generate and return a new authentication challenge using Redis.
    """
    
    def post(self, request):
        """
        Create a new challenge in Redis with 60-second TTL.
        
        Returns:
            JsonResponse: Contains the challenge UUID.
        """
        challenge_uuid = str(uuid.uuid4())
        # Store in Redis with 60-second expiry
        cache.set(challenge_uuid, 'pending', timeout=60)
        
        return JsonResponse({
            'challenge': challenge_uuid,
            'expires_in': 60,
        })

    def get(self, request):
        """
        Health check endpoint.
        
        Returns:
            JsonResponse: Status message.
        """
        return JsonResponse({'status': 'auth_bridge operational'})


@method_decorator(csrf_exempt, name='dispatch')
class VerifySignatureView(View):
    """
    Verify a DID signature against a challenge and authenticate the user.
    """
    
    def post(self, request):
        """
        Verify signature and authenticate user.
        
        Expects JSON: {"verifiable_presentation": {...}, "challenge": "uuid"}
        
        Returns:
            JsonResponse: Success/failure with user info or error.
        """
        try:
            data = json.loads(request.body)
            vp_json = data.get('verifiable_presentation', None)
            challenge = data.get('challenge', '')
            
            if not vp_json or not challenge:
                return JsonResponse({
                    'error': 'Missing required fields: verifiable_presentation, challenge'
                }, status=400)
            
            # Check if challenge exists in Redis
            cached_challenge = cache.get(challenge)
            if cached_challenge is None:
                return JsonResponse({
                    'error': 'Challenge not found or expired'
                }, status=404)
            
            # Verify verifiable presentation using Rust bridge
            from iyou_idp._crypto import verify_vp
            result_json = verify_vp(json.dumps(vp_json), challenge)
            result = json.loads(result_json)
            
            if not result.get('valid', False):
                error_msg = result.get('error', 'Verification failed')
                return JsonResponse({
                    'error': error_msg
                }, status=401)
            
            # Extract DID from verification result
            did = result.get('did', '')
            if not did:
                return JsonResponse({
                    'error': 'No DID found in verifiable presentation'
                }, status=400)
            
            # Mark challenge as used
            cache.delete(challenge)
            
            # Get or create user based on DID
            user, created = User.objects.get_or_create(username=did)
            
            if not user.is_active:
                return JsonResponse({
                    'error': 'User account is disabled'
                }, status=403)
            
            # Start Django session
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            
            return JsonResponse({
                'success': True,
                'user': {
                    'did': user.username,
                    'is_new_user': created,
                    'is_authenticated': True,
                    'session_id': request.session.session_key
                }
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'error': 'Invalid JSON payload'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'error': f'Internal server error: {str(e)}'
            }, status=500)


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
