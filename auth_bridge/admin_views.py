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
Custom admin views for DID-based authentication.
"""
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.core.cache import cache
from django.http import JsonResponse
from auth_bridge.models import User
from auth_bridge.backend import evaluate_sovereign_admin_posture
import uuid
import json


def custom_admin_login(request):
    """
    Custom admin login page that uses DID challenge-response flow.
    """
    if request.method == 'POST':
        # Handle challenge request
        challenge_uuid = str(uuid.uuid4())
        cache.set(challenge_uuid, 'admin_login', timeout=60)

        return JsonResponse({
            'challenge': challenge_uuid,
            'expires_in': 60,
            'next_step': 'verify'
        })

    return render(request, 'admin/did_login.html', {
        'title': 'DID Admin Login',
        'action_url': '/admin/did-verify/'
    })


@csrf_protect
def custom_admin_verify(request):
    """
    Verify DID signature and log in user.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
        vp_json = data.get('verifiable_presentation', None)
        challenge = data.get('challenge', '')

        if not vp_json or not challenge:
            return JsonResponse({
                'error': 'Missing verifiable_presentation or challenge'
            }, status=400)

        # Verify the challenge exists and is for admin login
        cached_challenge = cache.get(challenge)
        if cached_challenge != 'admin_login':
            return JsonResponse({
                'error': 'Invalid or expired challenge'
            }, status=401)

        # Verify using Rust bridge
        from iyou_idp._crypto import verify_vp
        result_json = verify_vp(json.dumps(vp_json))
        result = json.loads(result_json)

        if not result.get('valid', False):
            error_msg = result.get('error', 'Verification failed')
            return JsonResponse({'error': error_msg}, status=401)

        # Extract DID from the VP itself
        did = vp_json.get('holder', '')
        if not did:
            return JsonResponse({
                'error': 'No DID found in verifiable presentation'
            }, status=400)

        # Get user and check if they're a staff user
        try:
            user = User.objects.get(custodial_did=did)
            user = evaluate_sovereign_admin_posture(user)
            if not user.is_staff:
                return JsonResponse({
                    'error': 'User is not an admin user'
                }, status=403)

            if not user.is_active:
                return JsonResponse({
                    'error': 'User account is disabled'
                }, status=403)

            # Mark challenge as used
            cache.delete(challenge)

            # Log the user in
            user.backend = 'auth_bridge.backend.DIDAuthBackend'
            login(request, user)

            return JsonResponse({
                'success': True,
                'redirect_url': '/admin/'
            })

        except User.DoesNotExist:
            return JsonResponse({
                'error': 'User not found'
            }, status=404)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({
            'error': f'Internal error: {str(e)}'
        }, status=500)


@login_required
def custom_admin_dashboard(request):
    """
    Custom admin dashboard that shows DID information.
    """
    if not request.user.is_staff:
        return redirect('/admin/')

    return render(request, 'admin/did_dashboard.html', {
        'user': request.user,
        'did': request.user.custodial_did,
        'is_superuser': request.user.is_superuser
    })
