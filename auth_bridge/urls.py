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

from django.urls import path
from .views import (
    ChallengeView,
    verify_signature,
    LoginPageView,
    managed_login,
    mobile_verify_signature,
    check_challenge_status,
    GlobalLogoutView,
    LegalDisclaimerView,
    acknowledge_legal_disclaimer,
)
from .views_oauth import OAuthInitiateView, OAuthCallbackView
from .views_passkeys import (
    passkey_register_begin,
    passkey_register_complete,
    passkey_authenticate_begin,
    passkey_authenticate_complete,
)
from .admin_views import custom_admin_login, custom_admin_verify, custom_admin_dashboard

app_name = 'auth_bridge'

urlpatterns = [
    # verify/ first to rule out any routing shadow
    path('verify/', verify_signature, name='verify_signature'),
    path('challenge/', ChallengeView.as_view(), name='challenge'),
    path('login/', LoginPageView.as_view(), name='login'),
    path('legal-disclaimer/', LegalDisclaimerView.as_view(), name='legal_disclaimer'),
    path('legal-disclaimer/acknowledge/', acknowledge_legal_disclaimer, name='legal_disclaimer_acknowledge'),
    path('disclaimer/acknowledge/', acknowledge_legal_disclaimer, name='disclaimer_acknowledge'),

    path('admin/did-login/', custom_admin_login, name='admin_did_login'),
    path('admin/did-verify/', custom_admin_verify, name='admin_did_verify'),
    path('admin/did-dashboard/',       custom_admin_dashboard,    name='admin_did_dashboard'),
    path('managed-login/',             managed_login,             name='managed_login'),
    path('mobile-verify/',             mobile_verify_signature,  name='mobile_verify'),
    path('challenge-status/<str:challenge_id>/', check_challenge_status, name='challenge_status'),
    path('logout/', GlobalLogoutView.as_view(), name='global_logout'),
    path('oauth/initiate/<str:provider>/', OAuthInitiateView.as_view(), name='oauth_initiate'),
    path('oauth/callback/<str:provider>/', OAuthCallbackView.as_view(), name='oauth_callback'),

    path('passkeys/register/begin/',     passkey_register_begin,     name='passkey_register_begin'),
    path('passkeys/register/complete/',  passkey_register_complete,  name='passkey_register_complete'),
    path('passkeys/authenticate/begin/', passkey_authenticate_begin, name='passkey_authenticate_begin'),
    path('passkeys/authenticate/complete/', passkey_authenticate_complete, name='passkey_authenticate_complete'),
]
