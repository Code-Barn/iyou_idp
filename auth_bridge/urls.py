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
from .views import ChallengeView, verify_signature, LoginPageView, managed_login, mobile_verify_signature, check_challenge_status
from .admin_views import custom_admin_login, custom_admin_verify, custom_admin_dashboard

app_name = 'auth_bridge'

urlpatterns = [
    # verify/ first to rule out any routing shadow
    path('verify/', verify_signature, name='verify_signature'),
    path('challenge/', ChallengeView.as_view(), name='challenge'),
    path('login/', LoginPageView.as_view(), name='login'),

    path('admin/did-login/', custom_admin_login, name='admin_did_login'),
    path('admin/did-verify/', custom_admin_verify, name='admin_did_verify'),
    path('admin/did-dashboard/',       custom_admin_dashboard,    name='admin_did_dashboard'),
    path('managed-login/',             managed_login,             name='managed_login'),
    path('mobile-verify/',             mobile_verify_signature,  name='mobile_verify'),
    path('challenge-status/<str:challenge_id>/', check_challenge_status, name='challenge_status'),
]
