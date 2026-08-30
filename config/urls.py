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

from django.contrib import admin
from django.urls import path, include
from auth_bridge.views import LoginPageView, PkceTokenView, SovereignAuthorizeView
from apps.core.views import peer_instance_info

urlpatterns = [
    path('', LoginPageView.as_view(), name='landing'),
    path('admin/', admin.site.urls),
    # Peer instance capability descriptor (public JSON, no auth required)
    path('api/v1/instance/', peer_instance_info, name='peer_instance_info'),
    # auth/ must come before openid/ to avoid any routing conflict
    path('auth/', include('auth_bridge.urls')),
    # Identity Graduation protocol (export + confirm) under the canonical API prefix
    path('api/v1/identity/', include('auth_bridge.urls_api')),
    # Intercept the token endpoint before the library's catch-all to enforce PKCE
    path('openid/token/', PkceTokenView.as_view(), name='pkce_token'),
    # Intercept the authorize endpoint to bypass consent for trusted clients
    path('openid/authorize/', SovereignAuthorizeView.as_view(), name='sovereign_authorize'),
    path('openid/', include('oidc_provider.urls', namespace='oidc_provider')),
    path('oauth/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]
