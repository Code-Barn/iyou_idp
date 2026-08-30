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
Core peer-instance views for federated ``iyou_idp`` deployments.

The instance descriptor is a public JSON document that lets any relying party,
wallet, or neighbouring peer discover what this node offers across the three
auth tiers.  No session or permissions are required to read it.
"""

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .dids import managed_did_namespace


@require_GET
def peer_instance_info(request):
    """
    Public capability descriptor for this peer iyou_idp node.

    Advertises the Tier-1 managed ``did:web`` namespace (scoped to the
    operator's own domain), the Tier-2 QR-code / mobile endpoint set, and the
    Tier-3 desktop WebSocket bridge.  Sovereign ``did:key`` users interoperate
    without any account migration or vendor lock-in.
    """
    configured_providers = [
        name
        for name in settings.OAUTH_PROVIDERS
        if settings.OAUTH_PROVIDERS[name].get("client_id")
    ]

    payload = {
        "idp_base_url": settings.IDP_BASE_URL,
        "tier1": {
            "mode": "managed-convenience",
            "did_namespace": managed_did_namespace(),
            "login_endpoint": settings.IDP_BASE_URL + "/auth/managed-login/",
            "passkey_register_begin": "/auth/passkeys/register/begin/",
            "passkey_authenticate_begin": "/auth/passkeys/authenticate/begin/",
            "oauth_providers": configured_providers,
        },
        "tier2": {
            "mode": "qr-code-oob",
            "challenge_endpoint": settings.IDP_BASE_URL + "/auth/challenge/",
            "mobile_verify_endpoint": settings.IDP_BASE_URL + "/auth/mobile-verify/",
            "status_endpoint": settings.IDP_BASE_URL + "/auth/challenge-status/<challenge_id>/",
        },
        "tier3": {
            "mode": "desktop-websocket",
            "verify_endpoint": settings.IDP_BASE_URL + "/auth/verify/",
            "home_ws_url": settings.IDP_HOME_WS_URL,
            "home_url": settings.IDP_HOME_URL,
        },
        "oidc": {
            "pkce": "S256-enforced",
            "secretless": True,
            "authorize_endpoint": settings.IDP_BASE_URL + "/openid/authorize/",
            "token_endpoint": settings.IDP_BASE_URL + "/openid/token/",
            "discovery_endpoint": settings.IDP_BASE_URL + "/openid/.well-known/openid-configuration/",
            "jwks_endpoint": settings.IDP_BASE_URL + "/openid/jwks/",
        },
        "entrypoint": settings.IDP_WUN_URL,
        "admin_did": settings.ADMIN_DID,
    }
    return JsonResponse(payload)