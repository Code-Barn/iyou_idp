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

from typing import Any

from auth_bridge.resilient_cache import cache
from oidc_provider.lib.claims import ScopeClaims

from auth_bridge.models import SovereignInfrastructureLease
from auth_bridge.tokens import inject_dependent_claims


def custom_userinfo_claims(claims: dict, user: Any, request: Any = None) -> dict:
    auth_method = "unknown"
    if request and hasattr(request, "session"):
        auth_method = request.session.get("auth_method", "unknown")
    if auth_method == "unknown":
        cached_method = cache.get(f"user_auth_method:{user.id}")
        if cached_method:
            auth_method = cached_method
        elif getattr(user, "is_sovereign", False):
            auth_method = "did:websocket"

    claims["sub"] = user.custodial_did
    claims["did"] = user.custodial_did
    claims["preferred_username"] = user.custodial_did
    claims["did_method"] = user.custodial_did.split(":")[1] if user.custodial_did.count(":") >= 2 else "web"
    claims["email"] = user.email
    claims["email_verified"] = getattr(user, "email_verified", False)
    claims["account_tier"] = user.account_tier
    claims["amr"] = [auth_method]

    if hasattr(user, "linked_emails"):
        claims["public_emails"] = [
            {"email": e.email, "label": e.label}
            for e in user.linked_emails.filter(is_public=True)
        ]
    else:
        claims["public_emails"] = []

    try:
        lease = user.infra_lease
        if lease.is_lease_valid:
            claims["iyou_infra"] = {
                "accelerated": True,
                "pinning_pool_endpoint": "https://speed.iyou.me/v1/blob/",
                "quota_max_bytes": lease.pinning_quota_bytes,
            }
        else:
            claims["iyou_infra"] = {"accelerated": False}
    except SovereignInfrastructureLease.DoesNotExist:
        claims["iyou_infra"] = {"accelerated": False}

    return claims


def custom_id_token_claims(
    id_token: dict,
    user: Any,
    token: Any = None,
    request: Any = None,
) -> dict:
    auth_method = "unknown"
    if request and hasattr(request, "session"):
        auth_method = request.session.get("auth_method", "unknown")
    if auth_method == "unknown":
        cached_method = cache.get(f"user_auth_method:{user.id}")
        if cached_method:
            auth_method = cached_method
        elif getattr(user, "is_sovereign", False):
            auth_method = "did:websocket"

    id_token["sub"] = user.custodial_did
    id_token["did"] = user.custodial_did
    id_token["did_method"] = user.custodial_did.split(":")[1] if user.custodial_did.count(":") >= 2 else "web"
    id_token["email_verified"] = getattr(user, "email_verified", False)
    id_token["account_tier"] = user.account_tier
    id_token["amr"] = [auth_method]

    try:
        lease = user.infra_lease
        if lease.is_lease_valid:
            id_token["iyou_infra"] = {
                "accelerated": True,
                "pinning_pool_endpoint": "https://speed.iyou.me/v1/blob/",
                "quota_max_bytes": lease.pinning_quota_bytes,
            }
        else:
            id_token["iyou_infra"] = {"accelerated": False}
    except SovereignInfrastructureLease.DoesNotExist:
        id_token["iyou_infra"] = {"accelerated": False}

    if token is not None:
        print(f"DEBUG: Token issued for code — client={token.client.client_id} user_did={user.custodial_did}", flush=True)

    id_token = inject_dependent_claims(id_token, user, token=token, request=request)
    return id_token


def custom_idtoken_processing_hook(
    id_token: dict,
    user: Any,
    token: Any = None,
    request: Any = None,
    **kwargs: Any,
) -> dict:
    return custom_id_token_claims(id_token=id_token, user=user, token=token, request=request)


class CustomScopeClaims(ScopeClaims):
    info_profile = (
        "Profile",
        "Custom profile claims including DID and account tier",
    )

    def scope_profile(self) -> dict:
        dic = {}
        for key in (
            "did",
            "did_method",
            "preferred_username",
            "account_tier",
            "amr",
            "email_verified",
            "public_emails",
            "iyou_infra",
        ):
            if key in self.userinfo:
                dic[key] = self.userinfo[key]
        return dic

    def scope_openid(self) -> dict:
        dic = {}
        for key in (
            "sub",
            "did",
            "did_method",
            "preferred_username",
            "account_tier",
            "amr",
            "email",
            "email_verified",
            "public_emails",
            "iyou_infra",
        ):
            if key in self.userinfo:
                dic[key] = self.userinfo[key]
        return dic


def custom_sub_generator(user: Any) -> str:
    return user.custodial_did
