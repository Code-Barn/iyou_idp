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

from auth_bridge.models import SovereignInfrastructureLease


def custom_userinfo_claims(claims, user):
    claims['sub'] = user.custodial_did
    claims['did'] = user.custodial_did
    claims['preferred_username'] = user.custodial_did
    claims['did_method'] = user.custodial_did.split(':')[1] if user.custodial_did.count(':') >= 2 else 'web'
    claims['email'] = user.email
    claims['account_tier'] = user.account_tier

    try:
        lease = user.infra_lease
        if lease.is_lease_valid:
            claims['iyou_infra'] = {
                'accelerated': True,
                'pinning_pool_endpoint': 'https://speed.iyou.me/v1/blob/',
                'quota_max_bytes': lease.pinning_quota_bytes,
            }
        else:
            claims['iyou_infra'] = {'accelerated': False}
    except SovereignInfrastructureLease.DoesNotExist:
        claims['iyou_infra'] = {'accelerated': False}

    return claims


def custom_idtoken_processing_hook(id_token, user, token, request):
    print(f"DEBUG: Token issued for code — client={token.client.client_id} user_did={user.custodial_did}", flush=True)
    id_token['did'] = user.custodial_did
    id_token['did_method'] = user.custodial_did.split(':')[1] if user.custodial_did.count(':') >= 2 else 'web'

    try:
        lease = user.infra_lease
        if lease.is_lease_valid:
            id_token['iyou_infra'] = {
                'accelerated': True,
                'pinning_pool_endpoint': 'https://speed.iyou.me/v1/blob/',
                'quota_max_bytes': lease.pinning_quota_bytes,
            }
        else:
            id_token['iyou_infra'] = {'accelerated': False}
    except SovereignInfrastructureLease.DoesNotExist:
        id_token['iyou_infra'] = {'accelerated': False}

    return id_token


def custom_sub_generator(user):
    return user.custodial_did
