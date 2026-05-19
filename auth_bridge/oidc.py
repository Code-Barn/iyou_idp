# Copyright (C) 2026 Byers Brands, LLC
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

def custom_userinfo_claims(claims, user):
    claims['sub'] = user.username
    claims['did'] = user.username
    claims['preferred_username'] = user.username
    claims['did_method'] = user.username.split(':')[1] if user.username.count(':') >= 2 else 'key'
    return claims


def custom_idtoken_processing_hook(id_token, user, token, request):
    print(f"DEBUG: Token issued for code — client={token.client.client_id} user_did={user.username}", flush=True)
    id_token['did'] = user.username
    id_token['did_method'] = user.username.split(':')[1] if user.username.count(':') >= 2 else 'key'
    return id_token


def custom_sub_generator(user):
    return user.username
