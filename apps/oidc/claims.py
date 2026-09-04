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
OIDC Claims & Dependent Token Slot Injection (DEP-104).
"""

from auth_bridge.tokens import (
    DependentSessionRevokedError,
    ExpiredCredentialError,
    get_dependent_vector_for_did,
    inject_dependent_claims,
    is_credential_revoked,
    is_dependent_user,
    record_revocation_ticket,
    register_dependent_vector,
)

__all__ = [
    "inject_dependent_claims",
    "register_dependent_vector",
    "record_revocation_ticket",
    "is_credential_revoked",
    "is_dependent_user",
    "get_dependent_vector_for_did",
    "DependentSessionRevokedError",
    "ExpiredCredentialError",
]
