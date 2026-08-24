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
Thin HashiCorp Vault KV v2 wrapper for managed-identity Ed25519 key custody.

Key material lives at ``{mount}/identity/{custodial_did}/ed25519`` and is
expected to contain at least ``private_key_pem`` and ``public_key_pem``.
"""

from typing import Any

import hvac
from django.conf import settings


def _key_path(custodial_did: str) -> str:
    return f"identity/{custodial_did}/ed25519"


def _client() -> hvac.Client:
    return hvac.Client(
        url=settings.IDP_VAULT_ADDR,
        token=settings.IDP_VAULT_TOKEN,
    )


def read_identity_key(custodial_did: str) -> dict[str, Any]:
    """
    Read the Ed25519 keypair secret data for *custodial_did*.

    Raises hvac exceptions on transport/auth failure and VaultLookupError
    (KeyError) when the path holds no secret.
    """
    client = _client()
    secret = client.secrets.kv.v2.read_secret_version(
        mount_point=settings.IDP_VAULT_KV_MOUNT,
        path=_key_path(custodial_did),
    )
    if secret is None:
        raise KeyError(f"No Vault secret at identity/{custodial_did}/ed25519")
    return secret["data"]["data"]


def write_identity_key(custodial_did: str, data: dict[str, Any]) -> None:
    """Seed key material for *custodial_did* (provisioning helper/tests)."""
    client = _client()
    client.secrets.kv.v2.create_or_update_secret(
        mount_point=settings.IDP_VAULT_KV_MOUNT,
        path=_key_path(custodial_did),
        secret=data,
    )


def delete_identity_key(custodial_did: str) -> None:
    """
    Permanently shred all versions and metadata of the keypair secret at
    ``{mount}/identity/{custodial_did}/ed25519``.
    """
    client = _client()
    client.secrets.kv.v2.delete_metadata_and_all_versions(
        mount_point=settings.IDP_VAULT_KV_MOUNT,
        path=_key_path(custodial_did),
    )
