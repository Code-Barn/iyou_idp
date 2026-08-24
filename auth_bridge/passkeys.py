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
Server-side WebAuthn/passkey ceremony engine for the passwordless Managed
login factor. Wraps python-fido2's ``Fido2Server`` and provides JSON-safe
option serialization plus storage round-tripping of attested credentials.
"""

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from django.conf import settings
from fido2.cbor import decode as cbor_decode, encode as cbor_encode
from fido2.cose import CoseKey
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestedCredentialData,
    AuthenticatorAttachment,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    AuthenticationResponse,
)


def relying_party_id() -> str:
    return urlparse(settings.IDP_BASE_URL).hostname or "localhost"


def build_server() -> Fido2Server:
    server = Fido2Server(
        PublicKeyCredentialRpEntity(id=relying_party_id(), name="iYou Identity Provider")
    )
    server.timeout = 120000
    return server


def jsonify_options(options: Mapping[str, Any] | Any) -> dict[str, Any]:
    """
    Recursively convert fido2 option objects (Mapping subclasses holding raw
    bytes) into JSON-serializable dicts with base64url-encoded buffers.
    """
    if isinstance(options, Mapping):
        return {key: jsonify_options(value) for key, value in options.items()}
    if isinstance(options, (list, tuple)):
        return [jsonify_options(item) for item in options]
    if isinstance(options, bytes):
        return websafe_encode(options)
    return options


def begin_registration(
    user: Any, existing_credentials: list[AttestedCredentialData]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Start a passkey registration ceremony for *user*.

    Returns ``(creation_options_json, server_state)`` where server_state must
    be round-tripped verbatim into ``complete_registration``.
    """
    server = build_server()
    user_entity = PublicKeyCredentialUserEntity(
        id=user.id.bytes,
        name=user.email or user.custodial_did,
        display_name=user.email or user.custodial_did,
    )
    creation_options, state = server.register_begin(
        user_entity,
        credentials=existing_credentials,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return jsonify_options(creation_options), dict(state)


def complete_registration(
    state: dict[str, Any], client_response: Mapping[str, Any]
) -> tuple[bytes, bytes, int]:
    """
    Verify a registration response and return
    ``(credential_id, cose_encoded_public_key, sign_count)`` ready for
    persistence.
    """
    server = build_server()
    auth_data = server.register_complete(state, response=dict(client_response))
    credential_data = auth_data.credential_data
    if credential_data is None:
        raise ValueError("missing attested credential data")
    return (
        bytes(credential_data.credential_id),
        bytes(cbor_encode(dict(credential_data.public_key))),
        auth_data.counter,
    )


def begin_authentication(
    existing_credentials: list[AttestedCredentialData] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Start an assertion ceremony. With ``None`` this triggers the
    discoverable-credential (usernameless) flow required by the passwordless
    mandate; a non-empty allow-list scopes the ceremony to specific creds.
    """
    server = build_server()
    request_options, state = server.authenticate_begin(
        credentials=existing_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return jsonify_options(request_options), dict(state)


def complete_authentication(
    state: dict[str, Any],
    known_credentials: list[AttestedCredentialData],
    client_response: Mapping[str, Any],
) -> AttestedCredentialData:
    """
    Verify an assertion against *known_credentials* and return the matching
    attested credential data.
    """
    server = build_server()
    return server.authenticate_complete(
        state, known_credentials, response=dict(client_response)
    )


def rebuild_attested_credential(
    credential_id: bytes, cose_public_key: bytes, sign_count: int
) -> AttestedCredentialData:
    """
    Reconstruct an ``AttestedCredentialData`` from persisted model fields.
    The stored COSE map is CBOR-encoded; AAGUID is not persisted and defaults
    to the zero AAGUID (verification only relies on ID + public key).
    """
    cose_key = CoseKey.parse(cbor_decode(cose_public_key))
    return AttestedCredentialData.create(
        Aaguid.NONE,
        credential_id,
        cose_key,
    )


def extract_raw_credential_id(client_response: Mapping[str, Any]) -> bytes:
    """
    Pull the raw credential ID out of an assertion response body without
    performing full verification.
    """
    parsed = AuthenticationResponse.from_dict(dict(client_response))
    return bytes(parsed.raw_id)


def extract_user_handle(client_response: Mapping[str, Any]) -> bytes | None:
    parsed = AuthenticationResponse.from_dict(dict(client_response))
    user_handle = parsed.response.user_handle
    return bytes(user_handle) if user_handle else None


def extract_assertion_counter(client_response: Mapping[str, Any]) -> int:
    """
    Return the signature counter carried in the assertion's authenticator data.
    """
    parsed = AuthenticationResponse.from_dict(dict(client_response))
    return int(parsed.response.authenticator_data.counter)


__all__ = [
    "AuthenticatorAttachment",
    "CollectedClientData",
    "PublicKeyCredentialCreationOptions",
    "PublicKeyCredentialDescriptor",
    "PublicKeyCredentialRequestOptions",
    "RegistrationResponse",
    "begin_authentication",
    "begin_registration",
    "build_server",
    "complete_authentication",
    "complete_registration",
    "extract_assertion_counter",
    "extract_raw_credential_id",
    "extract_user_handle",
    "jsonify_options",
    "rebuild_attested_credential",
    "relying_party_id",
]
