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
Tier-1 managed-identity ``did:web`` namespace derivation.

A peer instance mints managed (Tier 1) identifiers under its *own* domain
authority, e.g. ``did:web:hub.community.org:user:{uuid}``.  The prefix is
controlled by ``IDP_WEB_DID_NAMESPACE`` (default ``did:web:iyou.me``, which
preserves legacy flagship behaviour); the instance descriptor in views.py can
suggest the value implied by ``IDP_BASE_URL``.
"""

import uuid
from urllib.parse import urlparse

from django.conf import settings


def managed_did_namespace() -> str:
    """
    Full Tier-1 namespace prefix including the trailing ``:user`` segment.

    Returns ``IDP_WEB_DID_NAMESPACE`` when set; otherwise derives a
    ``did:web`` authority from the hostname of ``IDP_BASE_URL`` with percent
    encoding applied per the did:web method specification.
    """
    override = getattr(settings, "IDP_WEB_DID_NAMESPACE", "").strip()
    if override:
        return f"{override.rstrip(':')}:user"

    host = urlparse(settings.IDP_BASE_URL).hostname or "localhost"
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    host = host.replace(":", "%3A")
    return f"did:web:{host}:user"


def managed_user_did() -> str:
    """Mint a fresh Tier-1 managed identifier under this peer's namespace."""
    return f"{managed_did_namespace()}:{uuid.uuid4()}"