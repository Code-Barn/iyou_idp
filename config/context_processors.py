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

from django.conf import settings
from django.http import HttpRequest

from apps.core.context_processors import ecosystem_releases

__all__ = ["global_settings", "ecosystem_releases"]


def global_settings(request: HttpRequest) -> dict[str, Any]:
    return {
        "ADMIN_DID": getattr(settings, "ADMIN_DID", ""),
        "SYSTEM_GATE_ENABLED": bool(getattr(settings, "SYSTEM_GATE_ENABLED", True)),
        "IDP_NODE_ROLE": getattr(settings, "IDP_NODE_ROLE", "community_peer"),
        "IDP_OPERATOR_NAME": getattr(settings, "IDP_OPERATOR_NAME", ""),
        "IDP_OPERATOR_CONTACT": getattr(settings, "IDP_OPERATOR_CONTACT", ""),
    }
