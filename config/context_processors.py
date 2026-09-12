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

from django.conf import settings


def global_settings(request):
    """
    Expose a small, curated set of global settings to every template so the
    airlock gate and gated download modal can reference ADMIN_DID without
    hardcoding DID literals into markup.
    """
    return {
        "ADMIN_DID": getattr(settings, "ADMIN_DID", ""),
        "SYSTEM_GATE_ENABLED": bool(getattr(settings, "SYSTEM_GATE_ENABLED", True)),
    }