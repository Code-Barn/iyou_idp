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
from django.core.checks import CheckMessage, Error, Tags, register


@register(Tags.security, deploy=True)
def check_production_security(app_configs: Any = None, **kwargs: Any) -> list[CheckMessage]:
    errors: list[CheckMessage] = []
    if not settings.DEBUG:
        secret_key = getattr(settings, "SECRET_KEY", "")
        if secret_key.startswith("django-insecure-") or secret_key.startswith("insecure-"):
            errors.append(
                Error(
                    "SECRET_KEY cannot use an insecure default prefix in production.",
                    id="iyou_idp.security.E001",
                    hint="Set a cryptographically strong IDP_SECRET_KEY in production.",
                )
            )
        base_url = getattr(settings, "IDP_BASE_URL", "")
        if not base_url.startswith("https://"):
            errors.append(
                Error(
                    "IDP_BASE_URL must use https:// in production.",
                    id="iyou_idp.security.E002",
                    hint="Set IDP_BASE_URL to an https:// address.",
                )
            )
        admin_did = getattr(settings, "ADMIN_DID", "")
        if not admin_did:
            errors.append(
                Error(
                    "ADMIN_DID must be defined in production.",
                    id="iyou_idp.security.E003",
                    hint="Set ADMIN_DID to the node operator's did:key: identifier.",
                )
            )
    return errors
