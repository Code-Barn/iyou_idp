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

from typing import Any, Dict
from django.http import HttpRequest


def ecosystem_releases(request: HttpRequest) -> Dict[str, Any]:
    return {
        "IYOU_HOME_GITHUB_REPO": "https://github.com/Code-Barn/iyou_home",
        "IYOU_HOME_FALLBACK_TAG": "v0.2.0",
    }
