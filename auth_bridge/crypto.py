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
Crypto utilities for DID verification using Rust bridge.
"""
from typing import Optional


def verify_bridge() -> Optional[str]:
    """
    Verify that the Rust crypto bridge is accessible.

    Returns:
        Optional[str]: Message from Rust bridge if successful, None otherwise.
    """
    try:
        # Explicit import from iyou_idp._crypto as per pyproject.toml
        from iyou_idp._crypto import hello_from_bin
        return hello_from_bin()
    except ImportError as e:
        print(f"Rust bridge not available: {e}")
        return None
    except Exception as e:
        print(f"Error calling Rust bridge: {e}")
        return None
