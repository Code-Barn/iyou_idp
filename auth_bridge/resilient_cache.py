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
Cache resilience for the auth ingress.

Challenge storage must never 500 a login when Redis stalls, so reads and
writes degrade to a process-local LocMemCache. Quota accounting (RFC-002
invite use counters) is a security control instead of a convenience, so
`increment_within_cap` fails *closed* when no live backend is reachable and
pins the whole read-modify-write sequence to a single backend so the
primary/fallback pair can never split-brain the counter.
"""

from __future__ import annotations

import logging

from django.core.cache import cache as default_cache
from django.core.cache.backends.locmem import LocMemCache

logger = logging.getLogger(__name__)

_locmem_fallback = LocMemCache("auth_bridge_locmem_fallback", {})


class ResilientCache:
    """
    Cache wrapper that delegates to Django's configured default cache (e.g., Redis)
    and gracefully falls back to an in-memory LocMemCache if Redis is unreachable
    or stalls, ensuring challenge generation and verification never fail with 500.
    """

    def __init__(self, primary_cache=default_cache, fallback_cache=None):
        self._primary = primary_cache
        self._fallback = fallback_cache or _locmem_fallback

    def get(self, key, default=None):
        try:
            val = self._primary.get(key, default)
            if val is not None:
                return val
            return self._fallback.get(key, default)
        except Exception as e:
            logger.warning("Primary cache.get failed (%s); using in-memory fallback", e)
            return self._fallback.get(key, default)

    def set(self, key, value, timeout=300):
        try:
            self._primary.set(key, value, timeout=timeout)
            self._fallback.set(key, value, timeout=timeout)
        except Exception as e:
            logger.warning("Primary cache.set failed (%s); using in-memory fallback", e)
            self._fallback.set(key, value, timeout=timeout)

    def delete(self, key):
        try:
            self._primary.delete(key)
        except Exception as e:
            logger.warning("Primary cache.delete failed (%s); using in-memory fallback", e)
        finally:
            self._fallback.delete(key)

    def clear(self):
        """Drop every entry on both backends. Used by tests to reset quota state."""
        try:
            self._primary.clear()
        except Exception as e:
            logger.warning("Primary cache.clear failed (%s); using in-memory fallback", e)
        finally:
            self._fallback.clear()

    def _live_backend(self, probe_key: str):
        """
        Return the single backend that will service a read-modify-write sequence.

        Probing with a write keeps `add` + `incr` on one backend: a split across
        primary and fallback would let the two halves of a quota increment land
        on different counters.
        """
        try:
            self._primary.set(probe_key, 1, timeout=5)
            return self._primary
        except Exception as e:
            logger.warning("Primary cache unavailable for atomic op (%s); using in-memory fallback", e)
            return self._fallback

    def claim_unit(self, key, initial=0, timeout=None):
        """
        Atomically claim one unit from *key* and return the post-claim count.

        ``add`` seeds the counter to *initial* only when absent, so the value
        never moves backwards and the subsequent ``incr`` — the actual
        linearization point — hands every concurrent caller a distinct count.
        Returns ``None`` when no live backend could service the sequence: an
        uncountable claim is never a granted one.
        """
        backend = self._live_backend(f"{key}:probe")
        try:
            backend.add(key, initial, timeout=timeout)
            return backend.incr(key)
        except Exception as e:
            logger.error("Atomic claim failed for %s (%s); failing closed", key, e)
            return None


cache = ResilientCache()
