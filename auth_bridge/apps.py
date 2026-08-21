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

from django.apps import AppConfig
from django.db.models.signals import post_migrate


def run_seed_clients(sender, **kwargs):
    from django.core.management import call_command
    try:
        call_command("seed_clients")
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"seed_clients post_migrate notice: {e}")


class AuthBridgeConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "auth_bridge"

    def ready(self):
        post_migrate.connect(run_seed_clients, sender=self)
