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

from django.contrib import admin
from django.forms import ModelForm, PasswordInput
from oidc_provider.models import Client

from auth_bridge.models import SovereignInfrastructureLease


class HardenedClientForm(ModelForm):
    class Meta:
        model = Client
        fields = "__all__"
        widgets = {
            "client_secret": PasswordInput(render_value=True),
        }


admin.site.unregister(Client)


@admin.register(Client)
class HardenedClientAdmin(admin.ModelAdmin):
    form = HardenedClientForm
    list_display = ("name", "client_id", "client_type")


@admin.register(SovereignInfrastructureLease)
class SovereignInfrastructureLeaseAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "is_active",
        "pinning_quota_bytes",
        "expires_at",
        "created_at",
    )
    list_filter = ("is_active",)
    search_fields = ("user__email", "user__custodial_did")
