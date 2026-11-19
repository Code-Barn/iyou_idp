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

from django.contrib import admin
from django.core.exceptions import ValidationError
from django.forms import ModelForm, PasswordInput
from django.http import HttpRequest
from oidc_provider.models import Client

from auth_bridge.models import (
    FederatedIdentity,
    IssuedCredential,
    LinkedEmail,
    PasskeyCredential,
    SovereignInfrastructureLease,
    User,
)


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


class SovereignModelAdmin(admin.ModelAdmin):
    actions = None
    immutable_fields: tuple[str, ...] = ()

    def get_readonly_fields(self, request: HttpRequest, obj: Any = None) -> tuple[str, ...]:
        readonly = list(super().get_readonly_fields(request, obj))
        if obj is not None:
            for field in self.immutable_fields:
                if field not in readonly:
                    readonly.append(field)
        return tuple(readonly)

    def save_model(self, request: HttpRequest, obj: Any, form: Any, change: bool) -> None:
        if change and obj.pk:
            persisted = obj.__class__.objects.get(pk=obj.pk)
            for field in self.immutable_fields:
                if getattr(obj, field) != getattr(persisted, field):
                    raise ValidationError(f"Field '{field}' is immutable on sovereign records.")
        super().save_model(request, obj, form, change)


@admin.register(User)
class UserAdmin(SovereignModelAdmin):
    immutable_fields = (
        "custodial_did",
        "graduated_from_did",
        "disclaimer_acknowledged_at",
        "email_verified_at",
        "age_bracket_established_at",
        "created_at",
        "updated_at",
    )
    search_fields = ("email", "custodial_did", "graduated_from_did")
    list_display = ("email", "custodial_did", "account_tier", "is_sovereign", "is_active", "is_staff")


@admin.register(PasskeyCredential)
class PasskeyCredentialAdmin(SovereignModelAdmin):
    immutable_fields = (
        "user",
        "credential_id",
        "public_key_cose",
        "sign_count",
        "created_at",
        "last_used_at",
    )
    search_fields = ("user__email", "user__custodial_did", "credential_id")
    list_display = ("user", "credential_id", "sign_count", "created_at", "last_used_at")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(IssuedCredential)
class IssuedCredentialAdmin(SovereignModelAdmin):
    immutable_fields = (
        "subject_did",
        "issuer_did",
        "bracket",
        "wot_distance",
        "raw_vc",
        "issued_at",
        "expires_at",
        "revocation_ticket",
        "created_at",
        "updated_at",
    )
    search_fields = ("subject_did", "issuer_did", "revocation_ticket")
    list_display = ("subject_did", "issuer_did", "bracket", "revoked", "issued_at", "expires_at")
    list_filter = ("revoked", "bracket")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(LinkedEmail)
class LinkedEmailAdmin(SovereignModelAdmin):
    immutable_fields = ("user", "email", "verified_at")
    search_fields = ("user__email", "user__custodial_did", "email")
    list_display = ("user", "email", "verified_at", "is_public")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(FederatedIdentity)
class FederatedIdentityAdmin(SovereignModelAdmin):
    immutable_fields = ("user", "provider", "provider_user_id", "linked_at")
    search_fields = ("user__email", "user__custodial_did", "provider_user_id")
    list_display = ("user", "provider", "provider_user_id", "linked_at")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


@admin.register(SovereignInfrastructureLease)
class SovereignInfrastructureLeaseAdmin(SovereignModelAdmin):
    immutable_fields = ("user", "billing_token_hash", "created_at", "updated_at")
    list_display = (
        "user",
        "is_active",
        "pinning_quota_bytes",
        "expires_at",
        "created_at",
    )
    list_filter = ("is_active",)
    search_fields = ("user__email", "user__custodial_did")
