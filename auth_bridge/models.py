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

import uuid

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


class SovereignUserManager(BaseUserManager):
    def create_user(self, email=None, password=None, **extra_fields):
        if email:
            email = self.normalize_email(email)

        user_uuid = uuid.uuid4()
        extra_fields.setdefault("custodial_did", f"did:web:iyou.me:user:{user_uuid}")
        extra_fields.setdefault("account_tier", "managed_free")

        user = self.model(id=user_uuid, email=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Superusers must have an email address.")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("account_tier", "managed_premium")
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    ACCOUNT_TIERS = [
        ("managed_free", "Managed Free (Ad-Supported)"),
        ("managed_premium", "Managed Premium ($5/mo Subscription)"),
        ("sovereign", "Fully Sovereign (Graduated via iyou_home)"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True, blank=True, null=True)
    custodial_did = models.CharField(max_length=255, unique=True, db_index=True)
    account_tier = models.CharField(max_length=20, choices=ACCOUNT_TIERS, default="managed_free")
    is_sovereign = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = SovereignUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} ({self.account_tier})"

    @property
    def date_joined(self):
        return self.created_at


class FederatedIdentity(models.Model):
    PROVIDERS = [
        ("github", "GitHub"),
        ("google", "Google"),
        ("apple", "Apple"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="federated_identities")
    provider = models.CharField(max_length=15, choices=PROVIDERS)
    provider_user_id = models.CharField(max_length=255, db_index=True)
    linked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("provider", "provider_user_id")

    def __str__(self):
        return f"{self.provider.upper()} link -> {self.user.email}"


class PasskeyCredential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="passkeys",
    )
    credential_id = models.BinaryField(unique=True)
    public_key_cose = models.BinaryField()
    sign_count = models.PositiveIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Passkey({bytes(self.credential_id).hex()[:16]}… -> {self.user.custodial_did})"


class SovereignInfrastructureLease(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="infra_lease",
    )
    is_active = models.BooleanField(default=False)
    pinning_quota_bytes = models.BigIntegerField(default=10737418240)
    billing_token_hash = models.CharField(max_length=64, blank=True, null=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_lease_valid(self):
        return self.is_active and self.expires_at > timezone.now()

    def __str__(self):
        return f"Lease({self.user.email}) active={self.is_active}"
