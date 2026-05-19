# Copyright (C) 2026 Byers Brands, LLC
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

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
import uuid


class UserManager(BaseUserManager):
    def create_user(self, did: str, **extra_fields):
        if not did:
            raise ValueError('The DID must be set')
        user = self.model(username=did, **extra_fields)
        user.save(using=self._db)
        return user

    def create_superuser(self, did: str, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(did, **extra_fields)


class User(AbstractBaseUser):
    # Use standard AutoField as PK, store DID in username field
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255, unique=True, help_text='DID string', default='did:placeholder')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

    class Meta:
        indexes = [
            models.Index(fields=['username']),
            models.Index(fields=['is_active']),
        ]
