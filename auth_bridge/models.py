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
