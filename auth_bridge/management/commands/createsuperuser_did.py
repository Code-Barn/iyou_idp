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
Custom createsuperuser command for DID-based authentication.

Supports password-based fallback for admin access during Alpha phase.
"""
import os
from getpass import getpass
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password


class Command(BaseCommand):
    help = 'Create a superuser with DID-based authentication'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            dest='email',
            default=None,
            help='Email for the superuser (required)',
        )
        parser.add_argument(
            '--did',
            dest='did',
            default=None,
            help='Custodial DID for the superuser (auto-generated if not provided)',
        )
        parser.add_argument(
            '--password',
            dest='password',
            default=None,
            help='Password for admin fallback login. Falls back to DJANGO_SUPERUSER_PASSWORD env var.',
        )
        parser.add_argument(
            '--no-input',
            action='store_true',
            dest='no_input',
            default=False,
            help='Do not prompt for input of any kind.',
        )

    def _get_password(self, options):
        password = options['password']
        if password:
            return password
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
        if password:
            return password
        if options['no_input']:
            return None
        while True:
            password = getpass('Password: ')
            if not password:
                self.stdout.write(self.style.ERROR('Password cannot be blank.'))
                continue
            password2 = getpass('Password (again): ')
            if password != password2:
                self.stdout.write(self.style.ERROR('Passwords do not match.'))
                continue
            try:
                validate_password(password)
            except Exception as e:
                self.stdout.write(self.style.ERROR('\n'.join(e.messages)))
                continue
            return password

    def handle(self, *args, **options):
        User = get_user_model()
        email = options['email']
        did = options['did']

        if not options['no_input']:
            if not email:
                email = input('Email: ')
            if not did:
                did = input(f'Custodial DID [{did or "auto-generated"}]: ') or None

        if not email:
            self.stdout.write(self.style.ERROR('Email is required.'))
            return

        password = self._get_password(options)

        extra_fields = {}
        if did:
            extra_fields['custodial_did'] = did

        user = User.objects.create_superuser(
            email=email,
            password=password,
            **extra_fields,
        )

        self.stdout.write(self.style.SUCCESS('Superuser created successfully!'))
        self.stdout.write(f'Email: {user.email}')
        self.stdout.write(f'Custodial DID: {user.custodial_did}')
        self.stdout.write(f'ID: {user.id}')
        self.stdout.write(f'Is superuser: {user.is_superuser}')
        self.stdout.write(f'Is staff: {user.is_staff}')
        if password:
            self.stdout.write('Password: set')
        else:
            self.stdout.write(
                self.style.WARNING(
                    'No password set — admin login only works via DID auth '
                    '(auth/admin/did-login/). '
                    'Set one later with: python manage.py changepassword <email>'
                )
            )
