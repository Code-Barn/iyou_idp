"""
Custom createsuperuser command for DID-based authentication.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Create a superuser with DID-based authentication'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--did',
            dest='did',
            default='did:admin:superuser',
            help='DID for the superuser (stored in username field)',
        )
        parser.add_argument(
            '--no-input',
            action='store_true',
            dest='no_input',
            default=False,
            help='Do not prompt for input of any kind.',
        )
    
    def handle(self, *args, **options):
        User = get_user_model()
        did = options['did']
        
        if not options['no_input']:
            did = input(f'DID (username) [{did}]: ') or did
        
        # Create the superuser
        user = User.objects.create_superuser(
            did=did,
            is_staff=True,
            is_superuser=True,
            is_active=True
        )
        
        self.stdout.write(self.style.SUCCESS(f'Superuser created successfully!'))
        self.stdout.write(f'DID (username): {user.username}')
        self.stdout.write(f'ID: {user.id}')
        self.stdout.write(f'Is superuser: {user.is_superuser}')
        self.stdout.write(f'Is staff: {user.is_staff}')
