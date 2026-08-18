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

from django.core.management.base import BaseCommand
from oidc_provider.models import Client, ResponseType, UserConsent
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta

LOCAL_DEV_FALLBACK = "http://127.0.0.1:8000/oidc/callback/"

SATELLITES = [
    {
        "client_id": "iyou-wun-satellite-client",
        "name": "Wun Social Engine",
        "redirects": [
            "https://wun.iyou.me/oidc/callback/",
            "http://127.0.0.1:8001/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://wun.iyou.me/",
            "http://127.0.0.1:8001/",
        ],
    },
    {
        "client_id": "iyou-poly-satellite-client",
        "name": "Poly Governance Node",
        "redirects": [
            "https://poly.iyou.me/oidc/callback/",
            "http://127.0.0.1:8002/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://poly.iyou.me/",
            "http://127.0.0.1:8002/",
        ],
    },
    {
        "client_id": "iyou-name-satellite-client",
        "name": "Name Profile Directory",
        "redirects": [
            "https://name.iyou.me/oidc/callback/",
            "http://127.0.0.1:8003/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://name.iyou.me/",
            "http://127.0.0.1:8003/",
        ],
    },
    {
        "client_id": "iyou-hive-satellite-client",
        "name": "Hive Satellite Workspace",
        "redirects": [
            "https://hive.iyou.me/oidc/callback/",
            "http://127.0.0.1:8004/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://hive.iyou.me/",
            "http://127.0.0.1:8004/",
        ],
    },
    {
        "client_id": "iyou-ride-satellite-client",
        "name": "Ride Marketplace",
        "redirects": [
            "https://ride.iyou.me/oidc/callback/",
            "http://127.0.0.1:8005/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://ride.iyou.me/",
            "http://127.0.0.1:8005/",
        ],
    },
    {
        "client_id": "dc-tech-satellite-client",
        "name": "DC Tech Platform",
        "redirects": [
            "https://dctech.iyou.me/oidc/callback/",
            "http://127.0.0.1:8006/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://dctech.iyou.me/",
            "http://127.0.0.1:8006/",
        ],
    },
    {
        "client_id": "iyou-safe-satellite-client",
        "name": "Safe Accountability Hub",
        "redirects": [
            "https://safe.iyou.me/oidc/callback/",
            "http://127.0.0.1:8007/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://safe.iyou.me/",
            "http://127.0.0.1:8007/",
        ],
    },
    {
        "client_id": "iyou-talk-satellite-client",
        "name": "Talk Peer Support",
        "redirects": [
            "https://talk.iyou.me/oidc/callback/",
            "http://127.0.0.1:8008/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://talk.iyou.me/",
            "http://127.0.0.1:8008/",
        ],
    },
    {
        "client_id": "iyou-clar-satellite-client",
        "name": "Clar Policy",
        "redirects": [
            "https://clar.iyou.me/oidc/callback/",
            "http://127.0.0.1:8009/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://clar.iyou.me/",
            "http://127.0.0.1:8009/",
        ],
    },
    {
        "client_id": "iyou-play-satellite-client",
        "name": "Play Activity Hub",
        "redirects": [
            "https://play.iyou.me/oidc/callback/",
            "http://127.0.0.1:8010/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://play.iyou.me/",
            "http://127.0.0.1:8010/",
        ],
    },
    {
        "client_id": "iyou-blog-satellite-client",
        "name": "Blog Publishing Engine",
        "redirects": [
            "https://blog.iyou.me/oidc/callback/",
            "http://127.0.0.1:8011/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://blog.iyou.me/",
            "http://127.0.0.1:8011/",
        ],
    },
    {
        "client_id": "iyou-draw-satellite-client",
        "name": "Draw Creative Canvas",
        "redirects": [
            "https://draw.iyou.me/oidc/callback/",
            "http://127.0.0.1:8012/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://draw.iyou.me/",
            "http://127.0.0.1:8012/",
        ],
    },
    {
        "client_id": "iyou-life-satellite-client",
        "name": "Life Wellness Tracker",
        "redirects": [
            "https://life.iyou.me/oidc/callback/",
            "http://127.0.0.1:8013/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://life.iyou.me/",
            "http://127.0.0.1:8013/",
        ],
    },
    {
        "client_id": "iyou-dev-satellite-client",
        "name": "Dev Platform Toolkit",
        "redirects": [
            "https://dev.iyou.me/oidc/callback/",
            "http://127.0.0.1:8014/oidc/callback/",
            LOCAL_DEV_FALLBACK,
        ],
        "post_logout_redirects": [
            "https://dev.iyou.me/",
            "http://127.0.0.1:8014/",
        ],
    },
]


class Command(BaseCommand):
    help = "Provisions fleet-wide OIDC public clients for the 14-satellite ecosystem mesh."

    def handle(self, *args, **options):
        code_response_type, _ = ResponseType.objects.get_or_create(
            value="code",
            defaults={"description": "code (Authorization Code Flow)"},
        )

        User = get_user_model()
        admin_user, admin_created = User.objects.get_or_create(
            custodial_did="did:admin:superuser",
            defaults={
                "email": "admin@iyou.me",
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
            },
        )

        if admin_created:
            self.stdout.write(
                self.style.SUCCESS("Created admin user: did:admin:superuser")
            )

        created_count = 0
        updated_count = 0

        for sat in SATELLITES:
            client_id = sat["client_id"]
            redirect_uris = "\n".join(sat["redirects"])
            logout_uris = "\n".join(sat["post_logout_redirects"])

            client, created = Client.objects.get_or_create(
                client_id=client_id,
                defaults={
                    "name": sat["name"],
                    "client_type": "public",
                    "client_secret": "",
                    "_redirect_uris": redirect_uris,
                    "_post_logout_redirect_uris": logout_uris,
                    "_scope": "openid profile email",
                    "jwt_alg": "RS256",
                    "require_consent": False,
                    "reuse_consent": True,
                },
            )

            if created:
                client.response_types.add(code_response_type)
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f"Created client: {client_id}")
                )
            else:
                client.name = sat["name"]
                client.client_type = "public"
                client.client_secret = ""
                client.require_consent = False
                client.reuse_consent = True
                client._redirect_uris = redirect_uris
                client._post_logout_redirect_uris = logout_uris
                client._scope = "openid profile email"
                client.save()
                client.response_types.add(code_response_type)
                updated_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f"Synchronized client: {client_id}")
                )

            consent, consent_created = UserConsent.objects.get_or_create(
                user=admin_user,
                client=client,
                defaults={
                    "_scope": "openid profile email",
                    "expires_at": timezone.now() + timedelta(days=365),
                    "date_given": timezone.now(),
                },
            )

            if not consent_created:
                consent._scope = "openid profile email"
                consent.expires_at = timezone.now() + timedelta(days=365)
                consent.save()

        self.stdout.write(
            self.style.SUCCESS(
                f"\nFleet sync complete: {created_count} created, "
                f"{updated_count} synchronized, {len(SATELLITES)} total clients."
            )
        )
