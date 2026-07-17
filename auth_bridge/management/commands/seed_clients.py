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
from oidc_provider.models import Client, ResponseType


class Command(BaseCommand):
    help = "Programmatically provisions hardened ecosystem OIDC clients."

    def handle(self, *args, **options):
        satellites = {
            "dctech": {
                "name": "DC Tech Platform",
                "redirects": [
                    "https://dctech.iyou.me/oidc/callback/",
                    "https://legal.dctech.iyou.me/oidc/callback/",
                ],
            },
            "iyou-hive": {
                "name": "Hive Satellite Workspace",
                "redirects": ["https://hive.iyou.me/oidc/callback/"],
            },
            "iyou-name": {
                "name": "Name Profile Directory",
                "redirects": ["https://name.iyou.me/oidc/callback/"],
            },
            "iyou-play": {
                "name": "iyou-play",
                "redirects": ["https://play.iyou.me/oidc/callback/"],
            },
            "iyou-poly": {
                "name": "Poly Governance Node",
                "redirects": ["https://poly.iyou.me/oidc/callback/"],
            },
            "iyou-ride": {
                "name": "Ride Marketplace",
                "redirects": ["https://ride.iyou.me/oidc/callback/"],
            },
            "iyou-safe": {
                "name": "Safe Accountability Hub",
                "redirects": ["https://safe.iyou.me/oidc/callback/"],
            },
            "iyou-clar": {
                "name": "Clar Policy",
                "redirects": ["https://clar.iyou.me/oidc/callback/"],
            },
            "iyou-talk": {
                "name": "Talk Peer Support",
                "redirects": ["https://talk.iyou.me/oidc/callback/"],
            },
            "iyou-wun": {
                "name": "Wun Social Engine",
                "redirects": ["https://wun.iyou.me/oidc/callback/"],
            },
        }

        code_response_type, _ = ResponseType.objects.get_or_create(
            value="code",
            defaults={"description": "code (Authorization Code Flow)"},
        )

        for slug, data in satellites.items():
            client_id = f"{slug}-satellite-client"

            client, created = Client.objects.get_or_create(
                client_id=client_id,
                defaults={
                    "name": data["name"],
                    "client_type": "public",
                    "client_secret": "",
                    "_redirect_uris": "\n".join(data["redirects"]),
                    "_scope": "openid profile email",
                    "jwt_alg": "RS256",
                    "require_consent": False,
                    "reuse_consent": True,
                },
            )

            if created:
                client.response_types.add(code_response_type)
                self.stdout.write(
                    self.style.SUCCESS(f"Created client: {client_id}")
                )
            else:
                client.client_type = "public"
                client.client_secret = ""
                client.require_consent = False
                client.reuse_consent = True
                client._redirect_uris = "\n".join(data["redirects"])
                client._scope = "openid profile email"
                client.name = data["name"]
                client.save()
                client.response_types.add(code_response_type)
                self.stdout.write(
                    self.style.SUCCESS(f"Synchronized client array: {client_id}")
                )
