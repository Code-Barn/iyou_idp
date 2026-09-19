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

from django.conf import settings
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase, override_settings

from apps.core.context_processors import ecosystem_releases

User = get_user_model()


class EcosystemReleasesContextProcessorTest(TestCase):

    def setUp(self):
        self.rf = RequestFactory()

    def test_ecosystem_releases_values(self):
        request = self.rf.get("/")
        data = ecosystem_releases(request)
        self.assertEqual(data["IYOU_HOME_GITHUB_REPO"], "https://github.com/Code-Barn/iyou_home")
        self.assertEqual(data["IYOU_HOME_FALLBACK_TAG"], "v0.2.2")

    def test_context_processor_registered_in_settings(self):
        cp_list = settings.TEMPLATES[0]["OPTIONS"]["context_processors"]
        self.assertIn("apps.core.context_processors.ecosystem_releases", cp_list)

    def test_download_modal_hydration_fallback(self):
        admin = User.objects.create_user(
            email="modal_test_user@iyou.me",
            custodial_did="did:key:test-modal-admin",
        )
        request = self.rf.get("/auth/login/")
        request.user = admin

        with override_settings(ADMIN_DID="did:key:test-modal-admin"):
            html = render_to_string(
                "auth_bridge/_download_modal.html",
                context={},
                request=request,
            )

        self.assertNotIn("Early Access Key Required", html)
        self.assertNotIn("IYOUWINEXEHASH", html)
        self.assertNotIn("QmYourWindowsExeHash", html)
        self.assertNotIn("IYOUMACARMHASH", html)
        self.assertNotIn("QmYourMacArmHash", html)

        self.assertIn('id="dl-windows-exe"', html)
        self.assertIn('id="dl-macos-dmg"', html)
        self.assertIn('id="dl-linux-deb"', html)
        self.assertIn('id="dl-linux-appimage"', html)
        self.assertIn('id="dl-linux-rpm"', html)
        self.assertIn('id="dl-bittorrent"', html)
        self.assertIn('id="dl-magnet"', html)
        self.assertIn('id="dl-ipfs"', html)

        self.assertIn(
            "https://github.com/Code-Barn/iyou_home/releases/download/v0.2.2/iyou-home_0.2.2_x64-setup.exe",
            html,
        )
        self.assertIn(
            "https://github.com/Code-Barn/iyou_home/releases/download/v0.2.2/iyou-home_0.2.2_x64.dmg",
            html,
        )
        self.assertIn(
            "https://github.com/Code-Barn/iyou_home/releases/download/v0.2.2/iyou-home_0.2.2_amd64.deb",
            html,
        )
        self.assertIn(
            "https://github.com/Code-Barn/iyou_home/releases/download/v0.2.2/iyou-home_0.2.2_amd64.AppImage",
            html,
        )
        self.assertIn(
            "https://github.com/Code-Barn/iyou_home/releases/download/v0.2.2/iyou-home-0.2.2-1.x86_64.rpm",
            html,
        )
        self.assertIn(
            "https://github.com/Code-Barn/iyou_home/releases/download/v0.2.2/iyou-home_0.2.2.torrent",
            html,
        )
        self.assertIn("https://ipfs.io/ipfs/QmfKNn6iVjqo47r5zvwAH9k9mCFeotDLS4mGn1hZ7ETZjH/", html)
        self.assertIn("36aa52f89e030d0a0daf79dffadef7b8ec8277b2", html)
        self.assertIn("91f411d3870be14625c1519aa861319e674780ab2f7dfd5efa42e41b4e3cc761", html)
        self.assertIn("9445c8a98a73ffea9eadd9bb982094c8243cd78eb67a5710f377758b058ce9c9", html)
        self.assertIn("426c9f3350d8d29e99d6b68beec1a9d1c169c5d51237b04977686e2c3f14271a", html)
        self.assertIn("2726b36c65bd14e173cd044e66ce98fe7f1fdadda572ab3b720bdd416a5757b5", html)
