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

import json
import logging
from django.conf import settings as django_settings
from django.contrib.auth import logout as django_logout
from django.contrib.sessions.models import Session
from django.db import transaction
from django.db.models import Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views import View

from auth_bridge.models import IssuedCredential, User
from auth_bridge.resilient_cache import cache
from auth_bridge.vault_client import delete_identity_key

logger = logging.getLogger(__name__)


class AccountPurgeView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if not getattr(request.user, "is_authenticated", False):
            return JsonResponse({"error": "authentication_required"}, status=401)

        try:
            payload = json.loads(request.body or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return JsonResponse({"error": "invalid_payload"}, status=400)

        if not isinstance(payload, dict) or payload.get("confirm") != "PURGE":
            return JsonResponse({"error": "confirmation_required"}, status=400)

        user = request.user
        user_id = str(user.id)
        dids = [d for d in (getattr(user, "custodial_did", None), getattr(user, "graduated_from_did", None)) if d]

        with transaction.atomic():
            User.objects.filter(merged_into=user).update(merged_into=None)
            IssuedCredential.objects.filter(Q(subject_did__in=dids) | Q(issuer_did__in=dids)).delete()

            now = timezone.now()
            for sess in Session.objects.filter(expire_date__gte=now):
                try:
                    decoded = sess.get_decoded()
                    if str(decoded.get("_auth_user_id", "")) == user_id:
                        sess.delete()
                except Exception:
                    pass

            for did in dids:
                try:
                    delete_identity_key(did)
                except Exception:
                    pass

            user.delete()

        cache.delete(f"user_auth_method:{user_id}")
        django_logout(request)

        logger.info("GDPR Art.17 erasure completed user_id=%s", user_id)

        response = JsonResponse({"success": True, "redirect_url": "/"})
        domain = None if getattr(django_settings, "DEBUG", False) else ".iyou.me"
        response.delete_cookie("idp_csrftoken", domain=domain)
        response.delete_cookie("iyou_sso_hint", domain=domain)
        if domain is not None:
            response.delete_cookie("idp_csrftoken")
            response.delete_cookie("iyou_sso_hint")
        return response
