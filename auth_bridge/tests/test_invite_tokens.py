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
RFC-002 invite capability token redemption through the Sovereign Airlock.

Covers the canonicalization contract shared with the iyou_home minter, the
raw-JSON / Base64URL / Base58 input encodings, the expiry, signature, issuer
authorization and use-budget gates, and the untouched legacy
``BETA_INVITE_KEYS`` fallback.
"""

import hashlib
import json
import time
import uuid
from base64 import urlsafe_b64encode

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from django.test import Client as TestClient, RequestFactory, TestCase, override_settings
from django.urls import reverse

from auth_bridge import invite_tokens
from auth_bridge.resilient_cache import cache
from auth_bridge.models import User
from auth_bridge.tests import _make_did


def _did_of(private_key) -> str:
    pub = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return _make_did(pub)


def _mint(private_key, **overrides) -> dict:
    """
    Replicate `iyou_home` `mint_token_core` + `sign_token` exactly.

    Canonical payload is the ten signed fields, sorted keys, no whitespace;
    the signature is Ed25519 over SHA-256 of that payload, base58-encoded.
    """
    now = int(time.time())
    token = {
        "v": 1,
        "issuer_did": _did_of(private_key),
        "satellite_id": "",
        "nonce": "a" * 32,
        "max_uses": 1,
        "uses_count": 0,
        "tier": "member",
        "created_at": now,
        "expires_at": now + 86_400,
        "scope": ["join"],
    }
    token.update(overrides)
    canonical = json.dumps(
        {field: token[field] for field in invite_tokens.RFC002_SIGNED_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    token["signature"] = base58.b58encode(
        private_key.sign(hashlib.sha256(canonical).digest())
    ).decode("ascii")
    return token


def _nonce() -> str:
    """Unique per call: the use counter is process-global, not test-scoped."""
    return uuid.uuid4().hex


def _b64url(token: dict) -> str:
    return urlsafe_b64encode(json.dumps(token).encode("utf-8")).decode("ascii").rstrip("=")


class CanonicalizationTest(TestCase):
    """The verifier must reproduce the minter's canonical bytes exactly."""

    def setUp(self):
        self.key = ed25519.Ed25519PrivateKey.generate()

    def test_matches_rust_minter_interop_vector(self):
        """
        Golden vector emitted by `iyou_home` `invites::canonical_payload` /
        `invites::sign_token` (Rust `cargo test emit_interop_vector`).

        Any drift in field selection, key ordering, separators, digest, or
        signature encoding breaks admission for every real invite, so this
        pins the exact bytes the minter produced.
        """
        vector = {
            "v": 1,
            "issuer_did": "did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js",
            "satellite_id": "",
            "nonce": "00112233445566778899aabbccddeeff",
            "max_uses": 4,
            "uses_count": 0,
            "tier": "member",
            "created_at": 1767225600,
            "expires_at": 1776993600,
            "scope": ["join", "relay:read"],
            "signature": (
                "2YNR75QEdCzKmHHbSsFqG3FJfAWhfRZCCZBypDG3pB42A44ib48Hvg3cjjZQ8zpCYr9NsDR8fo5aqmnWSb38ZPFN"
            ),
        }
        expected_canonical = (
            '{"created_at":1767225600,"expires_at":1776993600,'
            '"issuer_did":"did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js",'
            '"max_uses":4,"nonce":"00112233445566778899aabbccddeeff",'
            '"satellite_id":"","scope":["join","relay:read"],'
            '"tier":"member","uses_count":0,"v":1}'
        )

        self.assertEqual(invite_tokens.canonical_payload(vector).decode("utf-8"), expected_canonical)
        invite_tokens.verify_token_signature(vector)

    def test_rust_minted_vector_survives_every_input_encoding(self):
        """The real minter's envelope must decode identically however it is carried."""
        vector = {
            "v": 1,
            "issuer_did": "did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js",
            "satellite_id": "",
            "nonce": "00112233445566778899aabbccddeeff",
            "max_uses": 4,
            "uses_count": 0,
            "tier": "member",
            "created_at": 1767225600,
            "expires_at": 1776993600,
            "scope": ["join", "relay:read"],
            "signature": (
                "2YNR75QEdCzKmHHbSsFqG3FJfAWhfRZCCZBypDG3pB42A44ib48Hvg3cjjZQ8zpCYr9NsDR8fo5aqmnWSb38ZPFN"
            ),
        }
        for raw in (
            json.dumps(vector),
            _b64url(vector),
            base58.b58encode(json.dumps(vector).encode("utf-8")).decode("ascii"),
        ):
            self.assertEqual(invite_tokens.parse_token_input(raw), vector)
            invite_tokens.verify_token_signature(invite_tokens.parse_token_input(raw))

    def test_canonical_payload_is_sorted_compact_and_signature_excluded(self):
        token = _mint(self.key)
        text = invite_tokens.canonical_payload(token).decode("utf-8")

        self.assertTrue(text.startswith('{"created_at":'))
        self.assertTrue(text.endswith('"v":1}'))
        self.assertNotIn(": ", text)
        self.assertNotIn(", ", text)
        self.assertNotIn("signature", text)

        keys = [
            "created_at", "expires_at", "issuer_did", "max_uses", "nonce",
            "satellite_id", "scope", "tier", "uses_count", "v",
        ]
        cursor = 0
        for key in keys:
            needle = f'"{key}":'
            position = text.find(needle)
            self.assertGreaterEqual(position, cursor, f"keys out of order at {key}")
            cursor = position + len(needle)

    def test_digest_is_sha256_of_canonical_payload(self):
        token = _mint(self.key)
        self.assertEqual(
            invite_tokens.token_digest(token),
            hashlib.sha256(invite_tokens.canonical_payload(token)).digest(),
        )

    def test_absent_satellite_id_verifies_as_portable_token(self):
        """The minter encodes portable tokens as ""; omitting the field must match."""
        token = _mint(self.key)
        del token["satellite_id"]
        invite_tokens.verify_token_signature(token)

    def test_did_key_extraction_rejects_foreign_multicodec(self):
        self.assertIsNone(invite_tokens.ed25519_pubkey_from_did("did:key:z6Mkabc123"))
        self.assertIsNone(invite_tokens.ed25519_pubkey_from_did("did:web:iyou.me:user:1"))
        self.assertIsNotNone(invite_tokens.ed25519_pubkey_from_did(_did_of(self.key)))


class TokenInputEncodingTest(TestCase):
    """Raw JSON, Base64URL and Base58 encodings all resolve to the same token."""

    def setUp(self):
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.token = _mint(self.key, nonce=_nonce())

    def test_raw_json_parses(self):
        self.assertEqual(invite_tokens.parse_token_input(json.dumps(self.token)), self.token)
        self.assertTrue(invite_tokens.is_cryptographic_invite(json.dumps(self.token)))

    def test_base64url_parses_with_and_without_padding(self):
        padded = urlsafe_b64encode(json.dumps(self.token).encode("utf-8")).decode("ascii")
        unpadded = padded.rstrip("=")
        self.assertEqual(invite_tokens.parse_token_input(padded), self.token)
        self.assertEqual(invite_tokens.parse_token_input(unpadded), self.token)

    def test_base58_json_parses(self):
        wrapped = base58.b58encode(json.dumps(self.token).encode("utf-8")).decode("ascii")
        self.assertEqual(invite_tokens.parse_token_input(wrapped), self.token)

    def test_legacy_static_key_is_not_mistaken_for_a_token(self):
        self.assertIsNone(invite_tokens.parse_token_input("INVITE-BETA-001"))
        self.assertIsNone(invite_tokens.parse_token_input(""))
        self.assertIsNone(invite_tokens.parse_token_input(None))
        self.assertFalse(invite_tokens.is_cryptographic_invite("INVITE-BETA-001"))

    def test_unsigned_json_object_is_not_a_token(self):
        self.assertIsNone(invite_tokens.parse_token_input(json.dumps({"v": 1, "nonce": "c" * 32})))


@override_settings(SYSTEM_GATE_ENABLED=True)
class RedemptionAcceptanceTest(TestCase):
    """Valid RFC-002 tokens open the airlock through every accepted transport."""

    def setUp(self):
        self.client = TestClient()
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.issuer_did = _did_of(self.key)
        self.settings_ctx = override_settings(
            ADMIN_DID=self.issuer_did,
            BETA_ACCESS_ALLOWLIST=[],
            BETA_INVITE_KEYS=[],
        )
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)
        cache.clear()
        self.redeem_url = reverse("auth_bridge:gate_redeem")

    def test_raw_json_token_via_post_grants_access(self):
        token = _mint(self.key, nonce=_nonce())
        resp = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})

        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))
        self.assertEqual(self.client.session["beta_invite_issuer_did"], self.issuer_did)
        self.assertEqual(self.client.session["beta_invite_nonce"], token["nonce"])
        self.assertEqual(self.client.session["beta_invite_tier"], "member")

    def test_base64url_token_via_get_invite_parameter(self):
        token = _mint(self.key, nonce=_nonce())
        resp = self.client.get(self.redeem_url, {"invite": _b64url(token), "next": "/auth/login/"})

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/auth/login/")
        self.assertTrue(self.client.session.get("beta_access"))

    def test_base64url_token_via_get_t_parameter(self):
        token = _mint(self.key, nonce=_nonce())
        resp = self.client.get(self.redeem_url, {"t": _b64url(token)})

        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))

    def test_base64url_token_via_post(self):
        token = _mint(self.key, nonce=_nonce())
        resp = self.client.post(self.redeem_url, {"invite_key": _b64url(token)})

        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))

    def test_allowlisted_issuer_is_authorized(self):
        delegator = ed25519.Ed25519PrivateKey.generate()
        token = _mint(delegator, nonce=_nonce())
        with override_settings(BETA_ACCESS_ALLOWLIST=[_did_of(delegator)]):
            resp = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})

        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))
        self.assertEqual(self.client.session["beta_invite_issuer_did"], _did_of(delegator))

    def test_provenance_persisted_on_user_after_verified_did(self):
        pending_did = _did_of(ed25519.Ed25519PrivateKey.generate())
        session = self.client.session
        session["verified_pending_did"] = pending_did
        session["verified_pending_next_url"] = "/auth/login/"
        session.save()

        token = _mint(self.key, nonce=_nonce())
        resp = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})

        self.assertEqual(resp.status_code, 302)
        user = User.objects.get(custodial_did=pending_did)
        self.assertEqual(user.beta_invite_issuer_did, self.issuer_did)
        self.assertEqual(user.beta_invite_nonce, token["nonce"])
        self.assertIsNotNone(user.beta_invite_redeemed_at)
        self.assertIsNone(self.client.session.get("verified_pending_did"))

    def test_guest_tier_does_not_admit(self):
        token = _mint(self.key, tier="guest", nonce=_nonce())
        resp = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})

        self.assertEqual(resp.status_code, 403)
        self.assertFalse(self.client.session.get("beta_access"))
        self.assertIn("read-only", resp.content.decode())


class RedemptionRejectionTest(TestCase):
    """Every RFC-002 denial path leaves the airlock shut."""

    def setUp(self):
        self.client = TestClient()
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.issuer_did = _did_of(self.key)
        self.settings_ctx = override_settings(
            SYSTEM_GATE_ENABLED=True,
            ADMIN_DID=self.issuer_did,
            BETA_ACCESS_ALLOWLIST=[],
            BETA_INVITE_KEYS=[],
        )
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)
        cache.clear()
        self.redeem_url = reverse("auth_bridge:gate_redeem")

    def _assert_denied(self, resp):
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(self.client.session.get("beta_access"))

    def test_expired_token_rejected(self):
        now = int(time.time())
        token = _mint(self.key, created_at=now - 172_800, expires_at=now - 86_400, nonce=_nonce())
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_expiry_boundary_is_inclusive(self):
        now = int(time.time())
        token = _mint(self.key, expires_at=now, nonce=_nonce())
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_tampered_payload_rejected(self):
        nonce = _nonce()
        token = _mint(self.key, nonce=nonce)
        token["max_uses"] = 4
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_tampered_signature_rejected(self):
        token = _mint(self.key, nonce=_nonce())
        token["signature"] = base58.b58encode(b"\x00" * 64).decode("ascii")
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_signature_from_another_key_rejected(self):
        nonce = _nonce()
        token = _mint(self.key, nonce=nonce)
        forged = _mint(ed25519.Ed25519PrivateKey.generate(), nonce=nonce)
        token["signature"] = forged["signature"]
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_unauthorized_issuer_rejected(self):
        outsider = ed25519.Ed25519PrivateKey.generate()
        token = _mint(outsider, nonce=_nonce())
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_short_nonce_rejected(self):
        token = _mint(self.key, nonce="abcd")
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_unsupported_version_rejected(self):
        token = _mint(self.key, v=2, nonce=_nonce())
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_max_uses_above_ceiling_rejected(self):
        token = _mint(self.key, max_uses=9, nonce=_nonce())
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_lifetime_beyond_90_days_rejected(self):
        now = int(time.time())
        token = _mint(self.key, created_at=now, expires_at=now + 91 * 86_400, nonce=_nonce())
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_single_use_token_cannot_be_replayed(self):
        token = _mint(self.key, max_uses=1, nonce=_nonce())
        first = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})
        self.assertEqual(first.status_code, 302)

        self.client.cookies.clear()
        replay = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})
        self._assert_denied(replay)

    def test_use_budget_is_exhausted_exactly_at_max_uses(self):
        token = _mint(self.key, max_uses=4, nonce=_nonce())
        for attempt in range(4):
            self.client.cookies.clear()
            resp = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})
            self.assertEqual(resp.status_code, 302, f"redemption {attempt + 1} should succeed")

        self.client.cookies.clear()
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_issuer_declared_uses_count_is_honored(self):
        """A token already partly spent at mint time must not get a fresh budget."""
        token = _mint(self.key, max_uses=2, uses_count=1, nonce=_nonce())
        first = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})
        self.assertEqual(first.status_code, 302)

        self.client.cookies.clear()
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": json.dumps(token)}))

    def test_distinct_nonces_do_not_share_a_budget(self):
        first = _mint(self.key, max_uses=1, nonce=_nonce())
        second = _mint(self.key, max_uses=1, nonce=_nonce())
        self.assertEqual(self.client.post(self.redeem_url, {"invite_key": json.dumps(first)}).status_code, 302)
        self.client.cookies.clear()
        self.assertEqual(self.client.post(self.redeem_url, {"invite_key": json.dumps(second)}).status_code, 302)

    def test_garbage_input_falls_back_to_the_legacy_key_path(self):
        self._assert_denied(self.client.post(self.redeem_url, {"invite_key": "not-a-real-invite"}))

    def test_method_not_allowed_for_put(self):
        self.assertEqual(self.client.put(self.redeem_url).status_code, 405)


@override_settings(SYSTEM_GATE_ENABLED=True, ADMIN_DID="did:key:z6Mkunrelated", BETA_INVITE_KEYS=[])
class LegacyRedemptionTest(TestCase):
    """The pre-existing static-key and waitlist-DID paths must keep working."""

    def setUp(self):
        self.client = TestClient()
        self.redeem_url = reverse("auth_bridge:gate_redeem")

    def test_static_invite_key_still_redeems(self):
        with override_settings(BETA_INVITE_KEYS=["INVITE-BETA-001"]):
            resp = self.client.post(self.redeem_url, {"invite_key": "INVITE-BETA-001"})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))
        self.assertIsNone(self.client.session.get("beta_invite_issuer_did"))

    def test_static_invite_key_via_get(self):
        with override_settings(BETA_INVITE_KEYS=["INVITE-BETA-001"]):
            resp = self.client.get(self.redeem_url, {"invite": "INVITE-BETA-001"})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))

    def test_unissued_static_key_still_rejected(self):
        resp = self.client.post(self.redeem_url, {"invite_key": "NEVER-ISSUED"})
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(self.client.session.get("beta_access"))

    def test_admin_did_waitlist_path_still_redeems(self):
        resp = self.client.post(self.redeem_url, {"did": "did:key:z6Mkunrelated"})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))

    def test_allowlisted_did_waitlist_path_still_redeems(self):
        with override_settings(BETA_ACCESS_ALLOWLIST=["did:key:z6Mkbeta"]):
            resp = self.client.post(self.redeem_url, {"did": "did:key:z6Mkbeta"})
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))


class AirlockEndToEndTest(TestCase):
    """Gate trip → RFC-002 redemption → auto-login, as a real tap would flow."""

    def setUp(self):
        self.client = TestClient()
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.member_key = ed25519.Ed25519PrivateKey.generate()
        self.member_did = _did_of(self.member_key)
        self.settings_ctx = override_settings(
            SYSTEM_GATE_ENABLED=True,
            ADMIN_DID=_did_of(self.key),
            BETA_INVITE_KEYS=[],
        )
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)
        cache.clear()
        self.redeem_url = reverse("auth_bridge:gate_redeem")

    def _master_vp(self, challenge: str, holder: str) -> dict:
        from auth_bridge.tests import _sign

        return _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": holder,
                "challenge": challenge,
                "verifiableCredential": [],
                "issuer": holder,
            },
            self.member_key,
        )

    def test_rfc002_token_admits_a_gated_did(self):
        challenge = self.client.post(
            reverse("auth_bridge:challenge"), content_type="application/json"
        ).json()["challenge"]

        verify = self.client.post(
            reverse("auth_bridge:verify_signature"),
            data=json.dumps(
                {
                    "verifiable_presentation": self._master_vp(challenge, self.member_did),
                    "challenge": challenge,
                    "next_url": "/auth/login/",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(verify.status_code, 403)
        self.assertEqual(self.client.session["verified_pending_did"], self.member_did)

        token = _mint(self.key, nonce=_nonce())
        redeem = self.client.post(
            reverse("auth_bridge:gate_redeem"),
            {"invite": _b64url(token), "did": self.member_did, "next": "/auth/login/"},
        )

        self.assertEqual(redeem.status_code, 302)
        self.assertTrue(self.client.session.get("beta_access"))
        self.assertIn("_auth_user_id", self.client.session)
        user = User.objects.get(custodial_did=self.member_did)
        self.assertEqual(user.beta_invite_issuer_did, _did_of(self.key))
        self.assertEqual(user.beta_invite_nonce, token["nonce"])

        # The redeemed session now clears the airlock on the next ingress.
        from auth_bridge.views import _did_passes_gate

        request = RequestFactory().get("/")
        request.session = self.client.session
        self.assertTrue(_did_passes_gate(request, self.member_did))

    def test_token_error_is_surfaced_on_the_gate(self):
        token = _mint(self.key, nonce=_nonce())
        token["tier"] = "admin"
        resp = self.client.post(self.redeem_url, {"invite_key": json.dumps(token)})

        self.assertEqual(resp.status_code, 403)
        self.assertIn("not valid", resp.content.decode())

    def test_failed_redemption_preserves_the_stashed_did_for_retry(self):
        """A rejected token must not burn the pending DID the caller already proved."""
        pending_did = _did_of(ed25519.Ed25519PrivateKey.generate())
        session = self.client.session
        session["verified_pending_did"] = pending_did
        session["verified_pending_next_url"] = "/auth/login/"
        session.save()

        expired = _mint(self.key, created_at=1, expires_at=2, nonce=_nonce())
        denied = self.client.post(self.redeem_url, {"invite_key": json.dumps(expired)})
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.client.session["verified_pending_did"], pending_did)
        self.assertIn(pending_did, denied.content.decode())

        good = _mint(self.key, nonce=_nonce())
        granted = self.client.post(self.redeem_url, {"invite_key": json.dumps(good)})
        self.assertEqual(granted.status_code, 302)
        self.assertIsNone(self.client.session.get("verified_pending_did"))
        self.assertIn("_auth_user_id", self.client.session)


@override_settings(SYSTEM_GATE_ENABLED=True, BETA_INVITE_KEYS=[])
class CanonicalAirlockRouteTest(TestCase):
    """
    The `/airlock/?invite=…` link published in `iyou_home` invite QR codes.

    Registered at the top level in `config/urls.py` (not under the `/auth/`
    namespaced include) because the QR encodes an absolute `https://iyou.me`
    path, and it is scanned cold — no OIDC request is in flight to resume.
    """

    def setUp(self):
        self.client = TestClient()
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.issuer_did = _did_of(self.key)
        self.settings_ctx = override_settings(ADMIN_DID=self.issuer_did, BETA_ACCESS_ALLOWLIST=[])
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)
        cache.clear()
        self.airlock_url = reverse("airlock")

    def test_canonical_route_is_top_level(self):
        self.assertEqual(self.airlock_url, "/airlock/")

    def test_valid_base64_token_grants_access_and_redirects(self):
        token = _mint(self.key, nonce=_nonce())

        resp = self.client.get(f"{self.airlock_url}?invite={_b64url(token)}")

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/")
        self.assertIs(self.client.session["beta_access"], True)
        self.assertEqual(self.client.session["beta_invite_issuer_did"], self.issuer_did)
        self.assertEqual(self.client.session["beta_invite_nonce"], token["nonce"])

    def test_explicit_next_is_honoured(self):
        token = _mint(self.key, nonce=_nonce())

        resp = self.client.get(f"{self.airlock_url}?invite={_b64url(token)}&next=/auth/login/")

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/auth/login/")
        self.assertIs(self.client.session["beta_access"], True)

    def test_expired_token_renders_the_form_with_an_error(self):
        now = int(time.time())
        token = _mint(self.key, created_at=now - 172_800, expires_at=now - 86_400, nonce=_nonce())

        resp = self.client.get(f"{self.airlock_url}?invite={_b64url(token)}")

        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("beta_access", self.client.session)
        self.assertIn("expired", resp.content.decode())
        self.assertIn('name="invite_key"', resp.content.decode())

    def test_tampered_token_renders_the_form_with_an_error(self):
        token = _mint(self.key, nonce=_nonce())
        token["max_uses"] = 4

        resp = self.client.get(f"{self.airlock_url}?invite={_b64url(token)}")

        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("beta_access", self.client.session)
        self.assertIn("not valid", resp.content.decode())

    def test_bare_visit_renders_the_form_without_a_failure_message(self):
        """Scanning the link with the token stripped is a landing, not a rejection."""
        resp = self.client.get(self.airlock_url)

        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("beta_access", self.client.session)
        body = resp.content.decode()
        self.assertIn('name="invite_key"', body)
        self.assertNotIn("has not been issued", body)

    def test_garbage_token_renders_the_form_with_an_error(self):
        resp = self.client.get(f"{self.airlock_url}?invite=not-a-real-token")

        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("beta_access", self.client.session)
        self.assertIn("has not been issued", resp.content.decode())

    def test_redeemed_airlock_session_passes_the_gate(self):
        token = _mint(self.key, nonce=_nonce())
        self.assertEqual(self.client.get(f"{self.airlock_url}?invite={_b64url(token)}").status_code, 302)

        from auth_bridge.views import _did_passes_gate

        request = RequestFactory().get("/")
        request.session = self.client.session
        self.assertTrue(_did_passes_gate(request, "did:key:z6Mkstranger"))
