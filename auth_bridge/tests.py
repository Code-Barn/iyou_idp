"""
Integration tests for the DID challenge-response authentication flow.
"""
import json
import base58
from django.test import TestCase, Client
from django.core.cache import cache
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def _make_did(pub_bytes: bytes) -> str:
    multicodec = bytes([0xed, 0x01]) + pub_bytes
    return "did:key:z" + base58.b58encode(multicodec).decode("ascii")


def _sign(obj: dict, private_key, exclude: set = None) -> dict:
    """Return a copy of *obj* with an Ed25519 proof attached.

    The proof is computed over the JSON serialisation of *obj* (without
    the keys listed in *exclude*, defaulting to ``{"proof"}``).
    """
    exclude = exclude or {"proof"}
    payload = {k: v for k, v in obj.items() if k not in exclude}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(raw)
    return {
        **obj,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2025-01-01T00:00:00Z",
            "verificationMethod": f"{obj['holder']}#keys-1",
            "proofPurpose": "authentication",
            "signatureValue": base58.b58encode(sig).decode("ascii"),
        },
    }


def _sign_vc(vc: dict, private_key) -> dict:
    payload = {k: v for k, v in vc.items() if k != "proof"}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(raw)
    return {
        **vc,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2025-01-01T00:00:00Z",
            "verificationMethod": f"{vc['issuer']}#keys-1",
            "proofPurpose": "assertionMethod",
            "signatureValue": base58.b58encode(sig).decode("ascii"),
        },
    }


class ChallengeResponseCycleTest(TestCase):
    """Full end-to-end: request challenge → build VP → verify → session."""

    def setUp(self):
        self.client = Client()
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.did = _make_did(pub_bytes)

    def test_full_cycle_creates_session(self):
        # 1. Request a challenge
        resp = self.client.post("/auth/challenge/", content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("challenge", data)
        challenge = data["challenge"]

        # 2. Build a signed VC and wrap it in a signed VP
        vc = _sign_vc(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": self.did,
                "issuanceDate": "2025-01-01T00:00:00Z",
                "credentialSubject": {"id": self.did, "name": "Test"},
            },
            self.private_key,
        )

        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "verifiableCredential": [vc],
            },
            self.private_key,
        )

        # 3. Submit VP for verification
        resp = self.client.post(
            "/auth/verify/",
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": challenge,
            }),
            content_type="application/json",
        )

        # 4. Assert success and user session
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["user"]["did"], self.did)
        self.assertTrue(body["user"]["is_authenticated"])
        self.assertIsNotNone(body["user"]["session_id"])

    def test_missing_fields_returns_400(self):
        resp = self.client.post(
            "/auth/verify/",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_expired_challenge_returns_404(self):
        vc = _sign_vc(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": self.did,
                "issuanceDate": "2025-01-01T00:00:00Z",
                "credentialSubject": {"id": self.did},
            },
            self.private_key,
        )
        vp = _sign(
            {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "holder": self.did,
                "verifiableCredential": [vc],
            },
            self.private_key,
        )
        resp = self.client.post(
            "/auth/verify/",
            data=json.dumps({
                "verifiable_presentation": vp,
                "challenge": "nonexistent-uuid",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404)
