# iyou_idp Roadmap

**Status as of:** 2026-11-19
**Scope:** Identity Provider (`iyou_idp`) work items only. Ecosystem-wide copy and
template changes remain canonically owned by `omni_social` and are synced via
`docs/ecosystem_shared/`.

> **Conventions:** Security items carry their `SEC-xxx` identifier from
> `TODO.md`. Nothing in the Release 1.0 Gate ships with a runtime emergency
> auth bypass enabled by default.

---

## Release 1.0 Gate (Pre-Launch Must-Haves)

All five items below block the 1.0 launch. They are ordered by risk.

| # | Item | Owner focus | Acceptance | Status |
|---|------|-------------|------------|--------|
| 1 | **SEC-001 — Tier 3 emergency bypass lockdown** | `verify_signature` / `mobile_verify_signature` | Nonce-only fallback is gated behind explicit `IDP_ALLOW_EMERGENCY_BYPASS` (default `False`); no runtime auto-fallback when `DEBUG=True` on a non-loopback request. | ✅ Complete |
| 2 | **Tab 2 Passkey UI wiring** | `_tab_managed.html` | "Sign in with Passkey" calls `/auth/passkeys/authenticate/begin/` then `/auth/passkeys/authenticate/complete/`; errors surface inline and OIDC continuity is preserved. | ✅ Complete |
| 3 | **Tier 1 Vault seed verification** | OAuth / Email JIT provisioning | Every new `did:web` user has a seeded Ed25519 key at `secret/identity/{did}/ed25519`; missing seed fails provisioning loudly instead of silently. | ✅ Complete |
| 4 | **GDPR Art. 17 purge endpoint** | Self-service account deletion | Authenticated user can purge their account plus searchable indexes (User, LinkedEmail, FederatedIdentity, consent/session rows); audit log records the erasure without retaining PII. | ✅ Complete |
| 5 | **Desktop artifact sync** | `_download_modal.html` | Download links, checksums, and magnet/IPFS hashes point at the latest `iyou_home` release (`v0.2.3`). | ✅ Complete |

---

## Fleet & Infrastructure Hardening

Post-launch, before the multi-node beta expands beyond the flagship.

- **Satellite-wide federated logout + `prompt=none` rollout.** Propagate
  `/openid/end-session/` from every satellite through `PKCEOIDCLogoutView`
  (GET + POST), verify `post_logout_redirect_uris` includes `https://iyou.me/`
  on all 24 seeded clients, and exercise `prompt=none` silent SSO with
  `iyou_sso_hint` across `*.iyou.me`.
- **SEC-003 — `did_rust` submodule CI guard.** Enforce a single commit hash for
  `crates/did_rust/` across `iyou_idp`, `iyou_home`, and `iyou_mobile_swift` in
  CI; fail builds on drift to prevent `serde_json` canonicalization regressions.
- **Redis AOF persistence verification.** Confirm the ResilientCache primary
  uses append-only-file persistence so OAuth states, challenges, OTPs, and
  RFC-002 use budgets survive a Redis restart without replay or double-spend.

---

## Mobile & Multi-Node Horizon

Longer-term, dependent on ecosystem adoption.

- **`iyou_mobile_swift` UniFFI / Secure Enclave OOB integration.** Bring the
  Tier 2 `iyouauth://sign` deep link to iOS using the shared `did_rust` bridge;
  store the root `did:key` in the Secure Enclave and sign `/auth/challenge/`
  nonces for `check_challenge_status` polling.
- **SEC-004 — offline fallback assertions (✅ Complete 2026-11-19).** Codified Section 18
  `OFFLINE_CHALLENGE_VERIFY` wire protocol between satellite, browser, and `iyou_home`
  enclave in `docs/AUTH_FLOW_SPECIFICATION.md`: 300s TTL bounds, direct Ed25519 multicodec
  verification, single-use nonce tracking, forced OIDC re-validation, and strict fail-closed
  refusal on all `dep.*` dependent-session claims.
- **"Garden of IdPs" self-hosting operator guide (✅ Complete 2026-11-19).** Documented
  peer-node deployment in `docs/OPERATOR_GUIDE.md`: federation model, namespace isolation,
  WebAuthn RP IDs, WoT Sybil defense, complete `IDP_*` environment schema, production deploy
  checks (`auth_bridge/checks.py`), PostgreSQL/Redis AOF/Vault persistence, RSA rotation runbook,
  and GDPR compliance conduits.
