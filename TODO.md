# TODO — iyou_idp (Identity Provider)

**Orchestrated from:** `omni_social` (central hub)
**Last synced:** 2026-11-19

---

## Layer 0 — Ecosystem Standardization

> Templates generated via `omni_social/generate_templates.py`. Do not edit
> `_ecosystem_bar.html` or `_standard_header.html` manually — changes will be
> overwritten on next regeneration. Edit the canonical source in omni_social instead.

- [x] PKCE secretless ingress — all satellites verified — **Done 2026-07-13**

## Layer 1 — PKCE / Auth

- [x] PKCE Phase 2 complete — **Done 2026-07-13**
- [x] Identity Mesh Hardening: shifted satellite client databases to public client configurations; removed cleartext client secrets; synchronized update blocks to prevent stale data type columns during seed_clients routines — **Done 2026-07-13**
- [x] **Tier 1 Managed Login Hardening & OIDC Continuity:** Refactored `managed_login` in `auth_bridge/views.py` with sanitized `next_url` extraction (`_is_safe_public_redirect`), clean JIT user provisioning via `generate_custodial_did()`, `evaluate_sovereign_admin_posture`, Pre-Launch Airlock gate (`SYSTEM_GATE_ENABLED`), GDPR legal disclaimer gate (`show_legal_disclaimer` / `session["post_disclaimer_redirect"]`), and `_build_oidc_redirect` continuity; form context preservation in `_tab_managed.html` via hidden `next` input and query string propagation; covered by 10 integration tests in `test_managed_login.py` — **Done 2026-09-13**
- [x] **Sovereign `did:key:` posture auto-promotion & backfill:** `evaluate_sovereign_admin_posture()` promotes any `did:key:` login to `account_tier="sovereign"` / `is_sovereign=True`; migration `0014_did_key_rows_to_sovereign` backfills existing `did:key:` rows — **Done 2026-11-18**
- [x] **Authenticated dashboard overhaul:** `SOVEREIGN` (emerald) / `MANAGED FREE` / `MANAGED PREMIUM` badges; `iyou_home` opens `_download_modal.html` via `.open-download-modal`; explicit `Enter iyou_wun` CTA (`target="_blank" rel="noopener noreferrer"`); `Claim Primary Email` OTP flow on the unclaimed `Primary / Root` row; `Auto-sign in across ecosystem apps` toggle backed by `POST /auth/sso-preference/` — **Done 2026-11-18/19**
- [x] **Email Locker & Cross-Account Consolidation:** `LinkedEmail` anti-squatting registry + W3C `EmailOwnershipCredential` export; `User.merged_into` (migration `0013_user_merged_into`) with OTP-gated account merge and `/airlock/sponsor/` one-shot session-only invite provenance — **Done 2026-10-18**
- [x] **Neutral Age Gate:** `dep.*` dependent-session claims, `DependentTokenSlot` claim injection, and Zero-PII W3C age-bracket VCs with revocation (`IssuedCredential`, kind:9112 RevocationTickets) — **Done 2026-10**
- [x] **Hardened Global Logout, SSO hint & `prompt=none`:** `/auth/logout/` defaults to `/` with local-relative `?next=` validation, `Cache-Control: no-store` + `Pragma: no-cache` on `LoginPageView`, `pageshow` bfcache guard, `iyou_sso_hint` cross-subdomain cookie via `user_logged_in`/`user_logged_out` signals + `SSOHintCookieMiddleware` with opt-out, and OIDC `prompt=none` non-interactive error redirects (`login_required` / `interaction_required`) — **Done 2026-11-19**

## Layer 2 — Security Hardening

### Release 1.0 Gate — Open Items (priority order)

1. **[Critical] SEC-001 — Tier 3 emergency bypass lockdown.** Current auto-fallback accepts auth via nonce match without cryptographic signature. Gate it behind explicit `IDP_ALLOW_EMERGENCY_BYPASS` (default `False`) at deploy time; remove runtime auto-fallback.
2. **[High] Tab 2 Passkey UI wiring.** Wire `_tab_managed.html` "Sign in with Passkey" to the live `/auth/passkeys/authenticate/begin/` + `/auth/passkeys/authenticate/complete/` endpoints.
3. **[High] Desktop artifact sync.** Update `_download_modal.html` download links and magnet/IPFS hashes to the latest `iyou_home` release (`v0.2.1` / `v0.2.2`).
4. **[High] Tier 1 Vault seed + GDPR purge.** Verify Vault seed provisioning on OAuth/Email JIT creation; add a self-service GDPR Art. 17 account/index purge endpoint.
5. **[High] SEC-003 — `did_rust` submodule pinning.** Enforce commit-hash alignment across `iyou_idp`, `iyou_home`, and `iyou_mobile_swift` via CI check. Prevents silent `serde_json` serialization drift.

- [ ] **[High] SEC-004 — Central SPOF mitigation:** Investigate offline-capable auth fallback when iyou_idp is unreachable.
- [ ] **[Future] SEC-007 — Broaden DID ledger:** Activate `did:web` and `did:ethr` validation in `did_rust`.
- [ ] **[Future] SEC-008 — Rogue extension defense:** Evaluate nonce binding or `web_modal` redirect mode.
- [x] **Sovereign Airlock Gate (pre-launch beta):** `SYSTEM_GATE_ENABLED` (default `True`) 403s all non-exempt DIDs at every auth ingress with `beta_gate.html`; exceptions via `ADMIN_DID`, `BETA_ACCESS_ALLOWLIST`, or invite-key redemption (`/gate/redeem/`, `BETA_INVITE_KEYS`) → `session["beta_access"]` — **Done 2026-09-12**
- [x] **RFC-002 invite capability tokens:** `/gate/redeem/` admits signed, quota-limited invite tokens minted by `iyou_home` (raw JSON / Base64URL / Base58; `GET|POST` with `invite_key`/`invite`/`t`). Verification is the byte-level counterpart of the Rust minter, pinned by a golden vector emitted from `iyou_home` `src-tauri/src/invites.rs`; issuer recorded as Web-of-Trust provenance on both the session and `User`. Canonical invite landing `/airlock/?invite=<base64url_token>` registered at the top level in `config/urls.py` to match the absolute path `iyou_home` bakes into its QR codes — **Done 2026-09-29**
- [x] **[Medium] Flake — `test_invite_tokens` intermittent 403 — RESOLVED (2026-09-29), with a production caveat:** Before the RFC-002 work, roughly 3 of ~20 full `manage.py test auth_bridge` runs failed one positive-path redemption test with `403 != 302`, and a *different* test each run (`test_allowlisted_issuer_is_authorized`, `test_use_budget_is_exhausted_exactly_at_max_uses`, `test_guest_tier_does_not_admit`). Root cause identified as latent test-state bleed: fixtures used **static** nonces while the RFC-002 use counter lives in the process-global `ResilientCache` LocMem fallback, which is not rolled back between tests — a reused nonce presents an already-exhausted counter and is then correctly denied. Fixed by minting `uuid4().hex` nonces per call and calling `cache.clear()` in each redemption class's `setUp`. **Evidence: 25 consecutive clean runs** of the full `auth_bridge` suite in fresh processes (5 + 20, zero failures). At the original ~3-in-20 rate, 20 clean runs by chance is ~2.6%, so this is strong evidence of elimination rather than absence of evidence. **Caveat:** the loop only exercises the **LocMem fallback**, because no Redis is reachable in dev (every `claim_unit` logs `Error 61` and falls back). The production **Redis-primary** path, where `claim_unit` does a real network round-trip, is *not* covered by this evidence. If a redemption ever denies in K3s, instrument `claim_unit` for the fallback transition and check for more than one cache worker before assuming a regression.
- [x] **GDPR Legal Disclaimer Server-Side Hard Gate:** `show_legal_disclaimer` defaults `True`; `SovereignAuthorizeView` withholds front-channel OIDC codes until explicit `consent_accepted=true` at `/auth/legal-disclaimer/acknowledge/` (stamps `disclaimer_acknowledged_at`, resumes via `session["post_disclaimer_redirect"]`); unchecked-by-default consent modal — **Done 2026-09-12**
- [x] **Desktop Download Matrix Alignment (v0.2.0 under Code-Barn):** `_download_modal.html` desktop links pinned to `Code-Barn/iyou_home` v0.2.0 GitHub Releases (Windows setup/portable, macOS Intel/Apple Silicon DMG, Linux AppImage/deb) — **Done 2026-09-12**
- [ ] **Ecosystem Doc Organization:** Standardize repo layout to match iyou_wun precedent — root: `AGENT.md`, `README.md`; `docs/`: `DEVELOPER_GUIDE.md`, `DESIGN_DOC.md`, `TODO.md`, `ecosystem_shared/`, `archive/`.

---
