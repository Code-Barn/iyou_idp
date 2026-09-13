# TODO — iyou_idp (Identity Provider)

**Orchestrated from:** `omni_social` (central hub)
**Last synced:** 2026-09-13

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

## Layer 2 — Security Hardening

- [ ] **[Critical] SEC-001 — Tier 3 emergency bypass lockdown:** Current auto-fallback accepts auth via nonce match without cryptographic signature. Must require manual infrastructure flag (e.g., `ALLOW_EMERGENCY_BYPASS=true` at deploy time), not runtime auto-fallback.
- [ ] **[High] SEC-003 — did_rust submodule pinning:** Enforce commit-hash alignment between `iyou_idp/crates/did_rust/` and `iyou_home/libs/did_rust/` via CI check. Prevents silent `serde_json` serialization drift.
- [ ] **[High] SEC-004 — Central SPOF mitigation:** Investigate offline-capable auth fallback when iyou_idp is unreachable.
- [ ] **[Future] SEC-007 — Broaden DID ledger:** Activate `did:web` and `did:ethr` validation in `did_rust`.
- [ ] **[Future] SEC-008 — Rogue extension defense:** Evaluate nonce binding or `web_modal` redirect mode.
- [x] **Sovereign Airlock Gate (pre-launch beta):** `SYSTEM_GATE_ENABLED` (default `True`) 403s all non-exempt DIDs at every auth ingress with `beta_gate.html`; exceptions via `ADMIN_DID`, `BETA_ACCESS_ALLOWLIST`, or invite-key redemption (`/gate/redeem/`, `BETA_INVITE_KEYS`) → `session["beta_access"]` — **Done 2026-09-12**
- [x] **GDPR Legal Disclaimer Server-Side Hard Gate:** `show_legal_disclaimer` defaults `True`; `SovereignAuthorizeView` withholds front-channel OIDC codes until explicit `consent_accepted=true` at `/auth/legal-disclaimer/acknowledge/` (stamps `disclaimer_acknowledged_at`, resumes via `session["post_disclaimer_redirect"]`); unchecked-by-default consent modal — **Done 2026-09-12**
- [x] **Desktop Download Matrix Alignment (v0.2.0 under Code-Barn):** `_download_modal.html` desktop links pinned to `Code-Barn/iyou_home` v0.2.0 GitHub Releases (Windows setup/portable, macOS Intel/Apple Silicon DMG, Linux AppImage/deb) — **Done 2026-09-12**
- [ ] **Ecosystem Doc Organization:** Standardize repo layout to match iyou_wun precedent — root: `AGENT.md`, `README.md`; `docs/`: `DEVELOPER_GUIDE.md`, `DESIGN_DOC.md`, `TODO.md`, `ecosystem_shared/`, `archive/`.

---
