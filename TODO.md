# TODO — iyou_idp (Identity Provider)

**Orchestrated from:** `omni_social` (central hub)
**Last synced:** 2026-07-13

---

## Layer 0 — Ecosystem Standardization

> Templates generated via `omni_social/generate_templates.py`. Do not edit
> `_ecosystem_bar.html` or `_standard_header.html` manually — changes will be
> overwritten on next regeneration. Edit the canonical source in omni_social instead.

- [x] PKCE secretless ingress — all satellites verified — **Done 2026-07-13**

## Layer 1 — PKCE / Auth

- [x] PKCE Phase 2 complete — **Done 2026-07-13**

## Layer 2 — Security Hardening

- [ ] **[Critical] SEC-001 — Tier 3 emergency bypass lockdown:** Current auto-fallback accepts auth via nonce match without cryptographic signature. Must require manual infrastructure flag (e.g., `ALLOW_EMERGENCY_BYPASS=true` at deploy time), not runtime auto-fallback.
- [ ] **[High] SEC-003 — did_rust submodule pinning:** Enforce commit-hash alignment between `iyou_idp/crates/did_rust/` and `iyou_home/libs/did_rust/` via CI check. Prevents silent `serde_json` serialization drift.
- [ ] **[High] SEC-004 — Central SPOF mitigation:** Investigate offline-capable auth fallback when iyou_idp is unreachable.
- [ ] **[Future] SEC-007 — Broaden DID ledger:** Activate `did:web` and `did:ethr` validation in `did_rust`.
- [ ] **[Future] SEC-008 — Rogue extension defense:** Evaluate nonce binding or `web_modal` redirect mode.

---
