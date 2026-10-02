# Satellite Coordination Index

**Hub:** `omni_social`
**Last synced:** 2026-10-02

Each satellite repo has a `TODO.md` in its root, orchestrated from this central hub.
Edit tasks here first, then propagate to the satellite repos via their agents.

---

## TODO Registry

### Ecosystem Bar Apps (20-App Ecosystem Roster)

| App | Repo | TODO.md | Auth Status | Key Items |
|:---|:---|:---|:---|:---|
| iyou_idp | `~/CODE_BASE/iyou_idp/` | [TODO.md](../../../iyou_idp/TODO.md) | ✅ Hardened / Operational | System root. Public client config, secret removal. SEC-001 pending. |
| iyou_wun | `~/CODE_BASE/iyou_wun/` | [TODO.md](../../../iyou_wun/TODO.md) | ✅ Hardened / Operational | **Golden baseline.** Federated login, inline redirection, single-window UX loop, and admin panel privilege matching verified in production over revision 24. |
| iyou_poly | `~/CODE_BASE/iyou_poly/` | [TODO.md](../../../iyou_poly/TODO.md) | ✅ Hardened / Operational | PKCE configuration confirmed, backend resolution verified over ModelBackend. |
| iyou_name | `~/CODE_BASE/iyou_name/` | [TODO.md](../../../iyou_name/TODO.md) | ✅ Hardened / Operational | Import error resolved by transitioning class hierarchy to canonical ModelBackend foundations. |
| iyou_hive | `~/CODE_BASE/iyou_hive/` | [TODO.md](../../../iyou_hive/TODO.md) | 🟢 Hardened Greenfield (Phase 7 Complete) | React 19 + Vite SPA (Omni-Canvas), Django 5.2 Headless DRF API. Color: orange (#F97316 / #F59E0B amber accents). Domain: https://hive.iyou.me. Flagship React SPA reference implementation. |
| iyou_ride | `~/CODE_BASE/iyou_ride/` | [TODO.md](../../../iyou_ride/TODO.md) | ✅ Hardened / Operational | SessionMiddleware at index 2. 4-rule alignment complete. |
| dc_tech_website | `~/CODE_BASE/dc_tech_website/` | [TODO.md](../../../dc_tech_website/TODO.md) | ✅ Hardened / Operational | Proxy header, public client, state relay — all verified. |
| iyou_safe | `~/CODE_BASE/iyou_safe/` | [TODO.md](../../../iyou_safe/TODO.md) | ✅ Hardened / Operational | Exception guard, proxy header, public client, state relay — all verified. |
| iyou_talk | `~/CODE_BASE/iyou_talk/` | [TODO.md](../../../iyou_talk/TODO.md) | ✅ Hardened / Operational | 4-rule alignment complete. |
| iyou_clar | `~/CODE_BASE/iyou_clar/` | [TODO.md](../../../iyou_clar/TODO.md) | ✅ Hardened / Operational | Zero-secret backend. Proxy header, state relay, dirty-flag — all verified. |
| iyou_play | `~/CODE_BASE/iyou_play/` | [TODO.md](../../../iyou_play/TODO.md) | ✅ Hardened / Operational | Reference implementation. Standard mozilla_django_oidc defaults. |
| iyou_blog | `~/CODE_BASE/iyou_blog/` | [TODO.md](../../../iyou_blog/TODO.md) | 🟡 Onboarding | Deep Django layout. CDN tailwind (Rule 7), secret present (Rule 2), generic OIDC backend (needs PKCE). |
| iyou_help | `~/CODE_BASE/iyou_help/` | [TODO.md](../../../iyou_help/TODO.md) | ✅ Operational | Help & Support. Color: `red`. |
| iyou_draw | `~/CODE_BASE/iyou_draw/` | [TODO.md](../../../iyou_draw/TODO.md) | 🟡 Onboarding (target: PKCE Secretless) | Visual Creation Studio. Color: `fuchsia`. Client ID: `iyou-draw-satellite-client`. Dev port: 8011. |
| iyou_life | `~/CODE_BASE/iyou_life/` | [TODO.md](../../../iyou_life/TODO.md) | 🟢 Operational (PKCE Secretless) | Life Stories & Legacy. Color: `sky`. Client ID: `iyou-life-satellite-client`. Dev port: 8013. Cookie namespaces: `life_sessionid`, `life_csrftoken`. |
| iyou_walk | `~/CODE_BASE/iyou_walk/` | [TODO.md](../../../iyou_walk/TODO.md) | 🟡 Onboarding | Pedestrian Mesh & Dog Walking Coordination. Color: `green`. Dev port: 8015. Domain: `walk.iyou.me`. |
| iyou_stay | `~/CODE_BASE/iyou_stay/` | [TODO.md](../../../iyou_stay/TODO.md) | 🟡 Onboarding | Hospitality & Accommodation. Color: `yellow`. |
| iyou_dev | `~/CODE_BASE/iyou_dev/` | [TODO.md](../../../iyou_dev/TODO.md) | 🟡 Onboarding | Developer Portal & API Docs. Color: `zinc`. |
| iyou_spot | `~/CODE_BASE/iyou_spot/` | [TODO.md](../../../iyou_spot/TODO.md) | 🟡 Onboarding | Local Discovery & Recommendations. Color: `pink`. |
| iyou_baba | `~/CODE_BASE/iyou_baba/` | [TODO.md](../../../iyou_baba/TODO.md) | 🟢 Operational (PKCE Secretless) | Sovereign Sticker Vault, Discovery Index & Curation Foundry. Color: `blue`. Domain: `baba.iyou.me`. Dev port: 8016. Cookie namespaces: `baba_sessionid`, `baba_csrftoken`. |

### Supporting Projects (Not in Ecosystem Bar)

| Repo | Stack | TODO.md | Key Items |
|:---|:---|:---|:---|
| iyou_home | Tauri/TypeScript | [TODO.md](../../../iyou_home/TODO.md) | Local desktop enclave. Released v0.2.2 (RFC-001 through RFC-006 implemented). SEC-002/003/004/005/006. |
| did_rust | Rust crate | [TODO.md](../../../did_rust/TODO.md) | Core DID library. SEC-003 alignment enforcement. Shared by idp + home. |
| iyou_mobile | Tauri/React | [TODO.md](../../../iyou_mobile/TODO.md) | Mobile counterpart. Barcode scanner, deep-link, secure storage. |

---

## Active Coordinations

### PKCE Alignment Rollout (Ecosystem-Wide)

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| Rule 1 — Proxy Header | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | Add `SECURE_PROXY_SSL_HEADER` to settings.py |
| Rule 2 — Public Client | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | Backend must inherit `auth.Backend`. Strip `OIDC_RP_CLIENT_SECRET`. |
| Rule 3 — State Relay | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | Callback must override `get_backend_kwargs()`, not `get()` |
| Rule 4 — Profile Anchoring | poly, hive, ride, safe, talk, clar, blog, draw | Open | `get_username()` pinned to `sub` claim. No email fallback. |
| Scope Alignment | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | `OIDC_RP_SCOPES = "openid profile email"` — matches IDP default. Not `"openid"` alone. |
| Privilege Evaluation | poly, name, hive, ride, safe, talk, clar, blog, draw | Open | `settings.ADMIN_DID` (not `os.environ.get`). Uses `save(update_fields=[...])`. |
| Dirty-FFlag Pattern | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | `user.save()` only when state changes |
| Exception Guard | poly, name, hive, ride, dctech, talk, clar, blog, draw | Open | `try/except requests.RequestException` on HTTP calls |
| Secret Stripping | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | Remove `OIDC_RP_CLIENT_SECRET` from container manifests |
| Rule 5 — Logout View | poly, name, hive, ride, dctech, safe, talk, clar, blog, draw | Open | Add `path("oidc/logout/", OIDCLogoutView.as_view(), name="oidc_logout")` to config/urls.py |
| Rule 6 — No Loopbacks | all satellites | Open | No `ws://127.0.0.1:9001` or `http://127.0.0.1` in templates. Use `wss://home.iyou.me:9001`. |
| Rule 7 — No Runtime CSS Compilers | all satellites | Open | Remove `cdn.tailwindcss.com` scripts. Use pre-compiled static CSS. |
| Rule 8 — Local Asset Vendoring | all satellites | Open | Vendor converse.js, bootstrap, icon fonts locally. No hotlinked CDNs (unpkg, cdnjs). |

### Layout / UI

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| Ecosystem bar gap drift | iyou_name | Resolved | Scoped reset applied 2026-07-14 |
| Bootstrap→Tailwind eval | iyou_name | Potential | Not committed — pending decision |

### Geographic Locality Subdomains & TLS

- **Authoritative DNS Wildcard Resolution:** 1984.is authoritative DNS already wildcard-resolves `*.iyou.me` at any depth to `89.127.234.121` under RFC 1034 / RFC 4592. No per-locality DNS records are required.
- **Let's Encrypt & RFC 6125 Constraints:** Let's Encrypt HTTP-01 challenges do not issue wildcard certificates (`*.app.iyou.me`), causing wildcard ACME orders to stall indefinitely. Furthermore, RFC 6125 restricts x509 wildcard certificates to a single label depth (`*.app.iyou.me` matches only `us.<app>.iyou.me`, not multi-tier scopes like `dkc.il.us.<app>.iyou.me`).
- **Production Standard (Multi-SAN HTTP-01):** The working production standard is explicit Multi-SAN HTTP-01 certificates (established by `iyou_clar`, now standardizing across `poly` and `wun`). Helm chart values must define explicit hierarchy SANs (`<app>.iyou.me`, `us.<app>.iyou.me`, `il.us.<app>.iyou.me`, `dkc.il.us.<app>.iyou.me`) under both `ingress.hosts` and `ingress.tls.hosts`, paired with a Traefik `IngressRoute` matching `HostRegexp('{subdomain:[a-z0-9.-]+}.<app>.iyou.me')`.

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| Multi-SAN HTTP-01 Ingress & RTL Routing | iyou_clar | ✅ Production Reference | Operational reference in `k3s_vm/apps/iyou-clar/values.yaml`: explicit SANs for `clar`, `us.clar`, `il.us.clar`, `dkc.il.us.clar`. |
| Multi-SAN HTTP-01 Ingress & RTL Routing | iyou_poly | In Progress | Standardize Multi-SAN HTTP-01 in Helm values, replacing stalling `*.poly.iyou.me` wildcard HTTP-01 entry; retain `apps.core.middleware.GeographicRoutingMiddleware`. |
| Multi-SAN HTTP-01 Ingress & RTL Routing | iyou_wun | In Progress | Standardize Multi-SAN HTTP-01 in Helm values and onboard canonical `GeographicRoutingMiddleware` with `geo_data.py`. |
| Multi-SAN HTTP-01 Ingress & RTL Routing | all geo satellites | Backlog | Apply Multi-SAN HTTP-01 hierarchy to `play`, `talk`, `life`, `safe`, `stay`, `walk`, `help`. |

### Security (see `docs/strategy/SECURITY_HARDENING.md`)

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| SEC-001 | iyou_idp | Open | Tier 3 emergency bypass lockdown. Require manual infrastructure flag. |
| SEC-002 | iyou_home | Open | Remove bundled Let's Encrypt private key. Replace with ephemeral self-signed certs. |
| SEC-003 | iyou_idp, iyou_home, did_rust, iyou_mobile | Open | did_rust submodule commit-hash alignment enforcement. |
| SEC-004 | iyou_idp, iyou_home | Open | Central SPOF mitigation — offline auth fallback. |
| SEC-005 | iyou_home | Open | Polling → Push migration (WebSocket/SSE). |
| SEC-006 | iyou_home | Open | DNS hijack mitigation — cert pinning for wss://home.iyou.me:9001. |

### DYNAMIC-L2-VOTING — Dynamic Ephemeral L2 Burners (Coercion-Resistant Governance)

Canonical spec: `PROJECT_ZERO_SPEC.md` §3.4 (+ §6 ballot signing, Appendix A frame). Enclave bridge derives a single-use burner on demand; double-vote prevention is carried exclusively by `nullifier = SHA-256(holder_did || challenge)`, keeping the ledger vote unlinkable from any persistent L2 social profile.

| Ticket | Target Repo | Status | Notes |
|---|---|---|---|
| DLV-101 — `max + 1` burner allocator | iyou_home | Open | `derivation_index = max(live indices) + 1` under single writer lock; monotonic, never reuses a retired index, skips reserved `0`/`1`. |
| DLV-102 — `DERIVE_EPHEMERAL_BURNER` frame | iyou_home | Open | User-gated only — MUST NOT be exposed on the headless `OMNI_SIGN_REQUEST` path. Fail-closed on vault load, `PopupGuard`-serialized, single-use per `challenge`. |
| DLV-103 — Non-persistence guarantee | iyou_home | Open | Burner↔ballot association MUST NOT land in `vault.json`, `contacts.json`, or any audit log. Keypair discarded, not archived, at challenge close. |
| DLV-104 — Nullifier computation | iyou_home, iyou_poly | Open | `SHA-256(holder_did \|\| challenge)` → 64 lowercase hex; independent of `derivation_index`/`profile_id`. Engine counts distinct nullifiers per challenge; duplicates refused without mutating the tally entry. |
| DLV-105 — Sensitive-ballot salt rule | iyou_poly | Open | Per-contest random salt withheld until the tally is sealed (or commit-reveal). `challenge` MUST NOT be published pre-close for votes flagged sensitive. |
| DLV-106 — Ephemeral selection UX | iyou_wun | Open | Sensitivity flag → ephemeral ballot persona; zero pre-tagged "voting persona" picker entry anywhere in the profile manager. |
| DLV-107 — Ledger linkability audit | iyou_poly | Open | Assert ledger stores no burner-DID↔nullifier index, resolves no burner DID toward the holder, and rejects any `alsoKnownAs`/controller binding on an ephemeral burner DID document. |
| DLV-108 — Conformant test vectors | iyou_home, iyou_poly | Open | Implement `PROJECT_ZERO_SPEC.md` §8 items 7–10 (allocator determinism under concurrency, single-use refusal, nullifier determinism, no reserved voting-persona field). |

### NAME-KINSHIP-GATE — Lineage & Kinship Attestation Gating (`iyou_name`)

Canonical spec: `PROJECT_ZERO_SPEC.md` §4.4. `KinshipAttestation` VCs (`parent_did`, `root_ancestor_id`, `branch_id`, `generation_depth`) gate access to a living tree branch over the Port 9001 bridge — proof of kinship without a single byte of centralized PII.

| Ticket | Target Repo | Status | Notes |
|---|---|---|---|
| NKG-101 — `KinshipAttestation` issuance | iyou_home | Open | Signed by the `branch_id` Branch Anchor (or an already-attested holder under the same `root_ancestor_id`). Enclave MUST NOT mint on a satellite's behalf. |
| NKG-102 — Bounded chain verification | iyou_home | Open | Resolve issuer → `root_ancestor_id` with `MAX_CHAIN_DEPTH = 4`; over-depth chains rejected, not truncated. Every hop independently signature-checkable so anchors verify offline. |
| NKG-103 — Zero-PII gate predicate | iyou_name | Open | `generation_depth <= 2` ∧ matching `branch_id` ∧ valid/unexpired/unrevoked proof. Integer comparison, never heuristic. Fail closed on absent, malformed, expired, revoked, or over-depth presentations. |
| NKG-104 — Port 9001 challenge wiring | iyou_name | Open | Challenge for the VP via `POLY_CREDENTIAL_REQUEST` / `sign_credential`; evaluate locally, never proxy to a third party. |
| NKG-105 — Decision-only persistence | iyou_name | Open | Store `{branch_id, decision, evaluated_at, policy}` only. No `holder_did`, `parent_did`, `root_ancestor_id`, VC bytes, or signature persisted or forwarded to logs/analytics. |
| NKG-106 — Branch/anchor management surface | iyou_name | Open | Anchor appointment, branch slug stability, and `kind:9112` revocation notice handling for living-branch scopes. |
| NKG-107 — PII-request prohibition sweep | iyou_name | Open | No legal name, date/place of birth, government ID, address, or phone may be requested by the gate — audit the branch-access flow end to end. |
| NKG-108 — Conformant test vectors | iyou_home, iyou_name | Open | Implement `PROJECT_ZERO_SPEC.md` §8 items 11–12 (deny-default matrix, zero-PII claim surface). |

### Protocol Integrity & Governance Specifications

| Specification / Plan | Path | Status | Core Focus |
|:---|:---|:---|:---|
| **Canonical Geographic Routing Spec** | [`specs/CANONICAL_GEOGRAPHIC_ROUTING_SPEC.md`](specs/CANONICAL_GEOGRAPHIC_ROUTING_SPEC.md) | Canonical Living Spec (SPEC-008) | Multi-tier geographic subdomain routing (`dkc.il.us.<app>.iyou.me`), RTL token evaluation against ISO-3166-1 / US postal codes, leading-dot `ALLOWED_HOSTS`, Traefik `HostRegexp` IngressRoute, and Multi-SAN HTTP-01 TLS standard. |
| **Project Zero Specification** | [`PROJECT_ZERO_SPEC.md`](PROJECT_ZERO_SPEC.md) | Canonical Living Spec | Tiered derivation (anchor / public persona / burners), Trust Lens selective disclosure cards, and the two coercion-resistance extensions: §3.4 Dynamic Ephemeral L2 Burners (`DYNAMIC-L2-VOTING`) and §4.4 `KinshipAttestation` lineage gating (`NAME-KINSHIP-GATE`). Port 9001 wire contract. |
| **Omni-Social Peer Federation Spec** | [`OMNI_SOCIAL_PEER_FEDERATION_SPEC.md`](OMNI_SOCIAL_PEER_FEDERATION_SPEC.md) | Canonical Living Spec | Open federation standard: DID key derivation, secretless PKCE, Nostr wire registry (kinds 0, 1, 1063, 1111, 1112, 30023, 10002), Blossom BUD-01 3-tier storage failover, and autonomous peer hub deployment (`hub.community.org`). |
| **Developer Translation Manual** | [`DEVELOPER_TRANSLATION_MANUAL.md`](DEVELOPER_TRANSLATION_MANUAL.md) | Canonical Living Manual | Comprehensive developer guide: UI layout hierarchy (Layer 0, Layer 1, Layer 2), Local Signature Bridge wire contract (port 9001: `OMNI_SIGN_REQUEST`, `RESOLVE_PEER_ALIASES`, `SYNC_TO_HOME_REQUEST`), XMPP JID sanitization rules (`{nostr_pubkey_hex}@{domain}`), and 8-step satellite onboarding. |
| **Protocol Integrity & Post-Mortem Governance** | [`PROTOCOL_INTEGRITY_AND_POST_MORTEM_GOVERNANCE.md`](strategy/PROTOCOL_INTEGRITY_AND_POST_MORTEM_GOVERNANCE.md) | Canonical Living Spec | Long-term North Star for existential risk mitigation, Perpetual Purpose Trust legal shielding, client-side invariant verification engine, Merkle vote root domain separation, temporal drift guards ($\pm 900\text{s}$), dead-man key decay, and hydra relay federation. |
| **Immediate Integrity Execution Plan** | [`IMMEDIATE_INTEGRITY_EXECUTION_PLAN.md`](strategy/IMMEDIATE_INTEGRITY_EXECUTION_PLAN.md) | Active Execution Blueprint | Tactical sprint rollout: Phase 1 near-term zero-cost engineering (Invariant Alert hook specs `INVARIANT_ALERT_PUSH`, read-only database guards, fail-closed bridge checks), Phase 2 entity ring-fencing & Purpose Trust charter drafting, Phase 3 automated key decay & community witnesses. |
| **Dependent Identity & Graduation Spec** | [`DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md`](specs/DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md) | Canonical Living Spec | Parent-stewarded minors: client-side Web-of-Trust graph distance replaces intrusive cloud age verification; `iyou_home` enclave child subkey derivation (`m/iyou/dependent/<index>`); zero-PII `DependentTokenSlot` age-bracket VCs signed by parent DID; 5-year Trust Ladder (Stages 1–3); Sovereign Graduation zero-loss key export; automated restorative intervention (`iyou_safe` → `iyou_talk` COGS/POGS routing). |
| **Universal Profile Metadata & Cross-Satellite Sync (RFC-006)** | [`specs/RFC-006-universal-profile-metadata.md`](specs/RFC-006-universal-profile-metadata.md) | Canonical Living Spec (Implemented v0.2.2) | Universal profile metadata (handle, display name, avatar, banner, bio, nip05); `SET_PROFILE_METADATA` ingress & `profile_sync` Port 9001 broadcast; Level 0 air-gap enforcement; canonical `.mesh-user-handle` / `.mesh-user-avatar` reactive DOM hydration without reload. |
| **Ecosystem Vision & Dual-Entity Charter** | [`strategy/ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md`](strategy/ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md) | Canonical Living Charter | Defines Perpetual Purpose Trust vs. Byers Brands LLC separation, OMNI mythos, moderation posture, and launch perimeter roadmap. |

---

### RFC-006 Reactive Header Hydration Rollout

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| RFC-006 — Bridge Client Event Dispatch | iyou_wun | Open | Wire bridge client to emit `window.dispatchEvent(new CustomEvent("meshProfileSync", { detail: profile }))` upon receiving `profile_sync` / `get_profile`. |
| RFC-006 — Bridge Client Event Dispatch | iyou_poly | Open | Wire bridge client to emit `window.dispatchEvent(new CustomEvent("meshProfileSync", { detail: profile }))` upon receiving `profile_sync` / `get_profile`. |
| RFC-006 — Bridge Client Event Dispatch | iyou_talk | Open | Wire bridge client to emit `window.dispatchEvent(new CustomEvent("meshProfileSync", { detail: profile }))` upon receiving `profile_sync` / `get_profile`. |

---

### Universal Geographic Subdomain Navigation System Rollout

| Milestone / Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| GEO-001 — L0 Scope Preservation | All 20 apps | Complete | Client-side geographic scope preserver (`initEcosystemScopePreservation` + `data-app-slug`) automatically rewrites cross-app anchors while preserving non-scoped roots (`idp`, `dev`). |
| GEO-002 — L1 Auth-Gated Brand Lockup | All 20 apps | Complete | Anonymous users see static monospace badge; authenticated users receive interactive scope capsule (`#geo-scope-trigger-btn`). |
| GEO-003 — Hierarchical Popover Ladder Modal | All 20 apps | Complete | Embedded `#geo-scope-modal` with right-to-left tier rendering, quick scope search, switch actions, and localStorage history. |
| GEO-004 — Fleet Template Regeneration | 18 Satellites | Complete | Fleet-wide templates regenerated via `scripts/regenerate_all.py` without Layer 2 drift. Verified with reference satellites `iyou_play` and `iyou_wun`. |

---

## Dependent Identity & Graduation — Phase Milestones (Satellite Backlogs)

Roadmap for `OMNI-DEP-GRAD-SPEC-V1` (`docs/specs/DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md`). Each satellite implements its slice of the dependent identity / sovereign graduation lifecycle. Full checklist in `OMNI_SOCIAL_DEVELOPER_GUIDE.md` §7a.

### Phase A — Enclave Key Derivation & Zero-PII Attestation (foundation)

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| DEP-101 — Child subkey derivation | iyou_home | Open | Deterministic path `m/iyou/dependent/<index>` (Ed25519, LE32 index). Leaf-keypair-only isolation. |
| DEP-102 — Parent revocation & delegation | iyou_home | Open | `kind:9112` RevocationTicket + NIP-26 DelegationToken management in the parent vault. |
| DEP-103 — Dependent OIDC client registration | iyou_idp | Open | Register child DID as dependent OIDC client; expose `dep.*` claims. |
| DEP-104 — `dep.*` claim namespace issuance | iyou_idp | Open | `DependentTokenSlot`: `bracket`, `wot_distance`, `parent_did`, `attestation_vc`, `issued_at`, `expires_at`, `revoked`. Reject expired/revoked. |
| DEP-105 — Age-bracket VC issuance | iyou_idp | Open | W3C VC signed by parent DID (no cleartext DoB). Validate parent signature during token exchange. |

### Phase B — Trust Ladder Stages 1–2 (guided → autonomous)

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| DEP-201 — Stage 1 U14 safe-relay | iyou_safe | Open | Route outbound dependent messages through `iyou_safe` content screening (restorative, not punitive). |
| DEP-202 — Inbound DM WoT filter | iyou_wun | Open | WoT distance ≤ 1 (U14) / ≤ 2 (U14-U18). Block 3rd-degree and beyond by default. |
| DEP-203 — Circle feed defaults | iyou_wun | Open | Restrict feed to approved contacts for younger brackets. Enable Stage 2 peer-circle formation at U14-U18. |
| DEP-204 — L2 burner persona derivation | iyou_home | Open | Allow dependent to derive L2 burners under `m/iyou/dependent/<index>/l2/<context_id>`; parent revocation per-burner. |
| DEP-205 — Parent-visible connection audit log | iyou_wun | Open | Encrypted audit of new peer connections (DID + timestamp only, never content) delivered to parent. |

### Phase C — Sovereign Graduation & Restorative Intervention

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| DEP-301 — Friction flag taxonomy | iyou_safe | Open | `FRIC-001` → `FRIC-005` surfaced as `kind:9112` events. No silent algorithmic shadowbanning. |
| DEP-302 — COGS/POGS restorative routing | iyou_talk | Open | Map `iyou_safe` friction flags to COGS (licensed) / POGS (peer) support. Age-appropriate routing: U14 → COGS only. |
| DEP-303 — Parent transparency tiers | iyou_safe | Open | Full friction reports for U14; severity-weighted summaries for U14-U18. |
| DEP-304 — Graduation key export ceremony | iyou_home | Open | Zero-loss export of L1 primary + L2 burners to standalone child `iyou_home`. New root seed, non-derived. |
| DEP-305 — DID republish + controller flip | iyou_home | Open | Publish updated DID doc: `controller` parent → self, `alsoKnownAs` cleared. Emit immutable graduation audit record. |
| DEP-306 — Age-gated competition categories | iyou_play | Open | Read `dep.bracket` to assign age-appropriate team formation and competition brackets. |

---

## Protocol

1. **Edit tasks here first** in this index.
2. **Propagate** to the satellite's `TODO.md` by editing the file directly.
3. **Agents** in each repo pick up tasks from their local `TODO.md`.
4. **Status updates** flow back: agent marks `[x]` in local TODO, hub syncs this index.

## Sync Status

- **Shared spec propagation** (`scripts/sync_ecosystem_specs.py`): Fully synchronized. All 21 repos carry identical copies of `AUTH_FLOW_SPECIFICATION.md`, `OMNI_SOCIAL_AUTH_STANDARDIZATION.md`, `PROJECT_ZERO_SPEC.md`, `OMNI_SOCIAL_PEER_FEDERATION_SPEC.md`, `DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md`, `RFC-006-universal-profile-metadata.md`, `DEVELOPER_TRANSLATION_MANUAL.md`, `satellite-coordination.md`, `LONG_TERM_AUTH_TOPOLOGY.md`, `STANDARD_UI_SPECIFICATION.md`, `PROTOCOL_INTEGRITY_AND_POST_MORTEM_GOVERNANCE.md`, `IMMEDIATE_INTEGRITY_EXECUTION_PLAN.md`, `_persona_enclave.html`, and `auth_pkce.py` under `docs/ecosystem_shared/`.
- **Last sync:** 2026-10-02
