# Satellite Coordination Index

**Hub:** `omni_social`
**Last synced:** 2026-07-14

Each satellite repo has a `TODO.md` in its root, orchestrated from this central hub.
Edit tasks here first, then propagate to the satellite repos via their agents.

---

## TODO Registry

### Ecosystem Bar Apps (11-App Absolute Roster)

| App | Repo | TODO.md | Auth Status | Key Items |
|:---|:---|:---|:---|:---|
| iyou_idp | `~/CODE_BASE/iyou_idp/` | [TODO.md](../../../iyou_idp/TODO.md) | ✅ Hardened | System root. Public client config, secret removal. SEC-001 pending. |
| iyou_wun | `~/CODE_BASE/iyou_wun/` | [TODO.md](../../../iyou_wun/TODO.md) | ✅ Hardened / Operational | **Golden baseline.** Federated login, inline redirection, single-window UX loop, and admin panel privilege matching verified in production over revision 24. |
| iyou_poly | `~/CODE_BASE/iyou_poly/` | [TODO.md](../../../iyou_poly/TODO.md) | ✅ Hardened / Operational | PKCE configuration confirmed, backend resolution verified over ModelBackend. |
| iyou_name | `~/CODE_BASE/iyou_name/` | [TODO.md](../../../iyou_name/TODO.md) | ✅ Hardened / Operational | Import error resolved by transitioning class hierarchy to canonical ModelBackend foundations. |
| iyou_hive | `~/CODE_BASE/iyou_hive/` | [TODO.md](../../../iyou_hive/TODO.md) | ⚠️ Blocked / Inflight 500 | Awaiting pod log extraction pass to isolate backend exception details. |
| iyou_ride | `~/CODE_BASE/iyou_ride/` | [TODO.md](../../../iyou_ride/TODO.md) | ⏳ Pending | SessionMiddleware at index 2. Needs full 4-rule alignment. |
| dc_tech_website | `~/CODE_BASE/dc_tech_website/` | [TODO.md](../../../dc_tech_website/TODO.md) | ⏳ Pending | username=did lookup done. Needs proxy header, public client, state relay. |
| iyou_safe | `~/CODE_BASE/iyou_safe/` | [TODO.md](../../../iyou_safe/TODO.md) | ⏳ Pending | Exception guard done. Needs proxy header, public client, state relay. |
| iyou_talk | `~/CODE_BASE/iyou_talk/` | [TODO.md](../../../iyou_talk/TODO.md) | ⏳ Pending | Needs full 4-rule alignment. |
| iyou_clar | `~/CODE_BASE/iyou_clar/` | [TODO.md](../../../iyou_clar/TODO.md) | ⏳ Pending | Zero-secret backend. Needs proxy header, state relay, dirty-flag. |
| iyou_play | `~/CODE_BASE/iyou_play/` | [TODO.md](../../../iyou_play/TODO.md) | — | Reference implementation. Standard mozilla_django_oidc defaults. |

### Supporting Projects (Not in Ecosystem Bar)

| Repo | Stack | TODO.md | Key Items |
|:---|:---|:---|:---|
| iyou_home | Tauri/TypeScript | [TODO.md](../../../iyou_home/TODO.md) | Local desktop enclave. SEC-002/003/004/005/006. |
| did_rust | Rust crate | [TODO.md](../../../did_rust/TODO.md) | Core DID library. SEC-003 alignment enforcement. Shared by idp + home. |
| iyou_mobile | Tauri/React | [TODO.md](../../../iyou_mobile/TODO.md) | Mobile counterpart. Barcode scanner, deep-link, secure storage. |
| iyou_name_rust | Rust + PyO3 | [TODO.md](../../../iyou_name_rust/TODO.md) | `iyou_chart_kernel` — family tree chart engine. Python bridge. |

---

## Active Coordinations

### PKCE Alignment Rollout (Ecosystem-Wide)

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| Rule 1 — Proxy Header | poly, name, hive, ride, dctech, safe, talk, clar | Open | Add `SECURE_PROXY_SSL_HEADER` to settings.py |
| Rule 2 — Public Client | poly, name, hive, ride, dctech, safe, talk, clar | Open | Backend must inherit `auth.Backend`. Strip `OIDC_RP_CLIENT_SECRET`. |
| Rule 3 — State Relay | poly, name, hive, ride, dctech, safe, talk, clar | Open | Callback must override `get_backend_kwargs()`, not `get()` |
| Rule 4 — Profile Anchoring | poly, hive, ride, safe, talk, clar | Open | `get_username()` pinned to `sub` claim. No email fallback. |
| Scope Alignment | poly, name, hive, ride, dctech, safe, talk, clar | Open | `OIDC_RP_SCOPES = "openid profile email"` — matches IDP default. Not `"openid"` alone. |
| Privilege Evaluation | poly, name, hive, ride, safe, talk, clar | Open | `settings.ADMIN_DID` (not `os.environ.get`). Uses `save(update_fields=[...])`. |
| Dirty-FFlag Pattern | poly, name, hive, ride, dctech, safe, talk, clar | Open | `user.save()` only when state changes |
| Exception Guard | poly, name, hive, ride, dctech, talk, clar | Open | `try/except requests.RequestException` on HTTP calls |
| Secret Stripping | poly, name, hive, ride, dctech, safe, talk, clar | Open | Remove `OIDC_RP_CLIENT_SECRET` from container manifests |
| Rule 5 — Logout View | poly, name, hive, ride, dctech, safe, talk, clar | Open | Add `path("oidc/logout/", OIDCLogoutView.as_view(), name="oidc_logout")` to config/urls.py |
| Rule 6 — No Loopbacks | all satellites | Open | No `ws://127.0.0.1:9001` or `http://127.0.0.1` in templates. Use `wss://home.iyou.me:9001`. |
| Rule 7 — No Runtime CSS Compilers | all satellites | Open | Remove `cdn.tailwindcss.com` scripts. Use pre-compiled static CSS. |
| Rule 8 — Local Asset Vendoring | all satellites | Open | Vendor converse.js, bootstrap, icon fonts locally. No hotlinked CDNs (unpkg, cdnjs). |

### Layout / UI

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| Ecosystem bar gap drift | iyou_name | Resolved | Scoped reset applied 2026-07-14 |
| Bootstrap→Tailwind eval | iyou_name | Potential | Not committed — pending decision |

### Security (see `docs/strategy/SECURITY_HARDENING.md`)

| Ticket | Target Repo | Status | Notes |
|:---|:---|:---|:---|
| SEC-001 | iyou_idp | Open | Tier 3 emergency bypass lockdown. Require manual infrastructure flag. |
| SEC-002 | iyou_home | Open | Remove bundled Let's Encrypt private key. Replace with ephemeral self-signed certs. |
| SEC-003 | iyou_idp, iyou_home, did_rust, iyou_mobile | Open | did_rust submodule commit-hash alignment enforcement. |
| SEC-004 | iyou_idp, iyou_home | Open | Central SPOF mitigation — offline auth fallback. |
| SEC-005 | iyou_home | Open | Polling → Push migration (WebSocket/SSE). |
| SEC-006 | iyou_home | Open | DNS hijack mitigation — cert pinning for wss://home.iyou.me:9001. |

---

## Protocol

1. **Edit tasks here first** in this index.
2. **Propagate** to the satellite's `TODO.md` by editing the file directly.
3. **Agents** in each repo pick up tasks from their local `TODO.md`.
4. **Status updates** flow back: agent marks `[x]` in local TODO, hub syncs this index.

## Sync Status

- **Shared spec propagation** (`scripts/sync_ecosystem_specs.py`): Fully synchronized. All 15 repos carry identical copies of `AUTH_FLOW_SPECIFICATION.md`, `OMNI_SOCIAL_AUTH_STANDARDIZATION.md`, `satellite-coordination.md`, and `auth_pkce.py` under `docs/ecosystem_shared/`.
- **Last sync:** 2026-07-16
