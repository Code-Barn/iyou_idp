# Project Zero Specification

**Tiered Identity Derivation, Peer Trust Tiers & Bridge Wire Contract**

**Hub:** `omni_social`
**Status:** Living document — canonical reference for Project Zero across the iyou_ ecosystem.
**Last updated:** 2026-08-22
**Reference implementations:** `iyou_home` (Rust/Tauri enclave), `iyou_wun` (Trust Lens client)

---

## 1. Overview & Threat Model

Project Zero is the sovereign identity protocol implemented in `iyou_home` (zero-custody desktop enclave: vault hierarchy, contact enclave, and the port 9001 resolver/signing bridge) and consumed by satellite clients such as `iyou_wun` (client-side Trust Lens).

### 1.1 Goals

1. **Zero custody** — private key material never leaves the Rust enclave; external callers see only `did:key:` strings and `nostr_pubkey_hex` values.
2. **Unlinkable personas** — deterministic derivation yields context-separated identities that resist cross-correlation.
3. **Selective disclosure** — peers learn exactly what a user chooses to reveal, nothing more.
4. **Local-first operation** — all trust decisions are made locally from locally stored data.

### 1.2 Threats Addressed

| Threat | Mitigation |
|:---|:---|
| Alias harvesting / enumeration of a user's contact graph | `MAX_RESOLVE_KEYS = 256` frame cap, exact-match-only resolution, unknown-key echo isolation (§5.2) |
| Pivoting from one alias to a peer's other identities | Minimal projection — responses never carry `peer_id`, `disclosed_aliases`, receipts, or timestamps |
| Root-seed / key-material exposure over the bridge | Secret Adjacency Guard — alias queries load only `contacts.json`, never `vault.json`; air-gap guard blocks Level 0 targets fail-closed (§5.1) |
| Anchor de-anonymization via public pickers or signing traffic | Air-Gap Invariant on Level 0 (§3.2) |
| Loopback interception | TLS termination (`wss://home.iyou.me:9001`), PNA pre-flight handling; cert pinning tracked as SEC-006 |

### 1.3 Non-Goals

- Remote/cloud key escrow (contradicts zero custody).
- Global publishability of the trust graph — the contact enclave is local-only state.
- Anonymity network transport guarantees (handled by Tor/I2P strategy in `OMNI_SOCIAL_PROTOCOL_V2.md` §6).

---

## 2. Normative Language

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 3. Tiered Derivation Model

All identity key material is derived deterministically from a single 32-byte root seed held exclusively inside the `iyou_home` enclave (`vault.json`, base58-encoded at rest).

### 3.1 Key Derivation Formulas

```
Ed25519 DID keypair        = SHA-256(root_seed || LE(derivation_index))
Nostr secp256k1 keypair    = SHA-256("secp256k1-nostr" || root_seed || LE(derivation_index))
```

Implemented by `derive_deterministic_keypair(root_seed, derivation_index)` (`iyou_home/src-tauri/src/vault.rs`). The same `(root_seed, index)` pair MUST always yield identical keys on every platform (`did_rust` is pinned by commit across consumers — SEC-003).

### 3.2 Hierarchy

```
                 ┌────────────────────────────────┐
                 │   32-byte Root Master Seed     │
                 └───────────────┬────────────────┘
                                 │
       ┌─────────────────────────┼─────────────────────────┐
       ▼                         ▼                         ▼
Derivation Index #0     Derivation Index #1        Derivation Index #2+
┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
│ Level 0: Anchor      │ │ Level 1: Primary     │ │ Level 2+: Burners    │
│ profile_id "anchor"  │ │ profile_id "primary" │ │ Contextual / Sockets │
│ 🛡 Air-Gapped Sanctum│ │ 👤 Public Persona    │ │ 🎭 Disposable Anons  │
│ is_system_reserved:  │ │ Default Active Signer│ │ Freely creatable &   │
│   true               │ │                      │ │ deletable            │
└──────────────────────┘ └──────────────────────┘ └──────────────────────┘
```

#### Level 0 — Anchor DID (Index 0)

- The immutable root persona. `level: 0`, `derivation_index: 0`, `is_system_reserved: true`.
- Reserved exclusively for private root P2P containment, high-assurance introductions, and selective-disclosure card signing.
- **Air-Gap Invariant:** Level 0 profiles MUST be filtered out of external public pickers, standard UI dropdowns, and browser-initiated WebSocket signing requests. Bridge callers MUST NOT be able to target the anchor — enforcement is fail-closed (`bridge_access_denial_reason`).
- Peer-to-peer trust circles anchored here are recorded in the Contact Enclave (§4), never broadcast.

#### Level 1 — Public Persona DID (Index 1)

- `level: 1`, `profile_id: "primary"`. Initialized automatically at bootstrap alongside the anchor (dual bootstrap: index 0 + index 1).
- **Default active signer** for:
  - OIDC challenge/VP flows (PKCE Tier 3),
  - Nostr event publishing (kinds `1`, `1111`, `30023`),
  - bridge handshakes.
- Source of `public_persona()`; the only persona exposed by un-scoped bridge queries (§5.2).

#### Level 2+ — Contextual Burner DIDs (Index 2..n)

- Disposable, topic-specific personas for isolating interactions without linking to Level 1 or Level 0.
- Created via `add_profile`, deleted via `remove_profile`. Deleting the active custom persona resets the active pointer to `"primary"`.

### 3.3 Invariants

| Invariant | Rule |
|:---|:---|
| Structural deletion guard | `remove_profile` MUST reject any target where `is_system_reserved == true \|\| derivation_index == 0 \|\| level == 0` |
| Active-pointer fallback | Deleting the active custom persona MUST reset the active profile pointer to Level 1 `"primary"` |
| Atomic staging | All store writes (`vault.json`, `contacts.json`, `preferences.json`, `auto_start.json`) MUST write to a `.tmp` file, `sync_all()`, then atomically rename |
| Corrupt-file auto-quarantine | A store file that fails to parse MUST NOT be silently overwritten; it is renamed `{filename}.corrupt_{timestamp}.bak` (up to 5 newest retained) and an explicit error is surfaced |
| Key containment | Frontends and bridge clients receive only `did:key:` strings and `nostr_pubkey_hex` values — never seeds or signing keys |

---

## 4. Trust Tiers & Selective Disclosure Cards

### 4.1 Contact Enclave

Peer records live in `{app_data}/contacts.json`, deliberately separate from `VaultStore`. Bridge alias queries load **only** this file, so un-scoped WebSocket callers can never reach root-seed or key material (**Secret Adjacency Guard**).

```rust
// Canonical schema (iyou_home/src-tauri/src/contacts.rs)
pub struct PeerContact {
    pub peer_id: String,                  // canonical DID or 64-hex Nostr pubkey
    pub display_name: String,
    pub trust_level: TrustLevel,
    pub disclosed_aliases: Vec<String>,   // bound Level 2 sock DIDs, burner nostr
                                          // hex keys, external handles
    pub attestation_receipt: Option<String>, // raw signed VC backing the intro
    pub created_at: i64,
    pub updated_at: i64,
}
```

Key normalization: tokens are trimmed; **only pure 64-char hex tokens are lowercased** (Nostr x-only keys are case-insensitive). DIDs use case-sensitive base58/multibase and MUST be matched verbatim.

### 4.2 Trust Tiers

| Trust Level | Wire Token | Badge Label | UI Theme | Binding Semantics |
|:---|:---|:---|:---|:---|
| `Level0` | `"Level0"` | **Inner Circle** | Violet / Crimson | Direct **Anchor DID binding** — peer is keyed to the Level 0 identity itself |
| `Level0_5` | `"Level0_5"` | **Trusted Alliance** | Emerald Green | Level 1 **directed attestation** linking Level 2 sock aliases to the peer without exposing the anchor |
| `Level1` | `"Level1"` | **Peer** | Slate Gray | Standard public, unlinked interaction |

Serialization notes:

- Canonical wire/storage values are the variant names verbatim: `"Level0"`, `"Level0_5"`, `"Level1"`.
- Deserialization tolerates legacy aliases (`level0`, `level0_5`, `level0.5`, `Level0.5`, `level1`, …); serialization always emits canonical form.
- Default tier for new contacts: `Level1`.

### 4.3 Selective Disclosure Cards

**Issuance (outbound introduction):**

1. User selects the signing persona — Level 0 (for Inner Circle introductions) or Level 1 (for Trusted Alliance attestations).
2. User selects the target peer DID and trust tier.
3. User checks off which personas/aliases to include (e.g., specific Level 2 sock DIDs).
4. The enclave issues a signed Verifiable Credential (`SelectiveDisclosureCard`) binding subject DID + chosen aliases under the selected tier.

**Import (inbound introduction):**

1. Validate the cryptographic signature with `did_rust::verify_vc`.
2. Extract subject DID and disclosed aliases.
3. Upsert into `contacts.json` (match on canonical `peer_id`; preserve original `created_at`, refresh `updated_at`).

---

## 5. WebSocket Bridge Wire Contract (Port 9001)

The Signature Bridge binds exclusively to `127.0.0.1:9001` with TLS termination (`wss://home.iyou.me:9001`). It is the sole cross-origin entry point for browser-based identity providers and satellite-app queries.

```
Browser / Satellite App                   iyou_home Rust Bridge (:9001)
         │                                            │
         │─── OPTIONS (PNA Pre-flight) ──────────────>│
         │<── 200 OK (PNA headers) ───────────────────│
         │                                            │
         │─── GET (Upgrade: websocket) ──────────────>│
         │<── 101 Switching Protocols ────────────────│
         │                                            │
         │─── get_profile ───────────────────────────>│
         │<── profile_sync (Level 1 Primary Only) ────│
         │                                            │
         │─── RESOLVE_PEER_ALIASES [pubkeys] ────────>│
         │<── peer_aliases_resolved (Minimal) ────────│
         │                                            │
         │─── POLY_CREDENTIAL_REQUEST ───────────────>│
         │                                            │──> PopupGuard acquire
         │                                            │──> React Approval Modal
         │                                            │<── User Approves
         │<── POLY_CREDENTIAL_PRESENTATION (VP) ──────│
```

Transport details: TLS terminated via `tokio_rustls`; Private Network Access (PNA) pre-flight handled at the TLS layer via content-based routing of the first 4 KiB.

Error frames are uniform:

```json
{"type": "error", "message": "<reason>"}
```

### 5.1 Gate Model

| Tier | Message types | Gating |
|:---|:---|:---|
| **Pre-gate** | `ping`, `get_profile`, `RESOLVE_PEER_ALIASES` | Answered inline; no approval modal, no key material, no `vault.json` access |
| **User-gated** | `sign`, `sign_event`, `sign_credential`, `POLY_CREDENTIAL_REQUEST` | Approval pipeline (window focus / popup); key operations only after user consent |
| **Headless** | `OMNI_SIGN_REQUEST` | Auto-signing without popups (scoped to governance envelopes) |

All gated frames carry an optional `profile_id`. The enclave air-gap is enforced **fail-closed**: any frame targeting the Level 0 anchor (or arriving while the vault cannot be loaded) is rejected before dispatch.

### 5.2 Pre-Gate Queries

#### `get_profile`

Un-scoped sync exposing the public persona only. The Level 0 anchor is air-gapped from external bridge callers.

```json
// Request
{"type": "get_profile"}

// Response — Level 1 Public Persona only
{"type": "profile_sync", "profile": {
    "profile_id": "primary",
    "profile_name": "...",
    "derivation_index": 1,
    "did": "did:key:z6Mk...",
    "nostr_pubkey_hex": "<64-hex>",
    "credentials": [],
    "level": 1,
    "is_system_reserved": false
}}
```

An empty/absent `profile_id` resolves to the public persona — never the anchor.

#### `RESOLVE_PEER_ALIASES`

Read-only, exact-match batch resolution against `contacts.json`.

```json
// Request
{"type": "RESOLVE_PEER_ALIASES",
 "pubkeys": ["3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
             "did:key:z6MkSockAlias"]}

// Response
{"type": "peer_aliases_resolved",
 "matches": {
   "3bf0c63f...efa459d": {"nickname": "Alice", "trust_level": "Level0_5", "badge": "Trusted Alliance"}
 },
 "unknown": ["did:key:z6MkSockAlias"]}
```

Normative rules:

1. **Harvesting Guard:** frames MUST contain between 1 and `MAX_RESOLVE_KEYS = 256` keys. Oversized frames are rejected outright with `{"type":"error","message":"too_many_pubkeys"}`; missing/invalid `pubkeys` yields `missing_or_invalid_pubkeys`.
2. **Exact match:** lookup runs against `peer_id ∪ disclosed_aliases` with normalization per §4.1. The bridge MUST NOT enumerate the contact book.
3. **Minimal Privacy Projection:** each hit projects exactly `{ nickname, trust_level, badge }`. Responses MUST NOT include `peer_id`, `disclosed_aliases`, attestation receipts, or timestamps. Unknown keys return only their own echo in `unknown` — revealing nothing about other entries. Callers cannot pivot from one alias to a peer's other identities.
4. **Secret Adjacency Guard:** the handler loads only `contacts.json` — never `vault.json` or root seed material.
5. The same projection frame is shared verbatim by Tauri IPC consumers inside the app.

### 5.3 User-Gated Signing Flows

| Type | Action | Behavior |
|:---|:---|:---|
| `sign` | OIDC/VP challenge | Signs challenge string with derived Ed25519 key; returns signed Verifiable Presentation |
| `sign_event` | Nostr event signing | NIP-01 event signed with secp256k1 BIP-340 Schnorr; returns `id` + `sig` |
| `sign_credential` | W3C VC issuance | Returns a signed Verifiable Credential |
| `POLY_CREDENTIAL_REQUEST` | Credential sharing handshake | Filters matching vault credentials ordered by validity/fidelity; acquires `PopupGuard` (anti-trample concurrency control); presents React approval modal; returns `POLY_CREDENTIAL_PRESENTATION` carrying the VP |

```json
// POLY credential exchange
{"type": "POLY_CREDENTIAL_REQUEST",
 "required_credential_type": "...",
 "challenge": "..."}
// → (user approves in modal)
{"type": "POLY_CREDENTIAL_PRESENTATION", ...}
```

### 5.4 Headless Auto-Signing

```json
{"type": "OMNI_SIGN_REQUEST", "protocol": "POLY_V2", ...}
```

Canonicalization order: `poll_id`, `option_id`, `timestamp` → SHA-256 hash → Ed25519 signature → returns a Nostr **Kind 1112** vote envelope directly, without user popups.

### 5.5 Wire Normalization Register

Legacy `POLLY` naming has been cut over to `POLY` in both directions. Legacy inbound tolerance remains indefinitely for backward compatibility.

| Canonical | Deprecated alias (inbound tolerance only) | Status |
|:---|:---|:---|
| `POLY_CREDENTIAL_REQUEST` | `POLLY_CREDENTIAL_REQUEST` | Accepted inbound; normalized internally |
| `POLY_CREDENTIAL_PRESENTATION` | — | Canonical outbound only |
| `POLY_V2` | `POLLY_V2` | Accepted inbound; response echoes the caller's protocol casing back |

New implementations MUST emit only canonical names.

---

## 6. Nostr Federation Surface

- **Persona selection:** events SHOULD be signed by the Level 1 Public Persona by default. Kind `1` (short text), `1111` (threaded comment), and `30023` (long-form/poll) all originate from Level 1 unless explicitly overridden.
- **Double-broadcast topology** (local relay `ws://127.0.0.1:9003`, project relay, global relays) is defined in `OMNI_SOCIAL_PROTOCOL_V2.md` §4.1.
- **Kind `9112`** (trust attestation, `iyou_safe`) interacts with the Web-of-Trust graph; Project Zero's contact enclave remains the local source of truth for trust tiers and is not published wholesale.
- **XMPP mapping:** JID localparts derive from `nostr_pubkey_hex`; by default the **Level 1** key is used (see `roadmaps/XMPP_MESH_COMMUNICATIONS.md`).

---

## 7. Security Considerations

| Concern | Disposition |
|:---|:---|
| Bundled Let's Encrypt key in app bundle | Tracked as SEC-002 (Critical) — replace with ephemeral self-signed certs |
| DNS hijack / loopback interception of :9001 | Cert pinning evaluation — SEC-006; global DNS resolves `home.iyou.me` → `127.0.0.1` |
| Polling → push migration on the bridge | SEC-005 |
| did_rust serialization drift across consumers | Commit-hash pinning — SEC-003 |
| Popup concurrency | `PopupGuard` serializes approval modals; concurrent credential requests MUST NOT trample each other |
| Harvesting economics | Frame caps + exact-match + echo isolation make bulk contact-graph extraction cost-prohibitive |

See `strategy/SECURITY_HARDENING.md` for the full roadmap.

---

## 8. Conformance & Test Vectors

Implementations claiming Project Zero conformance MUST satisfy:

1. **Determinism:** `derive_deterministic_keypair(seed, n)` returns identical `did` output across platforms for identical inputs (ref: `vault.rs` unit tests).
2. **Anchor immovability:** deletion requests against reserved profiles fail; `public_persona()` never returns index 0 (ref: `test_get_profile_by_id_defaults_to_first`, `test_get_profile_keypair`).
3. **Resolution contract:** exact-match hits project `{nickname, trust_level, badge}` only; oversized batches rejected; unknown keys echoed verbatim after normalization (ref: `contacts.rs` tests, `test_trust_level_badges_and_defaults`).
4. **Trust round-trip:** contacts serialize/deserialize preserving tiers, including legacy alias tolerance (ref: `contacts.rs` persistence tests).
5. **Client hygiene:** satellite Trust Lens implementations MUST keep alias caches in-memory only — never persisted (ref: `iyou_wun/static/js/bridge_client.js`).
6. **DOM contract:** badge slots expose `data-pubkey` attributes and wire `trust_lens.js` on DOMContentLoaded (ref: `iyou_wun/apps/core/tests/test_views.py::Trust Lens DOM contract`).

UI badge configuration reference (`iyou_wun/static/js/trust_lens.js`):

```js
BADGE_CONFIG = {
    Level0:   { label: "Inner Circle",    theme: violet/crimson },
    Level0_5: { label: "Trusted Alliance", theme: emerald      },
    Level1:   { label: "Peer",            theme: slate        }
};
```

---

## Appendix A: Bridge Message Type Registry

| Type | Gate | Direction | Purpose |
|:---|:---|:---|:---|
| `ping` / `pong` | Pre-gate | C→S / S→C | Smoke test |
| `get_profile` → `profile_sync` | Pre-gate | C→S / S→C | Level 1 public metadata |
| `RESOLVE_PEER_ALIASES` → `peer_aliases_resolved` | Pre-gate | C→S / S→C | Batch alias/trust resolution (≤256 keys) |
| `sign` | User-gated | C→S | OIDC/VP challenge signing |
| `sign_event` | User-gated | C→S | Nostr event signing |
| `sign_credential` | User-gated | C→S | W3C VC issuance |
| `POLY_CREDENTIAL_REQUEST` → `POLY_CREDENTIAL_PRESENTATION` | User-gated | C→S / S→C | Credential sharing handshake |
| `OMNI_SIGN_REQUEST` | Headless | C→S | Governance vote envelope (Kind 1112) |
| `INVARIANT_ALERT_PUSH` | Server Push | S→C | Broadcasts Amber/Crimson invariant violations to satellite HUDs |
| `error` | Any | S→C | Uniform error frame |

## Appendix B: TrustLevel Enum Values

| Rust variant | Canonical serde token | Accepted aliases (deserialize) | Badge |
|:---|:---|:---|:---|
| `TrustLevel::Level0` | `"Level0"` | `level0` | Inner Circle |
| `TrustLevel::Level0_5` | `"Level0_5"` | `level0_5`, `level0.5`, `Level0.5` | Trusted Alliance |
| `TrustLevel::Level1` | `"Level1"` | `level1` | Peer |

## Appendix C: Glossary

| Term | Definition |
|:---|:---|
| **Anchor** | Level 0 immutable root identity (index 0), air-gapped from bridge signing |
| **Public Persona** | Level 1 default active signer (index 1) |
| **Burner / Socket (sock)** | Level 2+ contextual persona used to isolate an interaction domain |
| **Pre-gate query** | Bridge request answered inline without approval modal or key access |
| **Secret Adjacency Guard** | Policy that alias queries load only `contacts.json`, never vault/key material |
| **Selective Disclosure Card** | Signed VC binding a subject DID + chosen aliases under a trust tier |
| **PopupGuard** | Concurrency lock serializing approval modals for gated flows |

## References

- `OMNI_SOCIAL_PROTOCOL_V2.md` — meta-protocol, Nostr kind registry, port map
- `ecosystem_shared/LONG_TERM_AUTH_TOPOLOGY.md` — 3-tier architecture blueprint (did_rust / iyou_home / iyou_mobile)
- `AUTH_FLOW_SPECIFICATION.md` — OIDC PKCE flows consuming the bridge
- `strategy/SECURITY_HARDENING.md` — SEC-001 through SEC-008
- `iyou_home/src-tauri/src/{vault,contacts,bridge}.rs` — normative implementation
- `iyou_wun/static/js/{trust_lens,bridge_client}.js` — client-side Trust Lens pattern
