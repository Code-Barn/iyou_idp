# Project Zero Specification

**Tiered Identity Derivation, Peer Trust Tiers & Bridge Wire Contract**

**Hub:** `omni_social`
**Status:** Living document — canonical reference for Project Zero across the iyou_ ecosystem.
**Last updated:** 2026-10-02
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
| Coerced voting / vote-selling via a persistent "voting persona" | Dynamic Ephemeral L2 Burners (§3.4) — no pre-tagged voting identity, per-challenge derivation, nullifier-only double-vote prevention |
| Genealogical fraud resolved by centralized PII custody | Lineage & Kinship Attestation Cards (§4.4) — proof-of-kinship gating over Port 9001, zero stored PII |
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

### 3.4 Dynamic Ephemeral L2 Burners

Level 2 personas (§3.2) have a second, non-optional mode of use: **ephemeral ballot personas**. When a user casts a ballot on a sensitive referendum or a controversial vote, the persona that signs the vote is derived on demand, used exactly once, and retired. This is the coercion-resistance contract of Project Zero: a voter who can be observed once is not protected, so the identity that touches the ledger MUST NOT be an identity the voter has been observed to use before.

#### 3.4.1 Prohibition on Pre-Tagged Voting Personas

A persistent, semantically-reserved voting identity is **forbidden**. Implementations MUST NOT:

1. Reserve, pre-provision, or hand out any profile whose `profile_id`, `profile_name`, or metadata marks it as a voting/governance identity (e.g. `profile_id: "vote"`, `"governance"`, `"ballot"`, a `role: "voter"` field, or a dedicated vault namespace).
2. Expose a "voting identity" or "voting persona" entry in any persona picker, profile manager, `get_profile` projection, or onboarding flow.
3. Reuse a single Level 2 persona across two or more independent challenges, referendums, or polls.
4. Derive burners ahead of time in a pre-provisioned pool or batch. A static set of pre-minted keys is a static identifier set and re-creates the tracking surface this section exists to remove.

Rationale (coercion model): a dedicated voting persona is simultaneously a **coercion surface** (a party who observes it once can prove the holder's position in every later ballot, and can threaten exposure) and a **correlation vector** (participation becomes a durable, cross-referendum behavioural identifier). Plausible deniability requires that no retained artifact ties a ballot to a reusable identity.

#### 3.4.2 Derivation Policy — `derivation_index = max + 1`

Ephemeral burners extend the standard derivation path (§3.1) with a monotonic, non-caller-supplied index:

```
derivation_index = max(existing derivation_index in vault) + 1
```

Normative rules:

| Rule | Requirement |
|:---|:---|
| **On-demand only** | The index MUST be computed inside the enclave at the moment the challenge is presented. Callers MUST NOT supply, hint, or reserve the index. |
| **Monotonic** | Indices MUST increase strictly and MUST NOT be reused, decremented, or recycled after `remove_profile`. A retired burner's index stays burned. |
| **Reserved-range exclusion** | The allocator MUST skip any index inside the structural deletion guard set (§3.3) — index `0` (Level 0 anchor) and index `1` (Level 1 public persona) MUST never be allocated to a burner. |
| **Atomic allocation** | Read-max, allocate, and write MUST occur under a single writer lock; concurrent bridge requests MUST NOT observe or produce colliding indices. |
| **Naming** | Ephemeral profiles MUST be labelled with the challenge digest only (e.g. `ephemeral-<first 8 hex of SHA-256(challenge)>`) so that no plaintext referendum title or topic is retained at rest. |
| **Single use** | One burner MAY be derived per `challenge`. The enclave MUST reject a second derivation attempt for the same `challenge` — re-use is a policy violation, not a recoverable error. |
| **Retirement** | The burner MUST be retired (`remove_profile`, non-reserved profile) no later than challenge close plus the enforcement grace window. Its keypair MUST be discarded, not archived. |

#### 3.4.3 Double-Vote Prevention — Cryptographic Nullifier

Double-vote prevention MUST be enforced **exclusively** by the per-challenge cryptographic nullifier. It MUST NOT be enforced by burner identity, DID uniqueness, or any ledger-side record of a previously seen persona:

```
nullifier = SHA-256(utf8(holder_did) || utf8(challenge))     →  64 lowercase hex chars
```

| Property | Requirement |
|:---|:---|
| **Inputs** | `holder_did` is the holder's stable identifier at the tier the governance engine trusts (Level 0 anchor for Inner-Circle ballots; Level 1 public persona otherwise). `challenge` is the canonical contest digest issued by the governance engine. |
| **Domain separation** | `challenge` MUST be unique per contest and MUST already bind the poll identifier and option-set hash. `challenge` MUST NOT contain, and MUST NOT be derived from, any burner value, `derivation_index`, profile id, or persona name. |
| **Ledger rule** | The ledger counts **distinct nullifiers per challenge**. A duplicate nullifier is a rejected double-vote attempt: the submission MUST be refused and MUST NOT overwrite, replace, or annotate the original tally entry. |
| **No burner linkage** | The ledger MUST NOT persist the burner DID alongside the nullifier in any queryable index, MUST NOT resolve burner DIDs toward the holder, and MUST NOT accept an `alsoKnownAs` / controller relationship on the burner DID document. Burner DID documents MUST NOT be published to a resolver. |

**Unlinkability guarantee.** The nullifier is a pure function of `(holder_did, challenge)` and is mathematically independent of which persona signed the ballot. The public ledger surface therefore consists of:

- a **burner DID** committing to the vote selection (`option_id`) — the only per-ballot artifact, minted for that challenge alone; and
- a **nullifier** proving exactly one ballot per holder per contest.

From these two values an observer can conclude "one ballot was cast on this contest by a holder of this DID" and nothing further. The observer cannot determine the burner's `derivation_index`, its profile name, whether the holder owns other L2 personas, whether this burner participated in earlier referendums, or whether the burner is related to the holder's Level 1 public persona. This is what makes a burner useless as a tracking key and gives the holder **plausible deniability**: denying a specific ballot produces no contradiction with any retained state.

**Linkability caveat (normative, sensitive ballots).** `SHA-256(holder_did || challenge)` is deterministic and unsalted; an adversary holding a candidate set of holder DIDs and the published `challenge` can recompute the nullifier and re-attach the ballot to a named identity. Therefore, for referendums and votes designated **sensitive** by the governance engine:

1. `challenge` MUST be constructed with a per-contest random salt that is **withheld until the tally is sealed**, or the engine MUST accept a commit-reveal disclosure; and
2. the ledger MUST NOT publish `challenge` — or the salt — before close, so nullifiers are unlinkable during the voting window.

Non-sensitive ballots MAY publish `challenge` in the clear and MAY use the unsalted baseline nullifier.

#### 3.4.4 Bridge Flow (Port 9001)

Ephemeral burner derivation is a **user-gated** frame — the gate is not optional, and MUST NOT be downgraded to the headless `OMNI_SIGN_REQUEST` path (§5.4). Headless derivation would remove human consent from the coercion-resistance chain and defeat the purpose of §3.4.

```json
// Request — user-gated
{"type": "DERIVE_EPHEMERAL_BURNER",
 "purpose": "referendum",
 "challenge": "sha256:<contest digest>",
 "single_use": true}

// Response — burner minted, never persisted beyond the challenge window
{"type": "ephemeral_burner_derived", "profile": {
    "profile_id": "ephemeral-a1b2c3d4",
    "derivation_index": 7,
    "did": "did:key:z6Mk...",
    "nostr_pubkey_hex": "<64-hex>",
    "level": 2,
    "expires_at": 1760000000,
    "nullifier": "<64-hex>"
}}
```

Sequence:

1. Satellite (`iyou_wun`, `iyou_poly`) evaluates the poll's sensitivity flag and requests `DERIVE_EPHEMERAL_BURNER` with the engine-issued `challenge`.
2. Enclave acquires `PopupGuard`, presents the consent modal, and displays the contest digest (never the engine's private state).
3. On approval the enclave allocates `max + 1`, derives the Ed25519/secp256k1 pair locally, computes the nullifier, and returns the frame.
4. Satellite constructs the kind `1112` vote envelope and submits it signed by the burner.
5. Enclave retires the burner at challenge close.

| Invariant | Rule |
|:---|:---|
| Consent before derivation | Derivation MUST occur only after explicit user approval; refusal MUST leave no allocated index and no profile |
| Level 0 air-gap | A burner MUST NOT be derivable while the vault is unloadable; the frame fails closed exactly as §5.1 requires |
| Single-use enforcement | A repeat `DERIVE_EPHEMERAL_BURNER` for an already-consumed `challenge` MUST be refused |
| Index monotonicity | Allocated indices MUST never collide with a live profile, even under concurrent requests |
| No persistence of ballots | The enclave MUST NOT write the burner↔ballot association to `vault.json`, `contacts.json`, or any audit log |

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

### 4.4 Lineage & Kinship Attestation Cards (`KinshipAttestation`)

Selective disclosure extends from trust circles (§4.1–§4.3) to **genealogical access**. A genealogy registry such as `iyou_name` must be able to gate access to a living family branch — while refusing to become a custodian of legal identity. `KinshipAttestation` is the credential that closes that gap: it proves *structural membership in a lineage*, carrying **no personally identifiable information at all**.

#### 4.4.1 W3C Verifiable Credential Schema

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://iyou.me/credentials/kinship/v1"
  ],
  "type": ["VerifiableCredential", "KinshipAttestation"],
  "issuer": "did:key:z6Mk...branch_anchor_did",
  "issuanceDate": "2026-10-02T00:00:00Z",
  "expirationDate": "2027-10-02T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...holder_did",
    "parent_did": "did:key:z6Mk...immediate_parent_did",
    "root_ancestor_id": "urn:iyou:tree:8f2c...root",
    "branch_id": "obrien-mayo-1911",
    "generation_depth": 2
  },
  "credentialSchema": {
    "id": "https://iyou.me/schemas/kinship-v1.json",
    "type": "JsonSchemaValidator2018"
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2026-10-02T00:00:00Z",
    "verificationMethod": "did:key:z6Mk...branch_anchor_did#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndTn21..."
  }
}
```

| Claim | Type | Required | Semantics |
|:---|:---|:---|:---|
| `parent_did` | `did:key` string | Yes | Immediate ancestor's DID within the branch. One hop up the attested lineage — never the holder's own legal identity. |
| `root_ancestor_id` | opaque string (`urn:`) | Yes | Stable identifier of the tree root that anchors the whole attested lineage. All cards for one tree share this value; it is the correlation root a verifier chains to. |
| `branch_id` | slug string | Yes | Stable, human-auditable branch designation (e.g. `obrien-mayo-1911`). Selects **which living branch** the holder may reach. |
| `generation_depth` | integer ≥ 0 | Yes | Hops from the branch anchor to the holder. `0` = the anchor itself; `1` = child; `2` = grandchild; `3+` = outside the default family-adjacent scope. |
| `credentialSubject.id` | `did:key` string | Yes | The holder's DID. Distinct from the issuer; possession is proven at presentation time. |

**Issuer model — branch anchors.** The issuer MUST be the `branch_id`'s **Branch Anchor**: the eldest attested living member of that branch, or a Level 0/Level 1 holder already holding a valid `KinshipAttestation` for the same `root_ancestor_id`. Satellites MUST NOT mint lineage credentials — an issuer that can mint can also fabricate, and a satellite that can fabricate needs custody of exactly the PII this design removes.

**Chain of trust.** A verifier MAY accept an intermediate issuer rather than the anchor, provided it resolves the issuer's own `KinshipAttestation` up to the same `root_ancestor_id`. Recursion MUST be bounded by `MAX_CHAIN_DEPTH = 4`; a chain that exceeds the bound MUST be rejected, not truncated. Anchors MUST remain verifiable while offline — every hop is a self-contained, independently signature-checkable credential, so no live call to the anchor is required.

#### 4.4.2 Zero-PII Gating Rule

`iyou_name` gates access to a **living tree branch** by challenging for a proof of kinship over the Port 9001 bridge and evaluating it locally.

**Satellite obligations:**

1. The satellite MUST request a Verifiable Presentation containing a `KinshipAttestation` through the **Port 9001 signature bridge** (`POLY_CREDENTIAL_REQUEST` / `sign_credential`, §5.3) and MUST evaluate the gate predicate itself, locally.
2. The satellite MUST NOT request, accept, parse, log, or store legal names, dates or places of birth, government/national ID numbers, addresses, phone numbers, or any other cleartext PII — neither in the challenge, nor in the credential, nor in any optional profile field. Requesting PII to prove kinship defeats the credential.
3. The satellite MUST persist only the **decision**, never the proof:

   ```json
   {"branch_id": "obrien-mayo-1911", "decision": "grant", "evaluated_at": 1760000000, "policy": "kinship:generation_depth<=2"}
   ```

   No `holder_did`, no `parent_did`, no `root_ancestor_id`, no VC bytes, no signature. The record is indistinguishable between two holders of the same branch.

4. The satellite MUST NOT forward `parent_did`, `root_ancestor_id`, or the raw credential to third parties, analytics, or shared logging.

**Canonical gate predicate** — family-adjacent access to a living branch:

```
generation_depth <= 2        (from the branch anchor)
AND branch_id == requested_branch_id
AND credential is unexpired, unrevoked, and signature-valid
```

`generation_depth <= 2` admits the anchor, children, and grandchildren: the tier a living-branch view needs for direct-line descendant records, while excluding distant cousins and unrelated collaborators. This bound is the policy knob a branch sets for itself; it MUST be enforced as an integer comparison, never as a heuristic.

**Verifier obligations** (enclave-side):

| Invariant | Rule |
|:---|:---|
| Signature validation | `did_rust::verify_vc` MUST succeed for every hop; an unsigned or invalid proof MUST be refused |
| Fail closed | Absent, malformed, expired, revoked, or over-depth credentials MUST result in denial — never in a partial grant |
| Freshness | An expired `expirationDate` MUST be rejected; revocation MUST be honoured immediately on the branch's revocation credential / `kind:9112` revocation notice |
| Anchor binding | The issuer MUST resolve to a holder of the declared `branch_id` under the same `root_ancestor_id`; an issuer claiming an unrelated branch MUST be refused |
| No minting | The enclave MUST NOT issue `KinshipAttestation` credentials on a satellite's behalf (§4.4.1) |

**Threat disposition:** genealogy fraud (impostors claiming descent to harvest inheritance, medical, or custody records) is answered by a cryptographic proof whose *only* payload is graph position. Fraud is prevented by the signature chain; privacy is preserved because the verifiable predicate — depth and branch — carries no name to steal.

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
- **Ballot signing:** kind `1112` vote envelopes originate from Level 1 by default; on sensitive referendums and controversial votes they MUST originate from a single-use ephemeral L2 burner per §3.4, with double-vote prevention carried entirely by the nullifier.
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
| Coerced ballot disclosure | Ephemeral burners + withheld `challenge` salt for sensitive votes (§3.4) — a ballot cannot be re-attributed to a retained persona |
| Nullifier determinism / vote-selling | Sensitive-ballot salt rule (§3.4.3); unsanctioned nullifier reuse is the only accepted double-vote signal |
| Genealogical PII exfiltration from `iyou_name` | Zero-PII gating rule (§4.4.2) — decision-only persistence, no legal name / DoB / government ID ever requested or stored |
| Lineage forgery | Bounded signature chain to `root_ancestor_id`; issuer-may-not-mint rule makes fabricated ancestry unusable |

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
7. **Ephemeral burner allocation:** `derivation_index` for a burner equals `max(live indices) + 1`, never collides with indices `0`/`1`, stays strictly monotonic across retire cycles, and is identical under concurrent requests (ref: `vault.rs` allocator tests).
8. **Single-use enforcement:** a second `DERIVE_EPHEMERAL_BURNER` carrying an already-consumed `challenge` is refused; no profile or index is created on refusal (ref: `bridge.rs` gated-flow tests).
9. **Nullifier determinism:** `nullifier == SHA-256(holder_did || challenge)` yields 64 lowercase hex chars, is independent of `derivation_index` and `profile_id`, and the ledger rejects a duplicate nullifier for the same challenge without mutating the tally entry.
10. **No voting-persona reservation:** no profile id, profile name, or metadata field anywhere in the vault may be reserved for governance/voting semantics; `get_profile` projections MUST NOT offer a voting-identity slot (§3.4.1).
11. **Kinship gate denial default:** `iyou_name` denies a branch on absent, malformed, expired, revoked, or over-`MAX_CHAIN_DEPTH` `KinshipAttestation` presentations, and its persistence layer stores only `{branch_id, decision, evaluated_at, policy}`.
12. **Zero-PII gate:** no `KinshipAttestation` claim, presentation, or challenge carries or requests `birthDate`, `birthPlace`, `nationality`, `documentNumber`, or equivalent PII — parallel to `DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md` §3.2.

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
| `DERIVE_EPHEMERAL_BURNER` → `ephemeral_burner_derived` | User-gated | C→S / S→C | Single-use ballot burner for sensitive votes (§3.4). Never headless. |
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
| **Ephemeral L2 Burner** | Single-use Level 2 persona derived on demand (`max + 1`) for one challenge, then retired; no voting persona is ever pre-tagged (§3.4) |
| **Nullifier** | `SHA-256(holder_did \|\| challenge)` — the sole double-vote prevention mechanism, independent of the persona that cast the ballot |
| **Branch Anchor** | Issuer of `KinshipAttestation` cards for one `branch_id`; eldest attested living member or an already-attested holder under the same `root_ancestor_id` |
| **KinshipAttestation** | Zero-PII VC asserting `parent_did`, `root_ancestor_id`, `branch_id`, `generation_depth` — proof of lineage position with no legal identity (§4.4) |
| **PopupGuard** | Concurrency lock serializing approval modals for gated flows |

## References

- `OMNI_SOCIAL_PROTOCOL_V2.md` — meta-protocol, Nostr kind registry, port map
- `ecosystem_shared/LONG_TERM_AUTH_TOPOLOGY.md` — 3-tier architecture blueprint (did_rust / iyou_home / iyou_mobile)
- `AUTH_FLOW_SPECIFICATION.md` — OIDC PKCE flows consuming the bridge
- `strategy/SECURITY_HARDENING.md` — SEC-001 through SEC-008
- `specs/DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md` — DEP-204 L2 burner derivation under a dependent path; zero-PII attestation pattern that §4.4 mirrors
- `strategy/ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md` — dual-entity architecture and brand charter
- `iyou_home/src-tauri/src/{vault,contacts,bridge}.rs` — normative implementation
- `iyou_wun/static/js/{trust_lens,bridge_client}.js` — client-side Trust Lens pattern
