# Long-Term Authentication Topology

**Hub:** `omni_social`
**Last updated:** 2026-08-22

---

## 3-Tier Cryptographic Architecture Blueprint

This document defines the long-term sovereign identity network architecture, unifying the core cryptographic library (`did_rust`), the desktop loopback gateway (`iyou_home`), and the native mobile application (`iyou_mobile`) into a cohesive, anti-Sybil identity mesh managed by the central identity provider (`iyou_idp`).

---

### Tier 1: Core Cryptographic Library (`did_rust`)

**Role:** Single source of truth for all DID operations, cryptographic primitives, and serialization formats across the ecosystem.

#### UniFFI Target Configurations

| Target Platform | Output Format | Build Profile | Consumer |
|:---|:---|:---|:---|
| Android (JNI) | `.aar` / `.jar` | `release` + `arm64-v8a`, `armeabi-v7a`, `x86_64` | `iyou_mobile` Android |
| iOS (Swift) | `.xcframework` | `release` + `aarch64-apple-ios`, `x86_64-apple-ios-simulator` | `iyou_mobile` iOS |
| WebAssembly | `.wasm` + `.js` bindings | `release` + `wasm32-unknown-unknown` | `iyou_home` Tauri WebView |
| Native Linux | Shared object `.so` | `release` + `x86_64-unknown-linux-gnu` | `iyou_home` Tauri Core |
| Native macOS | Dynamic library `.dylib` | `release` + `aarch64-apple-darwin` | `iyou_home` Tauri Core |

#### Core Responsibilities

- `did:key` and `did:web` resolution and creation
- Key pair generation (Ed25519, secp256k1)
- Credential signing and verification (JWT-VC, SD-JWT)
- Anti-Sybil proof-of-personhood attestations
- Serialization boundary enforcement (JSON, CBOR, MessagePack)

---

### Tier 2: Desktop Loopback Gateway (`iyou_home`)

**Role:** Local-first sovereign enclave managing cryptographic material, session tokens, and browser-loopback authentication flows.

#### Loopback Architecture

```
┌─────────────────────────────────────────────────────────┐
│  iyou_home (Tauri Desktop Enclave)                      │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │  WebView (Frontend)                               │  │
│  │  - OIDC Authorization Code + PKCE                 │  │
│  │  - did_rust WASM bindings for local signing       │  │
│  └───────────────────────────────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Rust Core (Backend)                              │  │
│  │  - Project Zero vault hierarchy (L0 Anchor,       │  │
│  │    L1 Public Persona, L2+ Burners)                │  │
│  │  - Contact Enclave (contacts.json trust tiers)    │  │
│  │  - Local key vault (OS keychain integration)      │  │
│  │  - WebSocket bridge + resolver (127.0.0.1:9001)   │  │
│  │  - did_rust native library bindings               │  │
│  └───────────────────────────────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Authentication Flows                             │  │
│  │  - Primary: OIDC PKCE → iyou_idp                  │  │
│  │  - Fallback: Local DID challenge-response         │  │
│  │  - Remote: QR code ephemeral handshake            │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

#### Key Responsibilities

- Secure key storage via OS-native keychain (Keychain Services on macOS, Windows Credential Manager, Secret Service on Linux)
- Ephemeral QR code generation for mobile-to-browser verification
- Local session persistence with encrypted at-rest storage
- Certificate pinning for `wss://home.iyou.me:9001` (SEC-006)
- Offline-capable auth fallback when `iyou_idp` is unreachable (SEC-004)

#### Project Zero Identity Derivation Hierarchy

The enclave derives all personas deterministically from a single 32-byte root seed (`SHA-256(root_seed || LE(derivation_index))` for Ed25519; `SHA-256("secp256k1-nostr" || root_seed || LE(derivation_index))` for Nostr secp256k1):

| Level | Index | profile_id | Role |
|:---|:---|:---|:---|
| **Level 0 — Anchor** | 0 | `"anchor"` | Immutable root, air-gapped from bridge signing and public pickers; private P2P trust circles |
| **Level 1 — Public Persona** | 1 | `"primary"` | Default active signer for OIDC challenges, Nostr events, and bridge handshakes |
| **Level 2+ — Burners** | 2..n | custom | Disposable contextual personas, freely created/deleted |

The full tiered derivation model, trust tiers (`Level0` Inner Circle / `Level0_5` Trusted Alliance / `Level1` Peer), selective disclosure cards, and the port 9001 wire contract are specified canonically in **`PROJECT_ZERO_SPEC.md`**.

#### Client Trust Lens Pattern

Satellite apps consume the bridge as thin trust renderers:

1. On feed render, collect unknown Nostr pubkeys / DIDs from DOM nodes.
2. Send a single pre-gate `RESOLVE_PEER_ALIASES` frame (≤256 keys) to `wss://home.iyou.me:9001`.
3. Project the minimal `{nickname, trust_level, badge}` response into local-only badges.
4. Alias caches are in-memory only — never persisted client-side.

Reference implementation: `iyou_wun/static/js/{trust_lens,bridge_client}.js`.

---

### Tier 3: Native Mobile Authenticator (`iyou_mobile`)

**Role:** Ephemeral cryptographic handshake initiator for remote mobile-to-browser DID verification tracking loops.

**Current Stack:** Tauri/React Native (WebView-based).
**Planned Direction:** Native Swift (iOS) / Kotlin (Android) with `did_rust` UniFFI bindings for optimal Secure Enclave performance and minimal attack surface.

#### Mobile Authentication Architecture

```
┌─────────────────────────────────────────────────────────┐
│  iyou_mobile (Planned: Native Swift/Kotlin)             │
│  Current: Tauri/React Native (WebView)                  │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Platform Layer                                   │  │
│  │  - Android: JNI bindings to did_rust .aar         │  │
│  │  - iOS: Swift bindings to did_rust .xcframework   │  │
│  │  - Secure Enclave / Keychain integration          │  │
│  └───────────────────────────────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Authentication Flows                             │  │
│  │  - Primary: OIDC PKCE → iyou_idp                  │  │
│  │  - QR Scanner: Camera-based DID resolution        │  │
│  │  - Deep Link: Universal Links / App Links         │  │
│  └───────────────────────────────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Ephemeral Handshake Protocol                     │  │
│  │  1. Scan QR code from iyou_home browser           │  │
│  │  2. Decode DID challenge nonce                    │  │
│  │  3. Sign nonce with local private key             │  │
│  │  4. Return signed attestation via deep link       │  │
│  │  5. Browser loopback receives attestation         │  │
│  │  6. Session established (ephemeral key discarded) │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

#### Ephemeral Cryptographic Handshake Protocol

```
iyou_home (Browser)                    iyou_mobile
       │                                    │
       │──── QR Code (DID + nonce) ────────▶│
       │                                    │
       │                                    │── Decode DID
       │                                    │── Load key from Secure Enclave
       │                                    │── Sign(nonce, private_key)
       │                                    │
       │◀──── Signed Attestation ──────────│
       │     (via deep link callback)       │
       │                                    │
       │── Verify(attestation, public_key)  │
       │── Establish session                │
       │── Discard ephemeral nonce          │
       │                                    │
```

#### Key Responsibilities

- Barcode/QR scanner for DID resolution
- Secure key storage via Secure Enclave (iOS) / StrongBox (Android)
- Deep link handling (Universal Links on iOS, App Links on Android)
- Biometric-gated signing operations
- Anti-Sybil proof-of-personhood via biometric attestation

---

## Cross-Cutting Concerns

### Security Boundaries

| Boundary | Enforcement | Affected Tiers |
|:---|:---|:---|
| Key material never leaves secure storage | OS-level keychain abstraction | All |
| Ephemeral keys discarded after handshake | Protocol-level lifecycle | Tier 2, Tier 3 |
| Certificate pinning for all remote channels | TLS verification hooks | Tier 2, Tier 3 |
| Anti-Sybil proof-of-personhood | Biometric attestation (Tier 3), DID binding (Tier 1) | All |

### Serialization Protocol

All cross-tier communication uses JSON serialization via `did_rust`:

```json
{
  "type": "did:web",
  "operation": "resolve",
  "did": "did:web:home.iyou.me:alice",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-07-19T00:00:00Z",
    "verificationMethod": "did:web:home.iyou.me:alice#key-1",
    "proofPurpose": "authentication",
    "proofValue": "z..."
  }
}
```

### OIDC Integration Points

| Flow | Initiation | Verification | Session |
|:---|:---|:---|:---|
| Desktop PKCE | `iyou_home` WebView | `iyou_idp` token endpoint | Local encrypted storage |
| Mobile QR Handshake | `iyou_home` browser loopback | `iyou_idp` DID resolution | Ephemeral session token |
| Mobile OIDC PKCE | `iyou_mobile` browser | `iyou_idp` token endpoint | Secure Enclave-bound key |

---

## Implementation Milestones

- [ ] **M1:** `did_rust` UniFFI bindings for Android JNI and iOS Swift
- [ ] **M2:** `iyou_home` loopback server with ephemeral QR code generation
- [ ] **M3:** `iyou_mobile` QR scanner and deep link handler
- [ ] **M4:** End-to-end mobile-to-browser DID verification flow
- [ ] **M5:** Anti-Sybil proof-of-personhood attestation via biometrics
- [ ] **M6:** Offline-capable auth fallback (SEC-004)

---

## References

- `docs/AUTH_FLOW_SPECIFICATION.md` — Current PKCE flow documentation
- `docs/OMNI_SOCIAL_AUTH_STANDARDIZATION.md` — 4 Federation Rules
- `docs/strategy/SECURITY_HARDENING.md` — Security hardening roadmap
- `did_rust/` — Core cryptographic library
- `iyou_home/` — Desktop loopback gateway
- `iyou_mobile/` — Native mobile authenticator
