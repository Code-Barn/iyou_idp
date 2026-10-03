# Long-Term Authentication Topology

**Hub:** `omni_social`
**Last updated:** 2026-10-02

---

## 3-Tier Cryptographic Architecture Blueprint

This document defines the long-term sovereign identity network architecture, unifying the core cryptographic library (`did_rust`), the desktop loopback gateway (`iyou_home`), and the native mobile application (`iyou_mobile`) into a cohesive, anti-Sybil identity mesh managed by the central identity provider (`iyou_idp`).

For user account tiers, mobility lifecycle, and ingress invariants across devices (Tier 1 Managed Convenience, Tier 2 Mobile Authenticator, Tier 3 Desktop Enclave), see the canonical companion specification **[`MULTI_TIER_IDENTITY_LIFECYCLE.md`](MULTI_TIER_IDENTITY_LIFECYCLE.md)** (`OMNI-AUTH-TIERS-V2`).

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

| Flow | Initiation | Verification | Session | AMR Claim |
|:---|:---|:---|:---|:---|
| Desktop Enclave (Tier 3) | `iyou_home` WebView / WebSocket (`ws://127.0.0.1:9001`) | `iyou_idp` loopback bridge verification | Sovereign OIDC session | `["did:websocket"]` |
| Mobile QR Handshake (Tier 2) | `iyou_mobile` camera / deep link | `iyou_idp` ephemeral nonce verification | Sovereign OIDC session | `["did:oob_qr"]` |
| Passkey Assertion (Tier 1) | Browser WebAuthn API | `iyou_idp` FIDO2 attestation | Managed OIDC session | `["webauthn:passkey"]` |
| Email OTP (Tier 1) | Browser email challenge | `iyou_idp` HMAC-signed OTP verification | Managed OIDC session | `["otp:email"]` |
| OAuth2 Federation (Tier 1) | Upstream provider redirect | `iyou_idp` token exchange | Managed OIDC session | `["oauth:<provider>"]` |

#### Front-Channel OIDC Delegation Without Key Escrow

A cornerstone of the long-term topology is decoupling front-channel OIDC issuance from central key custody:
- **Zero Key Escrow for Sovereign Ingress:** Tier 2 (`iyou_mobile` QR) and Tier 3 (`iyou_home` WebSocket) logins mint standard OIDC authorization codes for relying party satellites (`iyou_wun`, `iyou_poly`, `iyou_talk`, etc.) through `iyou_idp` without server-side key escrow.
- **Protocol Flow:** The user's hardware enclave (desktop local loopback on port 9001 or mobile Secure Enclave / StrongBox via camera challenge) cryptographically signs an ephemeral challenge nonce issued by `iyou_idp`. Once verified, `iyou_idp` generates a standard authorization code.
- **Satellite Interoperability:** Satellite applications consume standard OIDC PKCE tokens without needing platform-specific DID verification libraries or direct socket connections to client devices. The `sub` claim is permanently pinned to the canonical sovereign DID (`user.custodial_did`), with `account_tier: "sovereign"`.

### AMR (Authentication Method Reference) Claim Standard

The OIDC `amr` claim (RFC 8176) is embedded in both the signed ID Token and the `/oauth2/userinfo/` endpoint response (under scopes `openid` and `profile`). It asserts the exact authentication mechanism and assurance level:

* **Tier 3 (Desktop Sovereign Enclave):** `["did:websocket"]` — Cryptographic challenge signed over local WebSocket loopback (`ws://127.0.0.1:9001`) by `iyou_home`.
* **Tier 2 (Mobile Hardware Authenticator):** `["did:oob_qr"]` — Cryptographic challenge signed out-of-band by `iyou_mobile` using keys sealed in Secure Enclave or StrongBox.
* **Tier 1 (Managed Convenience):**
  - Passkeys: `["webauthn:passkey"]` — FIDO2 hardware credential assertion.
  - Email OTP: `["otp:email"]` — Ephemeral one-time password verified via email.
  - OAuth2 Federation: `["oauth:google"]`, `["oauth:github"]`, `["oauth:apple"]` — Delegated assertion from trusted upstream identity providers.

**Fail-Closed Authorization Gate:** Graduated sovereign accounts (`is_sovereign=True`) are prohibited from authorizing sessions using unverified or legacy password methods. `SovereignAuthorizeView` checks the session `auth_method`; if it evaluates to `"password"` or `"unverified"`, code issuance terminates with HTTP 403 `access_denied`.

### Multi-Email Locker Pattern

To prevent identity pre-claiming across the federated mesh, Omni-Social implements the **Email Locker** architectural pattern:
- **Mesh Anti-Preclaiming Invariant:** In traditional distributed networks, attackers pre-register known target email addresses on unvisited satellite origins to hijack handles or establish conflicting identity anchors. In the Omni-Social federation, email addresses are locked to the authenticated DID (`did:key` or custodial `did:web`).
- **Cryptographic Binding:** An authenticated DID can bind multiple verified email addresses (e.g., primary, personal, work, service routing aliases) into its locker. Each address is validated via challenge-response OTP by `iyou_idp` and anchored in a W3C `EmailOwnershipCredential` issued by `did:web:iyou.me`.
- **Global Resolution & Conflict Rejection:** When any satellite or service encounters an email, it validates against the canonical DID locker index. An email bound to an existing DID cannot be claimed, registered, or usurped by any other identity across any federation origin.
- **Selective Privacy Disclosure:** Multiple emails reside in the user's local enclave locker (`iyou_home`). The user may disclose a `work` address to professional satellites (`iyou_clar`, `iyou_dev`) while projecting an `alias` or purely pseudonymous DID identity to social satellites (`iyou_wun`, `iyou_blog`), without exposing the underlying mailbox cluster.

### Identity Lifecycle & Cross-Tier Ingress Invariants

Account authentication tiers, cross-device mobility, and post-graduation transitions are specified canonically in **[`MULTI_TIER_IDENTITY_LIFECYCLE.md`](MULTI_TIER_IDENTITY_LIFECYCLE.md)** (`OMNI-AUTH-TIERS-V2`):
1. **Tier 3 <-> Tier 2 Parity:** A user holding a self-custodied `did:key` must be able to authenticate seamlessly via Tier 3 (loopback) on desktop or Tier 2 (QR scan) on mobile without database mutations.
2. **Post-Graduation Ingress:** Graduation shreds the Vault-held private seed and converts the account tier to `sovereign`. Post-graduation ingress MUST support:
   - Tier 3 WebSocket verification.
   - Tier 2 Mobile QR verification.
   - Hardware-bound Passkey assertion (WebAuthn), asserting identity without server-side key escrow.
3. **Zero Cleartext Passwords:** No tier may persist cleartext or hashed passwords in PostgreSQL. All user records enforce `set_unusable_password()`.

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

- `docs/ecosystem_shared/MULTI_TIER_IDENTITY_LIFECYCLE.md` — Multi-Tier Identity Lifecycle & Cross-Device Mobility Spec (OMNI-AUTH-TIERS-V2)
- `docs/AUTH_FLOW_SPECIFICATION.md` — Current PKCE flow documentation
- `docs/OMNI_SOCIAL_AUTH_STANDARDIZATION.md` — 4 Federation Rules
- `docs/strategy/SECURITY_HARDENING.md` — Security hardening roadmap
- `did_rust/` — Core cryptographic library
- `iyou_home/` — Desktop loopback gateway
- `iyou_mobile/` — Native mobile authenticator
