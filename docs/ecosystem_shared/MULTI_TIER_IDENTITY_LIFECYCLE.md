# Multi-Tier Identity Lifecycle & Cross-Device Mobility Spec

**Identifier:** `OMNI-AUTH-TIERS-V2`  
**Hub:** `omni_social`  
**Status:** Living Canonical Standard  
**Last Updated:** 2026-10-02  
**Target Implementers:** `iyou_idp`, `iyou_home`, `iyou_mobile`, `iyou_wun`, `iyou_poly`, satellites  

---

## 1. The Three Tiers Defined

Omni-Social structures authentication, key custody, and device ingress across three distinct tiers balancing sovereignty, convenience, and hardware security:

* **Tier 3 (Desktop Sovereign Enclave):** Direct loopback signing via `iyou_home` (`ws://127.0.0.1:9001`). Provides complete sovereignty with an air-gapped root seed (`Level 0 Anchor`), deterministic persona derivation (`Level 1 Public Persona`, `Level 2+ Ephemeral Burners`), and local OS keychain integration.
* **Tier 2 (Mobile Hardware Authenticator):** Out-of-band (OOB) QR challenge signing via `iyou_mobile`. Cryptographic keys are hardware-backed and sealed inside the mobile device's Secure Enclave (iOS) or StrongBox / Android Keystore (Android), gated by biometrics.
* **Tier 1 (Managed Convenience):** Cloud-assisted onboarding via WebAuthn Passkeys, verified email OTP challenges, and OAuth2 federation (Google, GitHub, Apple). The user is issued a custodial `did:web` anchored in HashiCorp Vault until sovereign graduation.

### 1.1 Architectural Comparison Matrix

| Property | Tier 3: Desktop Enclave | Tier 2: Mobile Authenticator | Tier 1: Managed Convenience |
|:---|:---|:---|:---|
| **Primary Runtime** | `iyou_home` (Tauri / Rust Core) | `iyou_mobile` (Swift / Kotlin / Tauri) | Web Browser / Relying Party |
| **Key Anchor** | OS Keychain / Memory (L0 Air-Gapped) | Secure Enclave / StrongBox | HashiCorp Vault (KV v2) |
| **Ingress Channel** | Local WebSocket (`ws://127.0.0.1:9001`) | Ephemeral QR Handshake / Deep Link | HTTPS / WebAuthn / OAuth2 |
| **AMR Claim** | `["did:websocket"]` | `["did:oob_qr"]` | `["webauthn:passkey"]`, `["otp:email"]`, `["oauth:<provider>"]` |
| **Sovereignty** | Full sovereign self-custody | Full sovereign hardware custody | Custodial until graduation |
| **Server Key Escrow** | None (Zero Escrow) | None (Zero Escrow) | Temporary custodial key in Vault |
| **Account Tier** | `"sovereign"` | `"sovereign"` | `"managed"` |

---

## 2. Identity Lifecycle & State Machine

```
   ┌────────────────────────────────────────────────────────┐
   │             Tier 1: Managed Convenience               │
   │  Onboarding via Passkey / Email OTP / OAuth2           │
   │  Custodial DID in HashiCorp Vault                      │
   │  Account Tier: "managed"                               │
   └───────────────────────────┬────────────────────────────┘
                               │
                               │ Graduation Ceremony
                               │ (Sealed ECDH export + Vault key shred)
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │                  Sovereign State                       │
   │  Air-Gapped Root Seed / Hardware-Bound Private Keys    │
   │  Zero Server-Side Key Escrow                           │
   │  Account Tier: "sovereign"                             │
   └─────────────┬────────────────────────────┬─────────────┘
                 │                            │
                 ▼ Seamless Parity            ▼ Seamless Parity
   ┌───────────────────────────┐┌───────────────────────────┐
   │  Tier 3: Desktop Enclave  ││ Tier 2: Mobile Authenticator│
   │  Loopback ws://127.0.0.1  ││ Camera QR Nonce Signing   │
   │  AMR: ["did:websocket"]   ││ AMR: ["did:oob_qr"]       │
   └───────────────────────────┘└───────────────────────────┘
```

### 2.1 Onboarding (Tier 1 Managed Convenience)
1. **Low-Friction Bootstrap:** Users without desktop enclaves or hardware signers register using WebAuthn Passkeys, email OTP verification, or OAuth2 federation.
2. **Custodial Provisioning:** `iyou_idp` creates a custodial `did:web` (e.g. `did:web:iyou.me:user:<uuid>`). The Ed25519 private key is sealed into HashiCorp Vault at `secret/identity/{custodial_did}/ed25519`.
3. **Passwordless Integrity:** User records in PostgreSQL are initialized via `set_unusable_password()`.
4. **Session Tagging:** Ingress sessions record the specific credential method in the session cache (`request.session["auth_method"] = "webauthn:passkey" | "otp:email" | "oauth:<provider>"`).

### 2.2 Graduation Ceremony (Transition to Sovereign)
Graduation transitions an identity from Tier 1 custodial stewardship to sovereign self-custody:
1. **Enclave Handshake (`POST /api/v1/identity/graduate/export/`):**
   - The user opens `iyou_home` or `iyou_mobile` and initiates graduation.
   - The enclave generates an ephemeral X25519 keypair and sends the public key to `iyou_idp`.
   - `iyou_idp` encrypts the Vault-held seed using ECDH + HKDF-SHA256 (`info="iyou-idp/graduation-export/v1"`) + AES-256-GCM, binding the custodial DID as AEAD associated data.
2. **Local Import & Verification:**
   - The enclave decrypts the seed into local hardware-sealed storage.
   - The client constructs a canonical confirmation receipt: `{"action": "graduate", "did": "<custodial_did>", "issued_at": <unix>}`.
   - The client signs the receipt with the decrypted private key and posts it to `/api/v1/identity/graduate/confirm/`.
3. **Atomic Vault Shred & Promotion:**
   - `iyou_idp` verifies the signature against the public key held in Vault.
   - Within an atomic database transaction:
     * `user.is_sovereign = True`
     * `user.account_tier = "sovereign"`
     * `delete_identity_key(did)` permanently shreds all versions and metadata in HashiCorp Vault.
   - Any Vault failure rolls back promotion entirely (`502 vault_shred_failed`).

### 2.3 Sovereign Ingress (Tier 2 & Tier 3 Front-Channel Delegation)
Following graduation, the user authenticates across the entire federation without central key escrow:
1. **Front-Channel OIDC Delegation:** Rather than forcing satellites to implement bespoke WebSocket or QR verification routines, `iyou_idp` acts as a front-channel OIDC delegator.
2. **Loopback Verification (Tier 3):** Desktop satellites connect to `iyou_home` over `ws://127.0.0.1:9001`. `iyou_home` presents the challenge signature to `iyou_idp`. Session AMR is tagged as `["did:websocket"]`.
3. **Mobile QR Verification (Tier 2):** When logging in from another terminal or browser, `iyou_idp` presents an ephemeral QR challenge containing a cryptographically random nonce. `iyou_mobile` scans the QR, signs the nonce with its Secure Enclave key, and returns the attestation via deep link. Session AMR is tagged as `["did:oob_qr"]`.
4. **Token Issuance:** `iyou_idp` mints standard OIDC PKCE authorization codes for the requesting satellite with:
   - `sub`: pinned to the canonical sovereign DID (`user.custodial_did`)
   - `account_tier`: `"sovereign"`
   - `amr`: `["did:websocket"]` or `["did:oob_qr"]`
   - `email_verified`: asserted proof-of-control state
5. **Fail-Closed Gate:** `SovereignAuthorizeView.get()` guarantees that graduated accounts cannot authorize sessions using legacy password or unverified sessions (`auth_method in ("password", "unverified")`), returning HTTP 403 `access_denied`.

---

## 3. Cross-Tier Ingress Invariants

1. **Tier 3 <-> Tier 2 Parity:** A user holding a self-custodied `did:key` must be able to authenticate seamlessly via Tier 3 (loopback) on desktop or Tier 2 (QR scan) on mobile without database mutations. The user's canonical identity remains identical across both form factors.
2. **Post-Graduation Ingress:** Graduation shreds the Vault-held private seed. It converts the account tier to `sovereign`. Post-graduation ingress MUST support:
   - Tier 3 WebSocket verification.
   - Tier 2 Mobile QR verification.
   - Hardware-bound Passkey assertion (WebAuthn), asserting identity without server-side key escrow.
3. **Zero Cleartext Passwords:** No tier may persist cleartext or hashed passwords in PostgreSQL. All user records enforce `set_unusable_password()`.
4. **AMR Claim Specification (RFC 8176 Compliance):**
   - Tier 3: `["did:websocket"]`
   - Tier 2: `["did:oob_qr"]`
   - Tier 1: `["webauthn:passkey"]`, `["otp:email"]`, `["oauth:google"]`, `["oauth:github"]`, `["oauth:apple"]`
   - Prohibited / Gated Out: `["password"]`, `["unverified"]`

---

## 4. Multi-Email Locker Architecture

### 4.1 The Mesh Anti-Preclaiming Problem
In a federated mesh of autonomous satellites (`iyou_wun`, `iyou_poly`, `iyou_talk`, `iyou_clar`, etc.), relying on unstructured email addresses creates a critical vulnerability:
- **Sybil Pre-Claiming:** An adversary registers an authentic user's known email address on an unvisited satellite before the user navigates there, blocking handle claims or intercepting notifications.
- **Siloed Aliasing:** Users frequently require distinct email routing identities (work vs. personal vs. disposable aliases) across different satellites without creating fragmented, disconnected DID personas.

The **Multi-Email Locker** pattern solves this by anchoring all verified email addresses directly to the user's sovereign DID via cryptographic credentials.

### 4.2 W3C Verifiable Credential Schema (`EmailOwnershipCredential`)

Every email bound to a user's locker is attested via an `EmailOwnershipCredential` issued by `did:web:iyou.me`:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iyou.me/v1"
  ],
  "id": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "type": ["VerifiableCredential", "EmailOwnershipCredential"],
  "issuer": "did:web:iyou.me",
  "issuanceDate": "2026-10-02T15:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8xde55v48nvCTLuC6Kqv",
    "email": "alice.work@byersbrands.com",
    "verified_at": "2026-10-02T14:58:32Z",
    "email_type": "work"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-10-02T15:00:00Z",
    "verificationMethod": "did:web:iyou.me#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3k9...signature"
  }
}
```

#### Credential Fields
* **`issuer`**: MUST be `did:web:iyou.me` (the central identity authority).
* **`credentialSubject.id`**: The holder's canonical sovereign `did:key` (or custodial `did:web` prior to graduation).
* **`credentialSubject.email`**: Normalized lowercase RFC 5322 email string.
* **`credentialSubject.verified_at`**: UTC ISO 8601 timestamp representing the moment OTP verification succeeded.
* **`credentialSubject.email_type`**: Enumerated binding type:
  - `"primary"`: Default system contact and account notification recipient.
  - `"personal"`: Secondary personal correspondence address.
  - `"work"`: Enterprise / institutional address for professional satellites.
  - `"alias"`: Masked or contextual routing alias.

### 4.3 Cross-Repository Roles & Responsibilities

```
 ┌──────────────────────┐         ┌──────────────────────┐         ┌──────────────────────┐
 │       iyou_idp       │         │      iyou_home       │         │       iyou_wun       │
 │                      │         │                      │         │                      │
 │ - OTP Challenge      │ Credential│ - Secure Storage   │ Bridge  │ - Link Deck Display  │
 │ - Email Ownership    ├─────────▶ - Selective          ├────────▶ - Mesh Badge Proof    │
 │   Credential Minting │         │   Disclosure Wallet  │ Frame   │ - Anti-Preclaim Gate │
 │ - Global Index Lock  │         │ - Contacts Enclave   │ (Port   │ - Public Profile     │
 └──────────────────────┘         └──────────────────────┘  9001)  └──────────────────────┘
```

1. **`iyou_idp` (Claims & OTP Verification Authority):**
   - Transmits cryptographic OTP challenges to claimed email addresses.
   - Upon verification, signs and issues the W3C `EmailOwnershipCredential`.
   - Maintains the authoritative global email-to-DID locker registry. An attempt to bind an already-claimed email to a different DID fails closed with conflict errors.
   - Emits verified email claims and `email_verified=True` in standard OIDC userinfo responses.

2. **`iyou_home` (Local Enclave Storage & Selective Disclosure):**
   - Stores all issued `EmailOwnershipCredential` instances inside the local, encrypted credential vault (`contacts.json` / wallet).
   - Manages selective disclosure: the user configures which email type (e.g. `work` vs `alias`) is revealed to specific satellite origins or contact trust tiers (`Level0` Inner Circle vs `Level1` Peer).
   - Serves the credentials locally over the Port 9001 bridge (`ws://127.0.0.1:9001`) to authorized local apps without querying external servers.

3. **`iyou_wun` (Link Deck Publication & Mesh Projection):**
   - Consumes email ownership proofs via the Port 9001 bridge.
   - Renders verified email badges on the user's public Link Deck (`UserLinkDeck`).
   - Rejects handle registration or email pre-claiming for any email address not cryptographically proven via an `EmailOwnershipCredential` bound to the active session DID.
   - Projects verified trust badges across the social feed without exposing raw email addresses unless explicitly opted in by the user.

---

## 5. References

- [`LONG_TERM_AUTH_TOPOLOGY.md`](LONG_TERM_AUTH_TOPOLOGY.md) — 3-Tier Cryptographic Architecture Blueprint
- [`AUTH_FLOW_SPECIFICATION.md`](../AUTH_FLOW_SPECIFICATION.md) — Canonical PKCE Ingress & Identity Graduation Protocol
- [`PROJECT_ZERO_SPEC.md`](../PROJECT_ZERO_SPEC.md) — Project Zero Persona Derivation & Port 9001 Wire Contract
- [`DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md`](../specs/DEPENDENT_IDENTITY_AND_GRADUATION_SPEC.md) — Dependent Identity & Sovereign Graduation Specification
- [`RFC-006-universal-profile-metadata.md`](RFC-006-universal-profile-metadata.md) — Universal Profile Metadata & Cross-Satellite Sync
