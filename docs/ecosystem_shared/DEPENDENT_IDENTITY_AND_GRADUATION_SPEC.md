# Dependent Identity & Sovereign Graduation Specification

**Specification Identifier:** `OMNI-DEP-GRAD-SPEC-V1`
**Hub:** `omni_social`
**Status:** Living Canonical Standard
**Published:** 2026-09-02
**Target Implementers:** `iyou_home`, `iyou_idp`, `iyou_wun`, `iyou_safe`, `iyou_talk`, `iyou_play`

---

## 1. The Trust Paradigm

### 1.1 Why Client-Side Web-of-Trust Replaces Cloud Age Verification

Traditional platforms enforce age gates by demanding government-issued ID scans uploaded to centralized verification providers (e.g., Yoti, Veriff, Persona). This model has three fatal architectural flaws:

1. **PII Concentration:** Every minor's full legal name, date of birth, and facial biometrics are stored in a third-party database — a high-value target with no sovereign control.
2. **Binary Gatekeeping:** A single boolean `is_adult` flag provides no graduated trust. A 13-year-old and a 17-year-old receive identical capability restrictions.
3. **Surveillance Normalization:** Requiring ID upload trains minors to accept identity document surrender as a precondition for digital participation.

### 1.2 The WoT Distance Alternative

Omni-Social replaces cloud age verification with a **client-side Web-of-Trust (WoT) graph distance** model. Instead of asking "prove your age to a stranger," the system asks "how far are you from a verified adult in the trust graph?"

```
Trust Graph Distance Model:

  [Parent DID] ─── distance 0 ─── (Anchor keypair, parent enclave)
       │
       ├── distance 1 ─── [Dependent DID] (child subkey, derived from parent)
       │        │
       │        └── distance 2 ─── [Peer DID] (friend-of-dependent, approved contact)
       │
       └── distance 3+ ─── [Untrusted] (outside trust radius, filtered)

  WoT Distance ≤ 2: Can see dependent's public persona
  WoT Distance > 2: Inbound interactions blocked by default
```

**Key invariant:** The dependent never proves their age to any server. The parent enclave asserts an **age-bracket attestation** (e.g., `U14`, `U18`) as a W3C Verifiable Credential signed by the parent's DID. Satellites verify the signature locally. No cleartext date of birth ever leaves the enclave.

### 1.3 Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## 2. Enclave Key Derivation (`iyou_home`)

### 2.1 Child Subkey Derivation

Parent-stewarded dependents receive cryptographic identity through **deterministic subkey derivation** within the `iyou_home` local enclave. The derivation path follows a BIP-32-inspired hierarchical scheme:

```
Root Seed (32 bytes, hardware-sealed)
  └── m/iyou/dependent/<index>
        └── Ed25519 keypair (32-byte public + 64-byte secret key)
```

**Canonical derivation formula:**

$$\text{child\_keypair} = \text{Ed25519}(\text{SHA-256}(\text{root\_seed} \parallel \text{"iyou/dependent/"} \parallel \text{LE32}(\text{index})))$$

Where:
- `root_seed` is the parent's 32-byte master seed stored in the local secure enclave
- `"iyou/dependent/"` is the domain separator string
- `index` is a monotonically incrementing `u32` (Little-Endian 32-bit encoding) assigned per dependent
- Each dependent receives `index = 0, 1, 2, ...` at creation time

**Derivation path example:**
```
m/iyou/dependent/0    →  First child (e.g., Alice)
m/iyou/dependent/1    →  Second child (e.g., Bob)
m/iyou/dependent/2    →  Third child, etc.
```

### 2.2 Isolation Boundaries

The architecture enforces strict key isolation between parent and dependent:

| Component | Possesses | MUST NOT Possess |
|:---|:---|:---|
| **Child device/enclave** | Only their leaf Ed25519 keypair (`m/iyou/dependent/<index>`) | Parent's root seed, sibling keypairs, parent's L0 Anchor |
| **Parent enclave** | Root seed, all child derivation paths, policy revocation tokens, age-bracket issuance capability | Cannot sign events as the child (absent explicit delegation) |

**Critical invariants:**

1. **Leaf-only exposure:** The child's `iyou_home` instance (or `iyou_mobile` on a shared device) stores only the derived leaf keypair. The root seed is never transmitted to the child enclave.
2. **Revocation authority:** The parent enclave holds a `RevocationTicket` — a signed Nostr event (`kind:9112` trust attestation with `"action":"revoke"`) that can invalidate the child's keypair at any time without accessing the child's private key.
3. **Delegation scope:** The parent MAY issue a `DelegationToken` (NIP-26 delegation event) granting the child limited signing authority for specific event kinds. Delegation tokens have explicit expiration timestamps and kind-level granularity.

### 2.3 Cross-Satellite Key Exposure

When a dependent authenticates to any satellite via OIDC PKCE:

1. The satellite receives `id_token.sub = did:key:z6Mk...{child_did}` — the child's derived DID.
2. The satellite resolves the DID document and verifies the parent DID is the **delegation authority** in the `alsoKnownAs` or `controller` field.
3. The satellite retrieves the age-bracket VC from the `dependent_claim` OIDC claim (see Section 3).
4. The satellite applies trust-ladder policies (Section 4) based on the age bracket — never based on a cleartext date of birth.

---

## 3. Zero-PII Attestation Tokens

### 3.1 The `DependentTokenSlot` Specification

Every satellite application that participates in the dependent trust lifecycle MUST implement the `DependentTokenSlot` — a standardized OIDC claim namespace for conveying age-bracket attestations without PII leakage.

**OIDC claim schema (decoded from `id_token`):**

```json
{
  "sub": "did:key:z6Mk...child_did_hex",
  "iss": "https://iyou.me",
  "dep": {
    "bracket": "U14",
    "wot_distance": 1,
    "parent_did": "did:key:z6Mk...parent_did_hex",
    "attestation_vc": "eyJhbGciOiJFUzI1NiIs...",
    "issued_at": 1725000000,
    "expires_at": 1756536000,
    "revoked": false
  }
}
```

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `dep.bracket` | string enum | Yes | Age bracket: `"U14"` (under 14), `"U14-U18"` (14–17), `"U18"` (under 18, late stage), `"ADULT"` (18+) |
| `dep.wot_distance` | integer | Yes | Graph distance from parent anchor: `0` = parent, `1` = direct dependent, `2` = approved peer |
| `dep.parent_did` | string | Yes | Parent's canonical `did:key` identifier |
| `dep.attestation_vc` | base64url | Yes | W3C Verifiable Credential JWT — signed by parent DID, asserts the age bracket |
| `dep.issued_at` | unix timestamp | Yes | When the attestation was issued |
| `dep.expires_at` | unix timestamp | Yes | Attestation expiry (satellites MUST reject expired attestations) |
| `dep.revoked` | boolean | Yes | If `true`, satellite MUST immediately terminate dependent session |

### 3.2 W3C Verifiable Credential Format

The `attestation_vc` is a JWT-encoded W3C Verifiable Credential using the `VerifiableCredential` type with a custom `AgeBracketClaim`:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://iyou.me/credentials/age-bracket/v1"
  ],
  "type": ["VerifiableCredential", "AgeBracketCredential"],
  "issuer": "did:key:z6Mk...parent_did",
  "issuanceDate": "2026-09-02T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...child_did",
    "ageBracket": "U14",
    "parentAttestation": "I attest that this dependent is within the U14 age bracket as of the issuance date."
  },
  "credentialSchema": {
    "id": "https://iyou.me/schemas/age-bracket-v1.json",
    "type": "JsonSchemaValidator2018"
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2026-09-02T00:00:00Z",
    "verificationMethod": "did:key:z6Mk...parent_did#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndTn21..."
  }
}
```

**Critical constraint:** The credential subject **MUST NOT** contain `birthDate`, `birthPlace`, `nationality`, `documentNumber`, or any other field that constitutes personally identifiable information beyond the age bracket classification.

### 3.3 Cross-Satellite Token Consumption

The `DependentTokenSlot` is consumed identically across all participating satellites:

| Satellite | Role in Dependent Lifecycle | Token Consumption |
|:---|:---|:---|
| `iyou_play` | Athletics — age-gated team formation, competition brackets | Reads `dep.bracket` to assign age-appropriate competition categories |
| `iyou_wun` | Social Hub — feed filtering, DM WoT gate | Reads `dep.wot_distance` + `dep.bracket` to apply inbound message filtering |
| `iyou_talk` | Mental Support — peer matching, crisis routing | Reads `dep.bracket` to match with age-appropriate peer counselors |
| `iyou_safe` | Crisis Triage — friction flags, escalation protocols | Reads `dep.revoked` + `dep.bracket` for safe escalation routing |
| `iyou_idp` | Identity Provider — token issuance, claim validation | Issues `dep.*` claims during OIDC token exchange; validates parent VC signature |

### 3.4 Age Bracket Definitions

| Bracket | Age Range | WoT Constraints | Capability Restrictions |
|:---|:---|:---|:---|
| `U14` | Under 14 | WoT distance ≤ 1 (parent + approved contacts only) | Safe-relay only; no outbound DM to non-approved contacts; no public persona exposure |
| `U14-U18` | 14–17 | WoT distance ≤ 2 (friend-of-friend mesh) | L2 burner personas permitted; peer-circle formation; limited public posting |
| `U18` | 17–18 (graduation pending) | WoT distance ≤ 3 | Near-autonomous; graduation ceremony eligible |
| `ADULT` | 18+ | Full WoT (no distance restriction) | Sovereign; no restrictions; standalone `iyou_home` instance |

---

## 4. The 5-Year Trust Ladder (Ages 13–18)

The Trust Ladder defines three progressive stages of autonomy that a dependent traverses between ages 13 and 18. Stage transitions are triggered by the parent enclave based on verified age, not by calendar automation — the parent retains stewardship authority throughout.

### 4.1 Stage 1: Guided Delegation (Ages 13–14)

**Trust bracket:** `U14`

| Dimension | Policy |
|:---|:---|
| **Key stewardship** | Parent enclave holds all derivation paths. Child possesses only leaf keypair. Parent MAY revoke at any time. |
| **Outbound communication** | Safe-relay restriction: all outbound messages route through `iyou_safe` for content screening before relay delivery |
| **Inbound filtering** | Mutual-contact inbound filtering: only messages from WoT distance ≤ 1 (parent + explicitly approved contacts) are delivered |
| **Public persona** | Child persona is NOT published to any relay mesh. Profile (`kind:0`) events are locally cached only. |
| **Cross-satellite scope** | `iyou_play` (team formation), `iyou_talk` (peer support), `iyou_wun` (restricted feed — approved contacts only) |
| **Parent intervention** | Parent may read inbound message headers (sender DID, timestamp, relay) but NOT message content (encrypted via NIP-04) |

**Stage 1 entry requirements:**
1. Parent creates dependent in `iyou_home` (derives child subkey at `m/iyou/dependent/<index>`)
2. Parent issues `U14` age-bracket VC signed by parent DID
3. Parent registers child DID with `iyou_idp` as a dependent OIDC client
4. Child's `iyou_home` (or `iyou_mobile`) is provisioned with the leaf keypair only

### 4.2 Stage 2: Autonomous Persona (Ages 15–17)

**Trust bracket:** `U14-U18`

| Dimension | Policy |
|:---|:---|
| **Key stewardship** | Child MAY derive L2 burner personas (`m/iyou/dependent/<index>/l2/<context_id>`) independently. Parent retains root revocation authority. |
| **Outbound communication** | Direct relay publishing permitted. No safe-relay routing required. NIP-04 encrypted DMs to WoT distance ≤ 2. |
| **Inbound filtering** | WoT distance ≤ 2 mesh discovery: messages from 2nd-degree connections are delivered. 3rd-degree and beyond are filtered. |
| **Public persona** | L2 burner personas may publish `kind:0` profiles and `kind:1` notes to configured relays. L1 primary persona remains private. |
| **Cross-satellite scope** | Full ecosystem access with age-bracket restrictions. `iyou_wun` peer-circle formation. `iyou_play` competition participation. `iyou_clar` directory listing (opt-in). |
| **Parent intervention** | Parent receives encrypted audit log of new peer connections (DID + timestamp only, not content). Parent may revoke L2 burners individually. |

**Stage 2 entry requirements:**
1. Child's verified age reaches 15 (parent enclave confirms via age-bracket VC reissuance)
2. Parent reissues age-bracket VC as `U14-U18`
3. Child's `iyou_home` is updated with L2 derivation permission flag
4. Child completes "persona sovereignty" onboarding flow in `iyou_home`

### 4.3 Stage 3: Sovereign Graduation (Age 18+)

**Trust bracket:** `ADULT`

**The Sovereign Graduation Ceremony** is the zero-loss key export event where a dependent's cryptographic identity transitions from parent-stewarded to fully sovereign.

#### 4.3.1 Ceremony Sequence

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SOVEREIGN GRADUATION CEREMONY                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. AGE VERIFICATION                                                    │
│     Parent enclave confirms dependent's verified age ≥ 18               │
│     (via age-bracket VC reissuance or external attestation)             │
│                                                                         │
│  2. KEY EXPORT                                                          │
│     Parent enclave exports the child's full keypair history:            │
│       - L1 primary keypair (from m/iyou/dependent/<index>)              │
│       - All L2 burner keypairs (from m/iyou/dependent/<index>/l2/*)    │
│       - Delegation tokens and their revocation status                   │
│     Exported via encrypted WebSocket frame (wss://home.iyou.me:9001)   │
│     to the child's standalone iyou_home instance                        │
│                                                                         │
│  3. ROOT SEED PROVISIONING                                              │
│     Child receives a NEW 32-byte root seed for their standalone        │
│     iyou_home instance. This seed is NOT derived from the parent's.    │
│     The child's existing keypairs are re-mapped as L1 personas         │
│     under the new root via key import (not re-derivation).             │
│                                                                         │
│  4. DID DOCUMENT REPUBLICATION                                          │
│     Child publishes updated DID document with:                          │
│       - controller field changed from parent DID to self                │
│       - alsoKnownAs parent reference removed                            │
│       - New L0 anchor keypair generated under new root seed             │
│                                                                         │
│  5. RELAY MESH MIGRATION                                                │
│     Child's relay list (`kind:10002`) is updated to independent         │
│     relay topology. Parent relay subscriptions are removed.             │
│                                                                         │
│  6. PARENT AUDIT TRAIL                                                  │
│     Parent enclave retains an immutable graduation record:              │
│       - Graduation timestamp                                            │
│       - Child's new DID (post-graduation)                               │
│       - Export manifest (keypairs, delegation tokens, L2 contexts)      │
│     Parent CAN NO LONGER revoke child's keys after ceremony.            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 4.3.2 Zero-Loss Guarantee

The graduation ceremony MUST preserve:

1. **All historical Nostr events** signed by the child's keypairs remain valid (signatures are unchanged).
2. **All WoT relationships** are maintained — peers who followed the child's L1/L2 personas see no disruption.
3. **All Blossom media** referenced by the child's events remains accessible (content-addressed by hash, not by signer identity).
4. **All cross-satellite sessions** continue uninterrupted — the OIDC `sub` claim (child's DID) is unchanged.

The only state change is the `controller` field in the DID document: from parent DID to self.

#### 4.3.3 Post-Graduation Sovereignty

After graduation, the former dependent:

- Possesses a standalone `iyou_home` instance with their own root seed
- May derive new L2 personas independently
- Has no remaining parent-enclave connection
- Is indistinguishable from any other adult participant in the federation
- MAY optionally maintain a voluntary social connection to the parent's DID (WoT link), but this is a peer relationship, not a stewardship hierarchy

---

## 5. Automated Restorative Intervention

### 5.1 The Problem with Silent Algorithmic Shadowbanning

Traditional platforms handle problematic minor behavior through opaque algorithmic suppression: reduced feed visibility, hidden comment filtering, account restriction without explanation. This model:

1. **Fails silently:** The minor never learns why their content is suppressed.
2. **Erodes trust:** The minor perceives the platform as hostile and unexplainable.
3. **Misses root causes:** Algorithmic suppression treats symptoms, not underlying distress.

### 5.2 Friction Flag → Peer Support Routing

Omni-Social replaces shadowbanning with a **friction flag → restorative routing** pipeline that maps `iyou_safe` crisis signals to `iyou_talk` peer support.

#### 5.2.1 Friction Flag Taxonomy

| Flag Code | Source | Severity | Description |
|:---|:---|:---|:---|
| `FRIC-001` | `iyou_safe` automated scanner | Low | Content tone anomaly detected (e.g., sudden shift to aggressive language) |
| `FRIC-002` | `iyou_safe` automated scanner | Medium | Repeated content removal (3+ posts removed in 24h for policy violation) |
| `FRIC-003` | `iyou_safe` peer report | Medium | Peer-reported concern (bullying, self-harm language, isolation signals) |
| `FRIC-004` | `iyou_safe` automated scanner | High | Crisis keyword match (self-harm ideation, violence planning) |
| `FRIC-005` | `iyou_talk` counselor escalation | Critical | Counselor-initiated welfare check request |

#### 5.2.2 Restorative Routing Protocol

```
┌──────────────┐     friction flag      ┌──────────────┐     COGS/POGS     ┌──────────────┐
│  iyou_safe   │───────────────────────▶│  iyou_talk   │──────────────────▶│  Peer Support│
│  (Detection) │   kind:9112 event      │  (Routing)   │   referral event  │  (Human)     │
└──────────────┘                        └──────────────┘                    └──────────────┘
       │                                      │                                   │
       │                                      ▼                                   │
       │                              ┌──────────────┐                            │
       │                              │  COGS/POGS   │                            │
       │                              │  Matching     │                            │
       │                              │  Engine       │                            │
       │                              └──────────────┘                            │
       │                                      │                                   │
       └──────────────────────────────────────┴───────────────────────────────────┘
                              Restorative feedback loop
```

**COGS/POGS** (Counselor-On-Grid Support / Peer-On-Grid Support) is `iyou_talk`'s peer matching system that routes friction-flagged dependents to age-appropriate human counselors rather than algorithmic suppression.

#### 5.2.3 Intervention Routing Rules

| Friction Flag | Routing Target | Response SLA | Escalation Path |
|:---|:---|:---|:---|
| `FRIC-001` | POGS (peer counselor) | Within 4 hours | If unacknowledged → `FRIC-003` auto-upgrade |
| `FRIC-002` | POGS + parent notification (encrypted) | Within 2 hours | If pattern continues → `FRIC-004` auto-upgrade |
| `FRIC-003` | COGS (licensed counselor) | Within 1 hour | Parent notification mandatory |
| `FRIC-004` | COGS + parent notification + `iyou_safe` crisis protocol | Immediate | `iyou_safe` activates emergency contact chain |
| `FRIC-005` | COGS + external emergency services coordination | Immediate | Law enforcement / emergency services if imminent danger |

#### 5.2.4 Restorative Intervention Invariants

1. **No silent suppression:** Every friction flag MUST result in a visible notification to the dependent explaining what was flagged and why.
2. **Age-appropriate routing:** `FRIC-*` events for `U14` dependents are routed exclusively to COGS (licensed counselors). POGS is only available for `U14-U18` and older.
3. **Parent transparency:** For `U14` dependents, parents receive full friction flag reports. For `U14-U18` dependents, parents receive severity-weighted summaries (High/Critical only).
4. **No algorithmic punishment:** Friction flags MUST NOT reduce feed visibility, suppress content reach, or restrict platform access. They initiate human support pathways.
5. **Graduation cleanup:** All friction flags and intervention records are archived (not deleted) at graduation. The former dependent MAY request full purge of their intervention history post-graduation.

---

## Document History

- **2026-09-02 (v1.0.0):** Canonical baseline specification authored. Trust paradigm, enclave key derivation, zero-PII attestation tokens, 5-year trust ladder, and restorative intervention pipeline defined.
