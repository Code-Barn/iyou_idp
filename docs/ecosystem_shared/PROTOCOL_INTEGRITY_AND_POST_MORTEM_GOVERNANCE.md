# Protocol Integrity & Post-Mortem Governance Specification

**Canonical North Star for Existential Risk Mitigation, Perpetual Purpose Trust Shielding, Cryptographic Self-Defense & Autonomous Post-Mortem Operation**

**Hub:** `omni_social`  
**Status:** Living Canonical Protocol Architecture  
**Date:** 2026-08-24  
**Layer:** Meta-Protocol & Institutional Governance  

---

## 1. Executive Summary & Threat Invariants

The Omni-Social ecosystem is an interconnected sovereign mesh of 19 satellite applications, native desktop/mobile cryptographic enclaves (`iyou_home`, `iyou_mobile`), shared cryptographic engines (`did_rust`), and federated data protocols (Nostr, Blossom, XMPP). 

Traditional decentralized networks frequently collapse not from cryptographic failures, but from **institutional capture, founder disappearance, legal coercion, and silent relay degradation**. This specification codifies the existential survival, legal protection, and mathematical self-defense architecture of the Omni-Social protocol.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   EXISTENTIAL DEFENSE MATRIX                             │
│                                                                          │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │   Legal Shielding    │  │ Cryptographic Defense│  │ Key Decay &    │  │
│  │   (Purpose Trust)    │  │ (Invariant Engine)   │  │ Guardian Mesh  │  │
│  │  - Irrevocable PPT   │  │  - Local Merkle root │  │ - Phase Decay  │  │
│  │  - Trust Enforcer    │  │    verification      │  │ - Dead-Man Lock│  │
│  │  - Poison Pills      │  │  - ±900s Drift Guard │  │ - Shamir SSS   │  │
│  │  - Dual-Entity Wall  │  │  - Wire Alert System │  │ - Zero Custody │  │
│  │                      │  │    (Amber/Crimson)   │  │                │  │
│  └──────────────────────┘  └──────────────────────┘  └────────────────┘  │
│                                      │                                   │
│                                      ▼                                   │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │     Hydra Federation: One-Click Failover & Edge State Privacy      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1.1 The Core Problem: Existential Threat Vector Analysis

The protocol is designed to withstand five existential failure modes:

| Threat Vector | Mechanism of Failure | Classical Failure Mode | Omni-Social Defense Invariant |
|:---|:---|:---|:---|
| **Founder Loss / Death** | Founder death, physical incapacitation, key loss, or sudden unavailability. | Project abandoned, critical certificates expire, admin keys lost forever or held in probate. | **Dead-Man Key Decay & Guardian Mesh (§4)**: Administrative elevation auto-expires; infrastructure access transfers to threshold guardians without sovereign key leakage. |
| **Board / Foundation Capture** | Hostile corporate takeover, venture capital capture, activist investor subversion, or insider board collusion. | Licensing changed to closed-source; monetization tolls injected; user tracking enabled. | **Perpetual Purpose Trust & Poison Pills (§2)**: Assets automatically surrender to neutral entities (EFF/SFC) upon charter breach; zero beneficial equity. |
| **State Coercion & Lawfare** | National security letters, subpoenas, extraterritorial injunctions, registrar takedowns, asset seizures. | Forced backdoor insertion, centralized server seizure, identity database exposed to state actors. | **Decoupled Ownership & Edge Enclaves (§1.3, §5.2)**: Servers store only ephemeral indexes; raw identity and social graphs live encrypted in local client enclaves. |
| **Relay / Index Corruption** | Malicious or compromised relays inject forged history, alter votes, or censor feeds. | Silent history rewriting, vote manipulation, Sybil astroturfing. | **Client-Side Invariant Engine (§3)**: Frontends mathematically verify Merkle roots and signatures before DOM rendering; fail-closed wire alerts. |
| **Supply Chain / Admin Compromise** | Compromise of root deployment keys or continuous integration pipelines. | Backdoored binaries or malicious database migrations. | **Strict Read-Only Data Guards & Multi-Party Witnessing (§3.2, §4.1)**: Database-level mutation rejection and public witness logs. |

### 1.2 Design Axiom: Mathematical Guarantees Over Human Goodwill

> **"Code as Law, Math as Defense."**  
> No institutional policy, board resolution, or founder promise is trusted without cryptographic enforcement.

1. **Zero Trust in Upstream Servers:** All satellite applications (`iyou_wun`, `iyou_poly`, `iyou_life`, etc.) and client enclaves (`iyou_home`, `iyou_mobile`) treat cloud infrastructure as potentially hostile or compromised.
2. **Local-First Verification:** Trust decisions, signature verification, and Merkle tree calculations are executed locally within user-controlled runtime environments.
3. **Fail-Closed Default:** If cryptographic proofs, timestamps, or invariant checks deviate from protocol standards, the client fails closed, severs untrusted streams, and alerts the user.

### 1.3 Decoupled Ownership Architecture: "Postgres is for Indexing, Not Ownership"

A foundational principle of the Omni-Social architecture is the absolute architectural separation between **ephemeral indexing layers** and **sovereign state ownership**:

```
Central / Cloud Infrastructure               User Sovereign Enclave (Local)
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│  PostgreSQL / Redis / K3s            │     │  iyou_home (Tauri/Rust) / Mobile    │
│  - Ephemeral query indexes           │     │  - vault.json (Root master seed)     │
│  - Public feed caching               │     │  - contacts.json (Trust enclave)     │
│  - Accelerated search lookups        │     │  - Local Merkle vote anchors         │
│  - Read-only DID projections         │     │  - Verifiable Credentials & VPs      │
│                                      │     │  - Blossom local blob store (9002)   │
│  ⚠️ SUBJECT TO SEIZURE / CORRUPTION  │     │                                      │
│  ⚠️ CARRIES ZERO PRIVATE KEYS        │     │  🛡️ SOVEREIGN SOURCE OF TRUTH       │
│  ⚠️ LOSS CAUSES ZERO IDENTITY LOSS   │     │  🛡️ MATHEMATICALLY IRREVERSIBLE     │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
```

- **Relational Databases as Disposable Projections:** Central databases (Django ORM over PostgreSQL) store zero private keys, zero raw unencrypted contact books, and zero custodial credentials. If the entire central cluster is seized, wiped, or corrupted, no user loses their identity, keys, or sovereign data.
- **Client-Side Ground Truth:** The authoritative copy of a user's identity, contact network, selective disclosure cards, and cryptographic history resides in local storage (`iyou_home` vault, `contacts.json`, and local Blossom content-addressed repositories).

---

## 2. Legal & Institutional Shielding (The Purpose Trust Model)

Protocol resilience requires complete legal decoupling from individual human mortality and corporate capital structures. Omni-Social utilizes an irrevocable **Perpetual Purpose Trust (PPT)** framework.

```
                          ┌─────────────────────────────┐
                          │  Perpetual Purpose Trust    │
                          │  (Sole Purpose: Protocol    │
                          │   Preservation & Free Good) │
                          └──────────────┬──────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
      │ Core IP & Assets   │  │ Trust Enforcer     │  │ Poison Pill Trigger│
      │ - iyou.me domains  │  │ - Independent legal│  │ - Auto-surrender   │
      │ - Trademarks       │  │   standing         │  │   to EFF / SFC on  │
      │ - Open-source repos│  │ - Litigates rogue  │  │   licensing/rent   │
      │ - Root certs/keys  │  │   trustees/boards  │  │   breach           │
      └────────────────────┘  └────────────────────┘  └────────────────────┘
                 │
                 │ Irrevocable AGPLv3 / GPLv3 License
                 ▼
      ┌────────────────────────────────────────────────────────┐
      │ Commercial Operating Arm Firewall (Dual-Entity Wall)   │
      │ - Hosted SaaS / Enterprise SLA / Support Services       │
      │ - Zero IP ownership; 0% protocol take-rate; No tolls    │
      └────────────────────────────────────────────────────────┘
```

### 2.1 Perpetual Purpose Trust (PPT) / Foundation Structure

1. **Irrevocable Protocol Charter:** All core intellectual property, brand trademarks (`iyou`, `iyou_`, `Omni-Social`), root DNS assets (`iyou.me`, `home.iyou.me`, and satellite apex domains), and canonical repositories are assigned in perpetuity to an irrevocable Purpose Trust (or Guernsey/Swiss Purpose Foundation).
2. **Absence of Beneficial Owners:** Unlike standard trusts or commercial corporations, the Purpose Trust has **no beneficiaries and no shareholders**. Its sole legal mandate is the maintenance, security, copyleft preservation, and public availability of the Omni-Social meta-protocol.
3. **No Exit or Capital Extraction:** The trust structure legally forbids dividend distributions, equity buyouts, or asset liquidations for private enrichment.

### 2.2 The Independent Trust Enforcer Mechanism

To resolve the classical principal-agent dilemma where trustees or foundation directors drift from their mission:

- **Third-Party Enforcer Standing:** The trust charter legally establishes an **Independent Trust Enforcer**—a designated entity (e.g., specialized non-profit open-source legal counsel or a rotating committee of digital rights guardians) possessing exclusive legal standing to audit trust operations and litigate against trustees.
- **Mandatory Litigation Trigger:** If trustees attempt to alter the open-source licensing, implement rent extraction, restrict protocol access, or comply with extrajudicial backdooring demands, the Trust Enforcer is legally bound to petition the courts for immediate removal of the trustees and execution of emergency protective covenants.

### 2.3 Foundation Bylaw Poison Pills (Automatic Asset Surrender)

To neutralize hostile takeovers, state coercion, or internal corruption, the trust charter and repository governance incorporate self-executing legal "poison pills":

```
IF (Trustees attempt AGPLv3/GPLv3 license modification to proprietary/commercial)
   OR (Mandatory protocol transaction tolls / rent extraction introduced)
   OR (Malicious backdoor / telemetry legally mandated by captured jurisdiction)
THEN:
   1. All domain names (iyou.me, etc.) immediately transfer to Custodian (EFF / SFC).
   2. All trademark licenses become public domain / CC0.
   3. Canonical Git commit histories and signing keys publish to decentralized git mirrors.
   4. Trustees immediately forfeit all administrative roles and legal authority.
```

- **Designated Neutral Custodians:** The charter names neutral public-interest entities—specifically the **Software Freedom Conservancy (SFC)** and the **Electronic Frontier Foundation (EFF)**—as default contingent transferees of all domains, repositories, and trademarks.

### 2.4 Dual-Entity Firewall

Any future commercial services (e.g., enterprise hosting, managed K3s clusters, SLA-backed support) must operate under a strict **Dual-Entity Firewall**:

1. **Protocol Steward (Trust/Foundation):** Holds 100% of IP, sets cryptographic standards, enforces copyleft licensing, and controls apex governance.
2. **Commercial Operating Arm (Separate OpCo):** Operates strictly as an ordinary downstream participant in the mesh.
   - The OpCo owns **zero** protocol patents, zero consensus code, and zero proprietary extensions to core wire formats.
   - The OpCo is legally prohibited from charging "protocol gate fees" or establishing walled gardens.

---

## 3. Cryptographic Self-Defense & Invariant "Check Engine Light"

Client applications must never assume server honesty. Every satellite frontend (`iyou_wun`, `iyou_poly`, etc.) and enclave gateway (`iyou_home`) operates a continuous cryptographic audit loop—the protocol's **"Check Engine Light."**

```
Incoming Stream / Server Response (Postgres / WebSocket)
                         │
                         ▼
      ┌────────────────────────────────────────────────────────┐
      │         CLIENT-SIDE INVARIANT VERIFICATION ENGINE      │
      │                                                        │
      │  [1] Signature Validation (Ed25519 / BIP-340 Schnorr)  │
      │  [2] Merkle Root Recomputation (calculate_vote_root)   │
      │  [3] Temporal Drift Envelope (|t_claim - t_now| ≤ 900s)│
      │  [4] Domain Separation Tags (0x00 leaf / 0x01 interior)│
      └──────────────────────────┬─────────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
           [Valid Proof]                  [Proof Failure]
                 │                               │
                 ▼                               ▼
      ┌────────────────────┐          ┌────────────────────────┐
      │ Render to Local DOM│          │ Trigger Port 9001 Wire │
      │ Allow Sign Actions │          │ INVARIANT_ALERT_PUSH   │
      └────────────────────┘          └──────────┬─────────────┘
                                                 │
                               ┌─────────────────┴─────────────────┐
                               ▼                                   ▼
                   ┌───────────────────────┐           ┌───────────────────────┐
                   │    AMBER WARNING      │           │    CRIMSON BANNER     │
                   │ (Soft Drift / Desync) │           │ (Consensus Compromise)│
                   │ - Non-blocking notice │           │ - Blocking HUD banner │
                   │ - Background retry    │           │ - Sever relay pipes   │
                   │ - Diagnostic logging  │           │ - Fail-closed lockout │
                   └───────────────────────┘           └───────────────────────┘
```

### 3.1 Client-Side Invariant Verification Engine

Every data payload ingested by a client application passes through four deterministic mathematical invariant checks before state admission:

1. **Cryptographic Signature Verification:** Ed25519 signatures (for DIDs and VCs) and secp256k1 Schnorr signatures (for Nostr events) must resolve against the claimed public key.
2. **Schema & Normalization Conformance:** Inbound payloads must adhere strictly to normalized field structures (e.g., exact 64-character lowercase hex Nostr pubkeys, valid multibase DIDs).
3. **State Lineage Continuity:** Records claiming to update existing state must include verifiable parent hashes or monotonically increasing sequence counters.
4. **Second-Preimage Resistance:** Merkle proofs must verify under strict domain separation rules (§3.2).

### 3.2 Merkle Tree Governance Anchoring & Domain Separation

Governance polls, vote ledgers, and identity state transitions are anchored via SHA-256 Merkle trees (`calculate_vote_merkle_root`).

To prevent **second-preimage attacks** (where an attacker crafts an interior node that collides with a leaf node or vice versa), the protocol mandates explicit 1-byte domain separation prefixes:

$$\text{Leaf Hash: } H_{\text{leaf}} = \text{SHA-256}(0\text{x}00 \mathbin{\Vert} \text{leaf\_bytes})$$

$$\text{Interior Hash: } H_{\text{interior}} = \text{SHA-256}(0\text{x}01 \mathbin{\Vert} H_{\text{left}} \mathbin{\Vert} H_{\text{right}})$$

```python
import hashlib

def calculate_vote_merkle_root(vote_signatures: list[bytes]) -> bytes:
    """
    Computes a second-preimage resistant Merkle root over vote signatures.
    Leaf nodes are prefixed with 0x00. Interior nodes are prefixed with 0x01.
    Empty input returns 32 zero-bytes (64-character hex zeros "00"*32)
    matching the iyou_home Rust enclave parity to prevent false-positive
    Crimson alerts on uninitialized/empty poll states.
    """
    if not vote_signatures:
        return b"\x00" * 32  # 64-hex '0'*64 canonical empty root parity

    # Domain-separated leaf hashing (0x00 prefix)
    current_level = [
        hashlib.sha256(b"\x00" + sig).digest() for sig in vote_signatures
    ]

    # Iterative pairwise interior hashing (0x01 prefix)
    while len(current_level) > 1:
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])  # Duplicate odd tail
        next_level = []
        for i in range(0, len(current_level), 2):
            combined = b"\x01" + current_level[i] + current_level[i + 1]
            next_level.append(hashlib.sha256(combined).digest())
        current_level = next_level

    return current_level[0]
```

Local clients recompute these roots independently from raw signature logs. Any discrepancy between server-asserted roots and locally calculated roots triggers an immediate **Crimson Invariant Alert**.

### 3.3 Crypto-Temporal Drift Guards ($\pm 900\text{s}$ Drift Envelope)

To prevent backdated record injection, replay attacks, and timestamp manipulation by rogue relays or server hosts, all time-stamped protocol payloads (OIDC challenges, Nostr events, Verifiable Presentations, and governance votes) are subject to a **$\pm 900$-second ($\pm 15$ minutes) drift guard**:

$$| t_{\text{payload}} - t_{\text{local\_enclave}} | \le 900\text{ seconds}$$

```
                -900s                                  +900s
  ────────────────[─────────────── t_local ──────────────]────────────────
   REJECT (Stale)              VALID ENVELOPE             REJECT (Future)
```

- **Rejection Policy:** Payloads with timestamps older than $t - 900\text{s}$ or newer than $t + 900\text{s}$ relative to local monotonic UTC clock are rejected fail-closed.
- **Clock Drift Warning:** Mild drift between $300\text{s}$ and $900\text{s}$ triggers an Amber diagnostic notification prompting the user to verify local NTP synchronization.

### 3.4 WebSocket Bridge Wire Alerts: `INVARIANT_ALERT_PUSH` (Port 9001)

When `iyou_home` or satellite verification layers detect protocol anomalies, an invariant alert is broadcast across `wss://home.iyou.me:9001`.

#### Standard Wire Format

```json
{
  "type": "INVARIANT_ALERT_PUSH",
  "version": "1.0",
  "alert_id": "urn:uuid:7f3b89a1-0d2e-4b71-9c84-123456789abc",
  "severity": "CRIMSON",
  "code": "ERR_MERKLE_ROOT_MISMATCH",
  "timestamp": 1787592000,
  "source": "iyou_poly:governance:poll_104",
  "target_endpoint": "https://poly.iyou.me/api/v2/polls/104/ledger",
  "details": {
    "expected_root": "a4f8e9...3b21",
    "calculated_root": "c7d2e1...8f09",
    "divergent_leaf_index": 42,
    "drift_seconds": null
  },
  "recommended_action": "SEVER_RELAY_AND_FAIL_CLOSED"
}
```

#### Alert Severities and Client Responses

| Severity | Color Code | Condition Triggers | Client HUD Behavior | Cryptographic Action |
|:---|:---|:---|:---|:---|
| **AMBER** | `#F59E0B` | Clock drift $300\text{s} < \|\Delta t\| \le 900\text{s}$; single relay timeout; unanchored non-critical metadata. | Non-blocking yellow warning badge in standard header. | Logs anomaly; attempts fallback relay query; continues operation. |
| **CRIMSON** | `#DC2626` | Merkle root mismatch; invalid Ed25519/Schnorr signature on ingested feed; clock drift $> 900\text{s}$; Level 0 air-gap access attempt. | **Blocking red modal banner** across UI; "Protocol Integrity Compromised." | **Fail-Closed:** Immediately aborts signing bridge requests; severs untrusted relay connection; freezes local cache updates. |

---

## 4. Dead-Man Key Decay & Privilege Destruction

Administrative privileges in early protocol stages (e.g., bootstrapping `ADMIN_DID` accounts, seeding database tables, configuring OIDC endpoints) represent a central point of failure. This protocol defines a deterministic path to **zero-custody permanence**.

```
Phase 0: Bootstrap         Phase 1: Time-Lock Guard       Phase 2: Zero Custody
┌──────────────────────┐   ┌──────────────────────────┐   ┌───────────────────────┐
│ Full Admin DID       │   │ Heartbeat Dead-Man Lock  │   │ Immutable Sovereign   │
│ - Seed clients       │──>│ - Periodic multisig sign │──>│ - ADMIN_DID stripped  │
│ - Initial migration  │   │ - 90-day decay timeout   │   │ - Zero admin override │
│ - Debug overrides    │   │ - Failure = auto-decay   │   │ - Pure mesh consensus │
└──────────────────────┘   └──────────────────────────┘   └───────────────────────┘
```

### 4.1 Master Privilege Decay Schedule

1. **Bootstrap Phase (Active):** `ADMIN_DID` (configured via Django `settings.ADMIN_DID`) grants administrative dashboard access to manage system configurations.
2. **Transition Phase (Time-Locked):** `ADMIN_DID` authority is gated by periodic cryptographic heartbeats (§4.2). Superuser mutation capabilities are locked behind multi-signature requirements.
3. **Autonomous Permanence Phase (Zero Custody):** Administrative escalation endpoints are permanently compiled out or disabled via immutable database constraints. All protocol migrations occur strictly via client-verified governance votes.

### 4.2 Cryptographic Heartbeat & Dead-Man Time-Locks

To ensure that founder death, physical capture, or key loss does not leave permanent backdoors or frozen governance:

- **Heartbeat Proof Event:** The core protocol steward publishes a signed cryptographic heartbeat event (Nostr Kind `20001` or signed Verifiable Presentation) every 30 days.
- **90-Day Decay Window ($T_{\text{decay}} = 7,776,000\text{s}$):**
  $$\text{If } (t_{\text{current}} - t_{\text{last\_heartbeat}}) > T_{\text{decay}} \implies \text{STATUS} = \text{DECAYED}$$
- **Automated Decay Execution:** When decay status is reached:
  1. All satellite backends automatically set `is_staff = False` and `is_superuser = False` across all accounts.
  2. The `ADMIN_DID` privilege evaluation hook in satellite auth backends returns `False` unconditionally.
  3. Dynamic database write endpoints for system configuration become permanently read-only.

### 4.3 Guardian Mesh Social Recovery

For catastrophic infrastructure recovery (e.g., apex domain DNS registrar renewals, SSL/TLS root re-issuance) without compromising user sovereignty:

```
                            ┌────────────────────────┐
                            │ Master Recovery Secret │
                            │ (DNS/Registrar Access) │
                            └───────────┬────────────┘
                                        │
                         Shamir's Secret Sharing (3-of-5)
                                        │
        ┌───────────────┬───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼               ▼
   Guardian 1      Guardian 2      Guardian 3      Guardian 4      Guardian 5
   (Jurisdiction A) (Jurisdiction B) (Jurisdiction C) (Jurisdiction D) (Jurisdiction E)
   Hardware Passkey Hardware Passkey Hardware Passkey Hardware Passkey Hardware Passkey
```

1. **Shamir's Secret Sharing (SSS) Threshold ($k$-of-$n$):** Master infrastructure credentials (registrar access tokens, emergency DNS keys) are split into $n=5$ cryptographic shares with a reconstruction threshold of $k=3$.
2. **Cross-Jurisdictional Guardian Distribution:** Shares are distributed to independent, geographically separated guardians across multiple legal jurisdictions (e.g., Switzerland, Iceland, Canada, Germany, Singapore).
3. **Hardware Key Binding:** Each share is encrypted to a hardware security passkey (FIDO2/WebAuthn or YubiKey OpenPGP).
4. **Strict Scope Limitation:** Guardian shares **only** reconstruct infrastructure maintenance credentials. They have **zero access** to user root seeds, zero ability to sign on behalf of users, and zero access to private contact enclaves.

---

## 5. Forkability, Relay Federation, and Network Hydras

The ultimate defense against censorship or infrastructure destruction is **forkability**—the mathematical and operational ability of the network to spawn independent heads (a "Network Hydra").

```
                      ┌─────────────────────────────────┐
                      │   Official Cloud Relay Cluster  │
                      │   (https://idp.iyou.me, etc.)   │
                      └────────────────┬────────────────┘
                                       │ ⚠️ SEIZED / OFFLINE
                                       ▼
                      ┌─────────────────────────────────┐
                      │   ONE-CLICK RELAY FAILOVER      │
                      │   - Hot-swap endpoint pools     │
                      │   - Zero state/identity loss    │
                      └────────────────┬────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         ▼                             ▼                             ▼
┌───────────────────┐        ┌───────────────────┐        ┌───────────────────┐
│ Community Relay A │        │ Community Relay B │        │ Local Blossom/IPFS│
│ (wss://relay.org) │        │ (wss://sovereign) │        │ (127.0.0.1:9002)  │
└───────────────────┘        └───────────────────┘        └───────────────────┘
```

### 5.1 One-Click Relay Failover & Multi-Relay Gossip

1. **Multi-Relay Gossip Pool:** Satellite clients maintain active connections to a redundant pool of relays (local `iyou_home` relay `ws://127.0.0.1:9003`, primary ecosystem relays, and third-party Nostr/Blossom nodes).
2. **Dynamic Failover Ingress:** If the official endpoint (`iyou.me`) returns HTTP 5xx, TLS errors, or invalid invariant proofs, client applications switch instantly to community-hosted fallback endpoints configured in local preferences.
3. **Content Addressability Durability (Blossom BUD-01 & IPFS):** Because all media, documents, and blobs are addressed strictly by their SHA-256 hash, content can be fetched from any mirror or peer node without data mutation or identity breakage.

### 5.2 Zero-Knowledge Family & Dependent Preservation

A critical ethical imperative of the Omni-Social network is the protection of vulnerable populations, family lineages, and emergency contact networks from centralized data harvesting or state confiscation.

```
                          ┌────────────────────────┐
                          │   iyou_home Enclave    │
                          │   (Local User Device)  │
                          └───────────┬────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
      ┌──────────────────────┐ ┌───────────────┐ ┌──────────────────────┐
      │   iyou_name Tree     │ │  iyou_safe    │ │   iyou_hive Vault    │
      │ - Lineage graphs     │ │ - Crisis triage│ │ - Legal documents    │
      │ - Dependent mappings │ │ - Emergency   │ │ - Power of attorney  │
      │ - Family enclaves    │ │   routes      │ │ - Estate instructions│
      └──────────────────────┘ └───────────────┘ └──────────────────────┘
                 │                    │                    │
                 └────────────────────┼────────────────────┘
                                      │
                                      ▼
                      ┌────────────────────────────────┐
                      │ AES-256-GCM Encrypted at Rest  │
                      │ ZERO EXPOSURE TO CLOUD DB      │
                      └────────────────────────────────┘
```

1. **Edge-Only Sensitive State:**
   - **Genealogy & Lineage Graphs (`iyou_name`):** Full family trees and dependent child relationships are stored exclusively in local client storage (`contacts.json` and local SQLite/JSON enclaves).
   - **Crisis & Emergency Triage (`iyou_safe`):** Safe-word triggers, physical distress routes, and emergency responder lists remain strictly inside the user's encrypted local enclave.
   - **Legal & Estate Vaults (`iyou_hive`):** Wills, advance health directives, and powers of attorney are encrypted with the user's Level 0 Anchor key.
2. **Zero-Knowledge Cloud Projection:** Central database schemas store only cryptographic hashes and zero-knowledge commitments. If a hostile entity subpoenas or seizes cloud servers, they obtain zero legible records of family structures, dependents, or vulnerable users.

---

## 6. Summary Matrix: Invariants & Enforcement

| Invariant Area | Rule / Standard | Enforcement Mechanism | Failure Response |
|:---|:---|:---|:---|
| **Identity Ownership** | Root seeds never leave local enclave (`vault.json`). | Rust memory isolation; Air-Gap guard on Level 0 Anchor. | Fail-closed denial (`bridge_access_denial_reason`). |
| **Legal Insulation** | Irrevocable Purpose Trust; zero beneficial equity. | Trust Enforcer legal standing; EFF/SFC Poison Pill surrender. | Automatic domain and asset transfer to public custodians. |
| **Consensus Integrity** | Merkle tree domain separation (`0x00` leaf / `0x01` interior). | Local recomputation via `calculate_vote_merkle_root`. | Crimson HUD Banner; immediate relay termination. |
| **Temporal Security** | Payloads must fall within $|t_{\text{claim}} - t_{\text{local}}| \le 900\text{s}$. | Client-side temporal drift guard. | Immediate rejection of payload; Amber warning if mild. |
| **Admin Privilege** | `ADMIN_DID` authority decays after 90 days without heartbeat. | Ingress backend dead-man check. | Automatic demotion of all accounts to non-staff. |
| **Data Resilience** | "Postgres is for Indexing, Not Ownership." | Content-addressed storage (Blossom/IPFS); local contact enclave. | One-click hot-swap to independent community relays. |

---

## References

- `docs/PROJECT_ZERO_SPEC.md` — Tiered identity derivation, trust tiers, and bridge wire contract
- `docs/OMNI_SOCIAL_PROTOCOL_V2.md` — Meta-protocol specification, Blossom BUD-01, Nostr kind register
- `docs/ecosystem_shared/LONG_TERM_AUTH_TOPOLOGY.md` — 3-tier architecture blueprint (`did_rust`, `iyou_home`, `iyou_mobile`)
- `docs/strategy/SECURITY_HARDENING.md` — Security roadmap (SEC-001 through SEC-008)
- `docs/strategy/IMMEDIATE_INTEGRITY_EXECUTION_PLAN.md` — Tactical sprint rollout and engineering plan
