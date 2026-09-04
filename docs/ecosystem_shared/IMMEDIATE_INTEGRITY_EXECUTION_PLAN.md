# Immediate Integrity Execution Plan

**Near-Term Engineering Deliverables, Mid-Term Entity Shielding, and Post-Release Autonomous Key Decay Roadmaps**

**Hub:** `omni_social`  
**Status:** Active Sprint Execution Blueprint  
**Date:** 2026-08-24  
**Companion Spec:** `docs/strategy/PROTOCOL_INTEGRITY_AND_POST_MORTEM_GOVERNANCE.md`  

---

## 1. Overview & Phased Execution Strategy

This execution plan operationalizes the long-term protocol integrity and post-mortem governance principles into actionable, prioritized engineering phases. The implementation schedule balances zero-cost near-term code hardening against mid-term legal structurings and release-flight cryptographic automation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INTEGRITY EXECUTION ROADMAP                              │
│                                                                             │
│  PHASE 1: Near-Term Engineering (Current Sprints)                          │
│  ├─ 1.1 Invariant Alert Hook Specs (`INVARIANT_ALERT_PUSH` wire schema)     │
│  ├─ 1.2 Read-Only Database Guards across 19 satellite admin panels          │
│  └─ 1.3 Fail-Closed Signature Bridge verification in `iyou_home`            │
│                                                                             │
│  PHASE 2: Mid-Term Entity Preparation & Legal Shielding (Pre-Release)       │
│  ├─ 2.1 Complete Ecosystem Asset Inventory & Domain Ring-Fencing           │
│  └─ 2.2 Perpetual Purpose Trust Charter Drafting (EFF/SFC Poison Pills)     │
│                                                                             │
│  PHASE 3: Release & Post-Release Flight Automation                          │
│  ├─ 3.1 Dead-Man Key Decay & Administrative Sunset Time-Locks               │
│  └─ 3.2 Independent Community Witnesses & Distributed Merkle Anchoring      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: Present Sprint Deliverables (Near-Term / Zero-Cost Engineering)

Phase 1 focuses exclusively on zero-overhead software engineering enhancements that eliminate attack surfaces and establish client-side cryptographic invariant visibility without requiring legal fees or infrastructure expansion.

### 2.1 Invariant Alert Hook Specifications (`INVARIANT_ALERT_PUSH`)

Standardize the `INVARIANT_ALERT_PUSH` event frame within the Port 9001 bridge contract (`wss://home.iyou.me:9001`) and propagate the specification across all satellite frontends.

#### Wire Payload Schema (`docs/ecosystem_shared/PROJECT_ZERO_SPEC.md` §5 & Appendix A)

```json
{
  "type": "INVARIANT_ALERT_PUSH",
  "version": "1.0",
  "alert_id": "urn:uuid:8b3c0e12-45a7-4cf2-9e81-fa89b2134567",
  "severity": "AMBER" | "CRIMSON",
  "code": "ERR_SIGNATURE_INVALID" | "ERR_MERKLE_ROOT_MISMATCH" | "ERR_TEMPORAL_DRIFT_EXCEEDED" | "ERR_AIRGAP_BREACH_ATTEMPT" | "ERR_RELAY_DESYNC",
  "timestamp": 1787592000,
  "source": "iyou_home:bridge_verifier",
  "target_endpoint": "https://wun.iyou.me/api/v1/feed",
  "details": {
    "claimed_signer": "did:key:z6Mku...",
    "reason": "Signature verification failed for Nostr Kind 1111 comment",
    "drift_seconds": 1240,
    "expected_root": null,
    "calculated_root": null
  },
  "recommended_action": "DISCARD_RECORD" | "SEVER_RELAY_AND_FAIL_CLOSED" | "NOTIFY_USER_NTP_SYNC"
}
```

#### Client HUD Consumer Hook (`static/js/bridge_client.js`)

Each satellite frontend subscribing to `wss://home.iyou.me:9001` registers a top-level frame handler:

```javascript
// Universal Invariant Listener Hook
bridgeSocket.addEventListener("message", (event) => {
  const data = JSON.parse(event.data);
  if (data.type === "INVARIANT_ALERT_PUSH") {
    handleInvariantAlert(data);
  }
});

function handleInvariantAlert(alert) {
  console.warn(`[INVARIANT ALERT ${alert.severity}] ${alert.code}:`, alert.details);
  
  if (alert.severity === "CRIMSON") {
    // 1. Render high-priority blocking modal HUD
    renderCrimsonBanner(alert);
    // 2. Halt auto-signing requests
    window.__SOVEREIGN_SIGNING_LOCKED = true;
    // 3. Sever active relay socket connections
    disconnectUntrustedRelays(alert.target_endpoint);
  } else if (alert.severity === "AMBER") {
    // Render non-blocking warning badge in standard header
    renderAmberIndicator(alert);
  }
}
```

### 2.2 Read-Only Database Guards

Audit all satellite admin interfaces (`admin.py` across all 19 Django apps) to guarantee that raw cryptographic identity fields, user DIDs, signatures, and verification nonces are strictly read-only.

#### Audit Target Register

| Satellite App | Model Admin Target | Target Fields | Protection Required |
|:---|:---|:---|:---|
| `iyou_idp` | `Client`, `ChallengeNonce`, `DIDProfile` | `client_id`, `sub`, `nonce`, `signature`, `created_at` | `readonly_fields`, `editable=False`, write-rejection |
| `iyou_wun` | `SocialPost`, `PeerConnection` | `author_did`, `post_sig`, `nostr_event_id` | `readonly_fields`, block admin edit |
| `iyou_poly` | `PollVote`, `VoteLedger` | `voter_did`, `vote_signature`, `merkle_leaf_hash` | `readonly_fields`, immutable database constraints |
| `iyou_hive` | `VaultDocument`, `LegalAttestation` | `creator_did`, `doc_sha256`, `signature` | Immutable after creation |
| `iyou_safe` | `CrisisLog`, `EmergencyRoute` | `reporter_did`, `location_commitment_hash` | `readonly_fields`, zero cleartext location |
| `All Satellites` | `auth.User` / Custom User | `username` (DID string) | `readonly_fields = ("username", "date_joined")` |

#### Canonical Hardening Pattern (`admin.py`)

```python
from django.contrib import admin
from django.core.exceptions import ValidationError

class SovereignModelAdmin(admin.ModelAdmin):
    """
    Prevents admin panel mutation of cryptographic signatures, DIDs,
    and second-preimage immutable ledger records.
    """
    readonly_fields = ("did", "signature", "merkle_root", "created_at")
    actions = None  # Disable bulk actions to prevent save_model bypass

    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of immutable ledger anchors via Django admin
        if obj and getattr(obj, "is_immutable_anchor", False):
            return False
        return super().has_delete_permission(request, obj)

    def save_model(self, request, obj, form, change):
        if change:
            # Enforce that cryptographic fields cannot be altered post-creation
            original = self.model.objects.get(pk=obj.pk)
            for field in self.readonly_fields:
                if getattr(original, field, None) != getattr(obj, field, None):
                    raise ValidationError(f"Cryptographic field '{field}' is immutable.")
        super().save_model(request, obj, form, change)
```

### 2.3 Fail-Closed Bridge Verification (`iyou_home`)

Audit and verify that `iyou_home` signature bridge (`src-tauri/src/bridge.rs` and `src-tauri/src/vault.rs`) enforces strict fail-closed gating:

1. **Air-Gap Invariant Test:** Ensure that any incoming WebSocket frame requesting `sign` or `sign_event` with `profile_id: "anchor"` or `derivation_index: 0` is rejected with `bridge_access_denial_reason: "Level 0 Anchor is air-gapped from bridge signing"`.
2. **Nonce Challenge Validation:** Enforce strict $\pm 900\text{s}$ check on challenge generation timestamps before displaying signing modals.
3. **Diagnostic Anomaly Logging:** Bridge logs malformed requests and emits `INVARIANT_ALERT_PUSH` (Amber) when satellite apps send unregistered frame types or bad payload encodings.

---

## 3. Phase 2: Entity Preparation & Asset Ring-Fencing (Mid-Term Legal & Operational)

Phase 2 secures the protocol against corporate, jurisdictional, and legal capture by cataloging assets and drafting the irrevocable Perpetual Purpose Trust framework.

### 3.1 Comprehensive Ecosystem Asset Inventory

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       ECOSYSTEM ASSET RING-FENCE                            │
│                                                                             │
│  Apex Domains & DNS                 Repositories & Codebases                │
│  - iyou.me                          - github.com/iyou-mesh/omni_social      │
│  - home.iyou.me                     - github.com/iyou-mesh/did_rust         │
│  - idp.iyou.me                      - github.com/iyou-mesh/iyou_idp         │
│  - 19 satellite subdomains          - Decentralized Radicle mirrors         │
│                                                                             │
│  Trademarks & Brand                 Infrastructure & Trust Roots            │
│  - "iyou", "iyou_", "Omni-Social"   - DNSSEC KSK / ZSK Signing Keys         │
│  - Visual logo marks and styles     - Root TLS Authority Trust Pinning      │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Detailed Asset Register

1. **DNS & Apex Domains:**
   - Primary apex: `iyou.me`
   - Infrastructure roots: `home.iyou.me`, `idp.iyou.me`, `k3s.iyou.me`
   - Satellite endpoints (19 apps): `wun.iyou.me`, `poly.iyou.me`, `name.iyou.me`, `hive.iyou.me`, `ride.iyou.me`, `dctech.iyou.me`, `safe.iyou.me`, `talk.iyou.me`, `clar.iyou.me`, `play.iyou.me`, `blog.iyou.me`, `help.iyou.me`, `draw.iyou.me`, `life.iyou.me`, `walk.iyou.me`, `stay.iyou.me`, `dev.iyou.me`, `spot.iyou.me`, `shop.iyou.me`.
2. **Canonical Code Repositories:**
   - Coordination Hub: `omni_social`
   - Cryptographic Core: `did_rust`
   - Enclaves: `iyou_home`, `iyou_mobile`
   - Satellites: All 19 Django satellite codebases
   - Infrastructure: `k3s_vm`
3. **Decentralized Git Mirrors:**
   - Radicle project IDs for sovereign peer-to-peer git replication
   - IPFS Git snapshot archives pinned across community pinning clusters.

### 3.2 Perpetual Purpose Trust Charter Drafting

Draft the model bylaws and trust instrument incorporating the mandatory non-negotiable clauses:

1. **Copyleft Protection Mandate:** Mandates AGPLv3/GPLv3 copyleft licensing across all core protocol software in perpetuity.
2. **0% Take-Rate & Rent Extraction Prohibition:** The trust instrument legally prohibits the foundation, trustees, or operating arms from charging transaction tolls, access rents, or monetized paywalls for protocol-level verification or federation.
3. **Independent Trust Enforcer Appointment:** Designates third-party legal standing to enforce trustee compliance and initiate litigation if trustees breach the open-source mandate.
4. **EFF / SFC Asset Surrender Poison Pill:** Legally self-executing transfer of domains, trademarks, and repositories to the Software Freedom Conservancy or Electronic Frontier Foundation upon any attempt to close the codebase or privatize network assets.

---

## 4. Phase 3: Automated Key Decay & Guardian Mesh (Release / Post-Release Flight)

Phase 3 executes the cryptographic automation that transitions early administrative bootstrapping into permanent zero-custody operation.

```
                                  Timeline
  Release v1.0                     v1.0 + 90 Days                   v1.0 + 180 Days
  ───────┬────────────────────────────────┬────────────────────────────────┬──────>
         │                                │                                │
         ▼                                ▼                                ▼
  [Bootstrap Live]               [Heartbeat Guard]                [Zero-Custody Mesh]
  - ADMIN_DID active             - 30-day heartbeat required      - ADMIN_DID stripped
  - Seeding clients              - Missed beat triggers decay     - Code is law
  - Initial telemetry            - Superuser mutation locked      - Autonomous mesh
```

### 4.1 Automated Administrative Key Decay & Time-Lock Escrow

1. **Heartbeat Verification Worker:** Satellite backends schedule a daily background job verifying the presence of a valid Nostr Kind `20001` or signed VP heartbeat emitted within the past 90 days.
2. **Automatic Privilege Sunset:** If the heartbeat expires:
   ```python
   # Ingress Auth Backend Privilege Check
   def is_admin_did_active(user_did: str) -> bool:
       heartbeat = get_latest_cryptographic_heartbeat()
       if not heartbeat or (now() - heartbeat.timestamp).total_seconds() > 7776000:
           # 90-day decay threshold exceeded: Administrative override permanently disabled
           logger.critical("ADMIN_DID privilege DECAYED. System in zero-custody mode.")
           return False
       return user_did == getattr(settings, "ADMIN_DID", None)
   ```
3. **Immutable Code Migration:** Following 180 days of public release stability, release a final firmware/container update that completely excises `ADMIN_DID` checks and sets `is_staff = False` unconditionally.

### 4.2 Independent Community Witnesses & Decentralized Anchoring

1. **External Witness Federation:** Onboard 5+ independent community relay runners (universities, privacy foundations, community node operators) to witness and re-sign Merkle governance roots.
2. **IPFS Governance Snapshots:** Publish daily Merkle root attestations to IPFS and Blossom servers, creating an immutable public audit trail resistant to single-entity takedowns.
3. **Guardian Shamir Setup:** Generate and distribute the 3-of-5 Shamir Secret Sharing (SSS) key shares for emergency DNS registrar maintenance across geographically distinct hardware passkeys.

---

## 5. Sprint Work Breakdown Structure & Milestones

| Sprint Phase | Milestone / Task | Target Repositories | Deliverable Artifact | Verification Method |
|:---|:---|:---|:---|:---|
| **Phase 1.1** | Author Canonical Strategy Specs & Wire Formats | `omni_social` | `docs/strategy/PROTOCOL_...md`<br>`docs/strategy/IMMEDIATE_...md` | Markdown formatting, spec sync dry-run |
| **Phase 1.2** | Standardize Invariant Alert Spec in Project Zero | `omni_social` | `docs/PROJECT_ZERO_SPEC.md` update | Port 9001 wire contract alignment |
| **Phase 1.3** | Satellite Admin Read-Only Audit | `iyou_idp`, `iyou_wun`, `iyou_poly`, `iyou_safe`, `iyou_hive` | `admin.py` patches across satellites | Django admin permission tests |
| **Phase 1.4** | Bridge Air-Gap & Fail-Closed Audit | `iyou_home` | `src-tauri/src/bridge.rs` | Enclave test suite & denial check |
| **Phase 2.1** | Compile Comprehensive Asset Matrix | `omni_social` | `docs/strategy/ASSET_INVENTORY.md` | DNS and repo registry verification |
| **Phase 2.2** | Draft Model Purpose Trust Charter | `omni_social` / Legal | Legal charter template with SFC poison pill | Legal review against open-source trust law |
| **Phase 3.1** | Implement Heartbeat Worker & Key Decay | `iyou_idp`, `iyou_home`, all satellites | Backend decay check & heartbeat listener | Decay simulation unit test |
| **Phase 3.2** | Deploy Community Witness Anchors | `iyou_poly`, `k3s_vm` | Decentralized IPFS/Blossom Merkle anchor script | Merkle root recomputation audit |

---

## References

- `docs/strategy/PROTOCOL_INTEGRITY_AND_POST_MORTEM_GOVERNANCE.md` — Canonical North Star Protocol Strategy
- `docs/PROJECT_ZERO_SPEC.md` — Tiered identity derivation and bridge wire contract
- `docs/OMNI_SOCIAL_PROTOCOL_V2.md` — Meta-protocol specification v2
- `docs/satellite-coordination.md` — Satellite coordination index
- `scripts/sync_ecosystem_specs.py` — Spec push-propagation script
