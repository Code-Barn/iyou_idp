# Canonical Strategy: Ecosystem Vision, Dual-Entity Architecture & Brand Charter

**Document Identifier:** OMNI-STRAT-DUAL-ENTITY-V1  
**Hub:** omni_social  
**Path:** docs/strategy/ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md  
**Status:** Living Canonical Charter  
**Companion Documents:**  
- `docs/strategy/PROTOCOL_INTEGRITY_AND_POST_MORTEM_GOVERNANCE.md`  
- `docs/strategy/IMMEDIATE_INTEGRITY_EXECUTION_PLAN.md`  
- `docs/DEVELOPER_TRANSLATION_MANUAL.md`  

---

## 1. Preamble & Sovereign Philosophy

The `iyou_` ecosystem is engineered on two non-negotiable principles:
1. **The Software Belongs to Humanity:** The protocols, cryptographic wire contracts, and baseline codebases are irrevocable open commons that cannot be captured, monetized through rent-seeking tolls, or corporatized.
2. **Generational Independence for the Founders:** The creator's family estate and commercial operations must achieve financial security through sovereign commercialization (physical production, advanced compute licenses, and enterprise service rails), shielded from protocol liabilities.

These two objectives do not conflict; they are strictly separated by an architectural and legal firewall.

---

## 2. The Dual-Entity Structural Wall

```text
                     ┌──────────────────────────────────────────────┐
                     │         THE SOVEREIGN COMMONS                │
                     │  Code Barn Software Foundation (PPT)         │
                     │  - Irrevocable Perpetual Purpose Trust       │
                     │  - Custodian of AGPLv3 code, wire specs      │
                     │  - EFF/SFC Poison Pill Asset Surrender       │
                     └──────────────────────┬───────────────────────┘
                                            │ Irrevocable AGPLv3 / CC0
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        THE COMMERCIAL ENGINE & FAMILY ESTATE                           │
│                                  Byers Brands, LLC                                     │
│  - 100% privately held family asset (perpetual multi-generational trust)               │
│  - Commercial trademarks, physical print hardware, enterprise SaaS/appliance revenue   │
│  - Monetization Vectors:                                                               │
│      1. iyou_name: Archival large-format plot prints & Gen 8/9/10 compute licenses     │
│      2. Enterprise Turnkey Appliances: Managed K3s nodes for municipalities/orgs      │
│      3. Identity Concierge: White-glove sovereign node setup & physical hardware keys  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 The Sovereign Commons: Code Barn Software Foundation
* **Legal Form:** Irrevocable Perpetual Purpose Trust (PPT), operating with zero equity shareholders.
* **Mandate:** Preserve and defend open protocol specifications (`OMNI-FED-SPEC-V1`, `OMNI-DEP-GRAD-SPEC-V1`), the public Git repositories, and copyleft licensing (AGPLv3 / Blue Oak / CC0).
* **Asset Containment:** Apex specifications, reference protocol tests, protocol verification testbenches, and public documentation.
* **Poison Pill:** In the event of hostile legal acquisition or judicial attack on trust governance, all custodial domains, specifications, and repositories immediately transfer to public software conservancies (Software Freedom Conservancy / Electronic Frontier Foundation).

### 2.2 The Commercial Operating Company: Byers Brands, LLC
* **Legal Form:** Limited Liability Company 100% held within the founder's family trust, inherited directly by the founder's daughters.
* **Mandate:** Commercial exploitation of products, hardware, enterprise appliances, and managed services built on top of the open protocols.
* **Revenue Pillars:**
  1. **Genealogical Printing & Deep Compute (`iyou_name`):** Free tier provides standard family tree renderings. Generations 8, 9, and 10 compute algorithms (leveraging `iyou_name_rust` / PyO3) and large-format physical plotting/printing services are proprietary offerings sold directly by Byers Brands.
  2. **Turnkey Sovereign Appliances:** Pre-configured K3s micro-clusters, local storage vaults, and hardened edge routers for institutional governance (`iyou_poly`) and corporate intranets (`dc_tech_website`).
  3. **Commercial Hosting & Domain Services:** White-glove node federation, managed backups, and DNS ingress hosting.

---

## 3. Brand Identity & The OMNI Mythos

### 3.1 Aesthetic & Narrative Irony
The OMNI brand identity—embodied in the chrome wireframe globe—intentionally evokes 1980s cinematic mega-conglomerates (*RoboCop*'s Omni Consumer Products, *Terminator*'s Cyberdyne Systems). 

* **The Satirical Shield:** It projects the visual dominance and unyielding precision of an omnipotent infrastructure entity.
* **The Sovereign Reality:** The corporate fortress is an empty shell. Behind the imposing facade lies zero centralized telemetry, zero user data harvesting, zero tracking databases, and mathematically verifiable individual sovereignty. It is "everywhere" only because the individual controls their own node.

### 3.2 Product Branding Hierarchy
* **OMNI / omni_social:** The overarching technology protocol, coordination engine, and open-source specification suite.
* **iyou / iyou_ (`iyou.me`):** The consumer-facing software implementation—the suite of 19 sovereign satellite applications, the identity provider, and local desktop/mobile enclaves.
* **Code Barn:** The engineering lab and foundation identity stewarding open-source creation.
* **Byers Brands:** The commercial enterprise and consumer product company.

---

## 4. Governance, Host Liability & Administrative Posture

### 4.1 The Node Operator vs. Protocol Boundary
Decentralized protocols do not protect a physical human from statutory hosting liability. The system architecture enforces a clean separation:
* **The Open Protocol:** Pure cryptographic math transiting Nostr relays, Blossom stores, and P2P bridges. Neutral, immutable, and censorship-proof.
* **The Host Ingress (`iyou.me`):** A physical server infrastructure paid for and administered by the founder. Illegal content (CSAM, criminal coordination) is strictly forbidden from the `iyou.me` domain ingress.
* **Moderation Without Protocol Censorship:** Host moderation operates via Traefik ingress routing, client-side Web-of-Trust (WoT) scoring, NIP-36 content warnings, and NIP-56 reporting events (Kind 1984). Bad actors are severed from the host's domain routing without tampering with the underlying cryptographic ledger or client keypairs.

### 4.2 Codebase Contribution & Privileges
* **Zero Shared Infrastructure Keys:** No outside collaborator receives SSH access, database superuser roles, or cluster secrets.
* **Standard Pull Request Workflows:** External developers contribute via standard GitHub pull requests against satellite repositories, validating code locally against `127.0.0.1:8000`.
* **Administrative Posture Hooks:** Administrative capabilities on live satellites remain strictly tied to `ADMIN_DID` evaluation in session backends, protected by dead-man key decay time-locks.

---

## 5. Public Release Strategy: Launch Perimeter & Lifecycle States

### 5.1 Initial Launch Perimeter
To maximize launch impact and maintain strict code quality, focus is narrowed to five perimeter satellites anchored by root identity:
* **`iyou_idp` + `iyou_home`:** Root Sovereign Identity Provider & Desktop Cryptographic Enclave.
* **`iyou_wun` (Violet):** Social Hub, Activity Feed & Sovereign Profiles.
* **`iyou_poly` (Purple):** Consensus Engine & Cryptographic Polling.
* **`iyou_name` (Teal):** Kinship Graph & Commercial Genealogy Registry.
* **`iyou_hive` (Orange):** Legal Vault, Proofs & Document Enclave.
* **`iyou_draw` (Fuchsia):** Sovereign Visual Studio & Blossom Media Canvas.

### 5.2 Application Lifecycle States
Every satellite in the 19-app protocol order (`idp / wun / poly / name / hive / ride / dctech / safe / talk / clar / play / blog / help / draw / life / walk / stay / dev / spot` + `baba`) is assigned an explicit status in `omni_social`:

| Status | Presentation in Layer 0 Bar | Routing / Intercept Behavior | Ingress Layer (Traefik / K3s) |
| :--- | :--- | :--- | :--- |
| `ACTIVE` | Full opacity, active accent underline | Direct HTTP navigation | Fully open public ingress route |
| `BETA` | Full opacity with subtle `beta` pill | Direct HTTP navigation | Fully open public ingress route |
| `DEV_WIP` | Muted (`opacity-50 text-slate-500`), `[wip]` tag | Click intercepted to Onboarding Modal | Shielded by `SovereignGatingMiddleware` |
| `INCUBATING` | Accent pulse dot, prominent hover highlight | Click intercepted to Co-Developer Modal | Shielded by `SovereignGatingMiddleware` |

---

## 6. Document Audit Trail & Registry
* **Authored:** 2026-10-01  
* **Approved By:** Sovereign Architecture Council (`ADMIN_DID`)  
* **Execution Target:** Phase 2 Legal Structuring / Phase 1 Ingress Rollout  

### 6.1 Hub Orchestration Integration
To make this vision canonical across the entire fleet, link it into the existing `omni_social` sync mechanisms:

1. **Add to `scripts/sync_ecosystem_specs.py`:**  
   Add `("docs/strategy/ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md", "ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md")` to the `SPEC_FILES` distribution array so it copies into `docs/ecosystem_shared/` across all satellite repositories during horizontal pushes.

2. **Register in `AGENT.md` & `docs/satellite-coordination.md`:**  
   Add a tracking line under the Protocol Integrity & Governance Specifications table:

| Document | Path | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Ecosystem Vision & Dual-Entity Charter** | [`ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md`](strategy/ECOSYSTEM_VISION_AND_DUAL_ENTITY_CHARTER.md) | Canonical Living Charter | Defines Perpetual Purpose Trust vs. Byers Brands LLC separation, OMNI mythos, moderation posture, and launch perimeter roadmap. |
