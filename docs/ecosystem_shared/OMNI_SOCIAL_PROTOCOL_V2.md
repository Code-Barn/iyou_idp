# Omni-Social Meta-Protocol Spec v2

**Objective**: A standardized, interoperable framework for sovereign digital life. Identity is portable, data is content-addressed, governance is verifiable, and every layer is designed for censorship resistance and offline resilience.

**Status**: Living document. Reflects the mature state of the iyou_ ecosystem as of July 2026.

---

## 1. The Core Stack (The "Omni-Stack")

| Layer | Protocol / Tool | Role |
|-------|----------------|------|
| **Identity** | **DID (`did_rust`)** + **OIDC (`iyou_idp`)** | Root of trust. Ed25519 keypairs owned by the user. OIDC bridge for web apps. |
| **Messaging** | **Nostr** | Global event distribution (microblogging, comments, media metadata, governance). |
| **Real-time** | **XMPP (Prosody)** + **OMEMO** | End-to-end encrypted instant messaging, group rooms, tactical comms. |
| **Storage** | **Blossom (BUD-01)** + **IPFS** | Content-addressed blob storage. Blossom for hot storage, IPFS for long-term redundancy. |
| **Governance** | **Poly** | Cryptographically verifiable polling, audit trails, Merkle-anchored vote ledgers. |
| **Enclave** | **`iyou_home` (Tauri/Rust)** | Local secure enclave: key management, signing bridge, Blossom, Nostr relay, XMPP server. |
| **Infrastructure** | **K3s + Traefik + Vault** | Containerized micro-cluster deployment with automated TLS, secret injection, and mesh networking. |

---

## 2. Identity & Authentication (The Mandate)

### 2.1 Sovereign Keypairs

- Users own their private keys. The system uses **Ed25519** for DID signing and **secp256k1 (BIP-340 Schnorr)** for Nostr event signing.
- All key material is derived deterministically from a single 32-byte root seed stored in `iyou_home`:
  ```
  Ed25519 keypair = SHA-256(root_seed || LE(derivation_index))
  secp256k1 keypair = SHA-256("secp256k1-nostr" || root_seed || LE(derivation_index))
  ```
- Private keys **never** leave the Rust enclave. The frontend receives only `did:key:` strings and `nostr_pubkey_hex` values.
- Multi-persona support: each profile at `derivation_index N` yields a unique keypair. **Dual bootstrap:** Index 0 is the Level 0 **Anchor** (immutable, air-gapped from bridge signing) and Index 1 is the Level 1 **Public Persona** (default active signer). Contextual burner personas occupy Index 2..n. See `PROJECT_ZERO_SPEC.md` §3.

### 2.2 Decentralized Identifiers (DID)

- All ecosystem members are identified by a DID (e.g., `did:key:z6Mk...`).
- The DID is the `sub` claim in OIDC tokens and the Django `username` across all satellite apps.
- `did_rust` is shared as a git submodule between `iyou_idp` (`crates/did_rust/`) and `iyou_home` (`libs/did_rust/`). **Both must point to the same commit at all times.**

### 2.3 The OIDC Challenge Framework (`iyou_idp`)

The `iyou_idp` is a Django-based OIDC provider that authenticates users via W3C DIDs instead of passwords. It implements a **three-tier sovereign spectrum**:

| Tier | Tab | Authentication Method |
|------|-----|----------------------|
| **3 — Full Sovereignty** | Full Sovereignty | Desktop WebSocket (`iyou_home` on port 9001) + manual VP paste |
| **2 — Community Self-Signing** | Community Self-Signing | OOB QR-code flow with mobile DID wallet (`iyou_mobile`) |
| **1 — Managed Convenience** | Managed Convenience | OAuth providers (Google, Apple, GitHub) + email/password scaffold |

**Challenge-Response Flow:**
1. Browser requests a challenge → `POST /auth/challenge/` (stored in Redis, 300s TTL)
2. User signs the challenge via one of the three tiers
3. Browser submits the signed VP → `POST /auth/verify/` (desktop) or polls `GET /auth/challenge-status/<uuid>/` (mobile)
4. Server validates through a **three-tier verification pipeline**: Python Ed25519 → Rust `verify_vp` → emergency bypass (logged)
5. On success: `django.contrib.auth.login()` + OIDC authorization code issued

**Executive Decision: No Passwords.** Django password backends are strictly for legacy/fallback use. The `ModelBackend` is kept in `AUTHENTICATION_BACKENDS` only for `force_login` in tests. All primary authentication flows use OIDC/DID exclusively.

### 2.4 The Local WebSocket Bridge

The Signature Bridge (`ws://127.0.0.1:9001`) runs via the Rust background enclave in `iyou_home`. It is the sole cross-origin entry point for browser-based identity providers.

**Supported message types:**

| Type | Gate | Action | Description |
|------|------|--------|-------------|
| `get_profile` → `profile_sync` | Pre-gate | Public metadata | Returns Level 1 Public Persona only (`did`, `nostr_pubkey_hex`, `derivation_index`) — never the Level 0 Anchor |
| `RESOLVE_PEER_ALIASES` → `peer_aliases_resolved` | Pre-gate | Peer resolution | Exact-match batch lookup (≤256 keys, `MAX_RESOLVE_KEYS`) projecting minimal `{nickname, trust_level, badge}` from the contact enclave |
| `sign` | User-gated | OIDC/VP challenge | Returns a Verifiable Presentation signed with the derived Ed25519 key |
| `sign_event` | User-gated | Nostr event signing | Returns `id` and `sig` (secp256k1 BIP-340 Schnorr) |
| `sign_credential` | User-gated | W3C VC issuance | Returns a signed Verifiable Credential |
| `OMNI_SIGN_REQUEST` (`POLY_V2`) | Headless | Poly V2 poll vote | Auto-signing, returns a Nostr Kind 1112 envelope |
| `POLY_CREDENTIAL_REQUEST` → `POLY_CREDENTIAL_PRESENTATION` | User-gated | Credential sharing | User-gated VP presentation via React popup; legacy `POLLY_CREDENTIAL_*` inbound tolerance remains |

Wire contract details (frame schemas, trust tiers, normalization register): see **`PROJECT_ZERO_SPEC.md`**.
| `ping` | Smoke test | Returns `{"type":"pong"}` |

**Wire protocol:** TLS-terminated via `tokio_rustls` with a Let's Encrypt certificate for `home.iyou.me`. PNA (Private Network Access) pre-flight handled at the TLS layer via content-based routing of the first 4 KiB.

### 2.5 Hardware Keys & Passkeys

Layer 2 sovereignty extends to hardware-bound key material:
- **FIDO2/WebAuthn**: Passkeys can be registered as authentication factors in the `iyou_idp` managed tier (Level 1).
- **Hardware security keys**: YubiKey and similar devices can store the root seed or derived keys for offline signing.
- **Mobile DID wallet**: `iyou_mobile` provides QR-code-based OOB signing for community self-signing (Level 2).

---

## 3. Data & Storage (The "Sovereign Home")

### 3.1 Postgres is for Indexing, Not Ownership

- Centralized databases (Postgres) are used only for high-speed discovery and local app state.
- Primary user data (posts, media, profile info) must be stored in **content-addressed formats**.
- The `iyou_home` vault persists per-profile credentials, vote history, and derived keys locally in base64-encrypted JSON.

### 3.2 Blossom Protocol (BUD-01)

- Large files (video, high-res images) are uploaded to a Blossom server (local or cloud) and addressed by their SHA-256 hash.
- Local Blossom runs on port 9002 in `iyou_home`.
- The server provides `GET`, `PUT`, `HEAD`, and `OPTIONS` endpoints.
- CORS/PNA headers are required for cross-origin access from HTTPS pages.

### 3.3 Metadata (NIP-94)

- File descriptions and hashes are broadcast as Nostr `kind:1063` events.
- Media uploads to local Blossom are marked `is_sovereign` and display an amber badge in the feed.

### 3.4 IPFS Optionality

- Blossom serves as the high-speed "hot storage" layer.
- IPFS provides long-term global redundancy and cold governance anchoring.
- The `calculate_vote_merkle_root` command builds a second-preimage resistant SHA-256 Merkle tree over vote signatures for IPFS-published governance anchors.

---

## 4. Communication & Federation

### 4.1 Social Feed (Nostr)

| Kind | Name | Purpose |
|------|------|---------|
| `kind:0` | Profile metadata | Display name, avatar, bio, nip05 |
| `kind:1` | Short text note | Microblogging |
| `kind:7` | Reaction | Emoji reactions |
| `kind:1063` | Media | File uploads with Blossom hash + MIME type |
| `kind:1111` | Threaded comment | Scoped to any ecosystem object (poll, video, file) |
| `kind:1112` | Vote envelope | Cryptographically signed poll vote |
| `kind:30023` | Long-form / Poll | Articles, project docs, and poll definitions |
| `kind:9112` | Trust attestation | Web-of-Trust graph sync (iyou_safe) |

**Double-Broadcast:** When posting, signed events are sent simultaneously to:
- `ws://127.0.0.1:9003` (local relay — sovereign copy)
- `wss://relay.iyou.me` (project relay)
- `wss://nos.lol` (global relay)

Broadcasting is parallel — one relay failure does not block others.

**Executive Decision: Nostr replaces ActivityPub.** Nostr's relay-based architecture aligns with our key-based DID identity and client-side-first logic.

### 4.2 Real-time Chat (XMPP)

- Used for secure, low-latency DMs and group rooms.
- XMPP JIDs are mapped to the user's DID: `{user_did}@{domain}`.
- OMEMO encryption for end-to-end privacy.
- Converse.js provides the web client.
- Server selection based on sovereignty level:

| Level | Mode | XMPP Domain | WebSocket Endpoint |
|-------|------|-------------|-------------------|
| `1` | Managed (cluster) | `iyou.me` | `wss://xmpp.iyou.me:5222/xmpp-websocket` |
| `2` | Sovereign (local) | `127.0.0.1` | `wss://home.iyou.me:5222/xmpp-websocket` |

### 4.3 XMPP/OMEMO Specifications

- All messages remain local to the XMPP server and are **never** stored in satellite app databases.
- Room names for group sessions (COGS/POGS) use `SHA-256("{classification}:{slug}:{topic_tag}")`.
- POIS rooms use `SHA-256("pois:{user_sub}:{provider_id}")` — salted per user-provider pair.
- Tactical comms rooms for `iyou_safe` responders are created as MUC (Multi-User Chat) instances with ephemeral JIDs.

---

## 5. Governance (The Poly Integration)

### 5.1 Protocolized Opining

- Every project in the ecosystem must support the **Poly Protocol**.
- Votes are signed by the user's DID and anchored to the Omni-Social Merkle Ledger.
- The Poly governance engine runs as a headless calculation engine at `POLY_ENGINE_URL`.

### 5.2 Verifiable Vote Pipeline

1. User selects an option → JS constructs a kind 1112 Nostr event with `vote_envelope` content
2. Tauri bridge signs the event via `ws://127.0.0.1:9001` — browser never touches the private key
3. Signed result packaged into V2 proxy format: `{voter_did, signature, vote_envelope}`
4. WUN proxies to `{POLY_ENGINE_URL}/api/v2/polls/{id}/cast/`
5. Engine validates signature and returns `{valid, details}`

### 5.3 Scoped Transparency

- Users can filter polls based on geographical or social scope.
- Geographic scopes use 7-character geohash strings.
- Org scopes use tags like `["org", "iyou"]` for family-scoped or `["geohash", "global"]` for public polls.

### 5.4 Cold Governance Anchoring

- `calculate_vote_merkle_root` builds a Merkle tree over `VoteRecord.client_signature` fields.
- Domain separation: `0x00` leaf prefix, `0x01` internal prefix (second-preimage resistant).
- Root hex strings can be compared against `ipfs_cid` hashes published by server-side anchors.
- The `iyou_home` IPFS Cloud Archive Viewer provides a UI for local-vs-published audit.

---

## 6. Network Resilience & Routing

### 6.1 Censorship Resistance

| Strategy | Implementation |
|----------|---------------|
| **Tor hidden services** | `.onion` addresses for relay endpoints and IdP access |
| **I2P anonymous destinations** | `.b32.i2p` endpoints for long-lived services |
| **Relay redundancy** | Double-broadcast to local + project + global relays |
| **Content addressing** | Blossom + IPFS ensure data survives endpoint takedowns |

### 6.2 Subdomain Routing Standards

- Geographic routing is implemented via right-to-left subdomain parsing in `GeographicRoutingMiddleware`.
- Pattern: `[locality].[state].[country].{app}.iyou.me`
- All apps share the same middleware implementation with per-app base domain configuration.
- System keywords (`admin`, `api`, `mods`, `devs`) bypass geographic extraction.
- Invalid tiers raise `Http404` immediately, preventing enumeration.

### 6.3 Regional Polling Engines

- Poly governance supports regional boundaries via geohash-scoped poll definitions.
- Subdomain routing isolates regional polling instances without separate deployments.
- Transnational boundary merging is supported via `Q(geo_scope__contains=segment)` OR-chaining.

---

## 7. Deployment & Orchestration

### 7.1 K3s Micro-Cluster Standard

| Component | Detail |
|-----------|--------|
| Cluster | K3s (single-node), Debian VM |
| Ingress | Traefik (entrypoints: `web`, `websecure`) |
| Certificates | cert-manager + Let's Encrypt HTTP-01 |
| Secrets | HashiCorp Vault (standalone) + External Secrets Operator |
| Storage | ZFS-backed, local-path provisioner, hostPath for apps |
| Mesh VPN | Headscale (self-hosted Tailscale control server) |
| External Bridge | VPS w/ Nginx stream proxy + WireGuard (10.0.0.0/24) |

### 7.2 Immutable App Onboarding Framework

Every new app follows the same deployment pipeline:

**Step 1: Helm Chart Scaffold** — Copy `apps/iyou-poly/` template, edit `Chart.yaml`, `values.yaml`, and `templates/deployment.yaml`.

**Step 2: Build Pipeline** — Cross-VM pipeline: source repo → dc13 build VM → `docker save` → pipe to K3s → `ctr import` → Helm upgrade.

**Step 3: Secret Injection** — Vault path `secret/mesh-infra/<app-name>`, `ExternalSecret` resource syncs to K8s secret.

**Step 4: Ingress / TLS** — cert-manager `ClusterIssuer` with HTTP-01 challenge. VPS → WireGuard → K3s tunnel.

**Step 5: Storage** — `hostPath` under `/var/lib/k3s-data/<app-name>` on ZFS-backed filesystem.

**Step 6: OIDC Client Registration** — `seed_clients` management command in `iyou_idp` provisions the relying party. Deploy scripts handle first-deploy and persistent registration.

### 7.3 Application Catalog

| Domain | App | Namespace | Stack |
|--------|-----|-----------|-------|
| iyou.me | iyou_idp | identity | Django + Rust FFI |
| wun.iyou.me | iyou_wun | iyou-wun | Django |
| poly.iyou.me | iyou_poly | iyou-poly | Django |
| name.iyou.me | iyou_name | iyou-name | Django + Wand |
| hive.iyou.me | iyou_hive | iyou-hive | Django + Celery/Redis |
| ride.iyou.me | iyou_ride | iyou-ride | Django |
| dctech.iyou.me | dc_tech_website | dc-tech | Django |
| safe.iyou.me | iyou_safe | iyou-safe | Django |
| talk.iyou.me | iyou_talk | iyou-talk | Django |
| clar.iyou.me | iyou_clar | iyou-clar | Django |
| play.iyou.me | iyou_play | iyou-play | Django |
| blog.iyou.me | iyou_blog | iyou-blog | Django |
| help.iyou.me | iyou_help | iyou-help | Django |
| draw.iyou.me | iyou_draw | iyou-draw | Django |
| life.iyou.me | iyou_life | iyou-life | Django |
| walk.iyou.me | iyou_walk | iyou-walk | Django |
| stay.iyou.me | iyou_stay | iyou-stay | Django |
| dev.iyou.me | iyou_dev | iyou-dev | Django |
| spot.iyou.me | iyou_spot | iyou-spot | Django |
| baba.iyou.me | iyou_baba | iyou-baba | Django |
| dine.iyou.me | iyou_dine | iyou-dine | Django 6.0 / Restaurant OS |
| show.iyou.me | iyou_show | iyou-show | Django 6.1 / Video Index |
| muse.iyou.me | iyou_muse | iyou-muse | Django 6.1 / Exhibition Gallery |
| hear.iyou.me | iyou_hear | iyou-hear | Django 6.1 / Audio Satellite |
| home.iyou.me | iyou_home | — | Tauri/Rust (local) |
| relay.iyou.me | Nostr Relay | nostr-relay | Rust |
| chat.iyou.me | Prosody XMPP | prosody | Prosody |
| keys.iyou.me | Vaultwarden | vaultwarden | Rust |

---

## 8. UI/UX Layer 0: Ecosystem Standardization

### 8.1 Ecosystem Bar (`_ecosystem_bar.html`)

- Fixed top bar, hidden to 4px by default, expands on hover.
- Lists all ecosystem apps with `/` separators.
- Current app is bolded: `text-white font-bold tracking-normal`.
- All other links: `hover:text-white transition-colors duration-150`.
- Label text uses the app's accent color.
- Bridge probe: `fetch('http://127.0.0.1:9001/')` with 300ms timeout, re-probes every 15 seconds.

### 8.2 Standard Header (`_standard_header.html`)

- White/dark header with `iyou_` branding + app name.
- Authenticated state: green pulse dot + username (truncated to 240px) + Sign Out.
- Unauthenticated state: amber dot + "Sovereign Key Required" + Sign In button.
- Sign In button uses the app's accent color.
- Dark mode support via `dark:` Tailwind variants.

### 8.3 Tailwind Accent Color Constraint

**Executive Decision: No two apps share the same accent color.**

Each app gets a unique Tailwind color used in:
1. `_ecosystem_bar.html` — border and label text color
2. `_standard_header.html` — "iyou_" brand text and Sign In button

| App | Color | Notes |
|-----|-------|-------|
| iyou_poly | purple | Ecosystem Core |
| iyou_wun | violet | Social Hub |
| iyou_play | amber | Athletics Master (reference) |
| iyou_clar | emerald | Directory Ledger |
| iyou_hive | orange | Legal Vault |
| iyou_talk | cyan | Mental Support |
| iyou_safe | rose | Crisis Triage |
| iyou_name | teal | Genealogy Registry |
| iyou_ride | lime | Transit Auction |
| dc_tech_website | indigo | Corporate Hardening |
| iyou_idp | — | Identity Provider (no accent — system root) |
| iyou_blog | sky | Sovereign Publishing on Nostr |
| iyou_help | red | Help & Support |
| iyou_draw | fuchsia | Visual Creation Studio |
| iyou_life | sky | Life Stories & Legacy |
| iyou_walk | green | Pedestrian Mesh & Dog Walking Coordination |
| iyou_stay | yellow | Hospitality & Accommodation |
| iyou_dev | zinc | Developer Portal & API Docs |
| iyou_spot | pink | Local Discovery & Recommendations |
| iyou_baba | blue | Sovereign Sticker Vault |
| iyou_chat | blue | Sovereign Messenger Hub |
| iyou_dine | amber | Sovereign Restaurant Operating System, 0% Take-Rate Settlement, Line-to-Floor Telemetry |
| iyou_show | rose | Zero-Custody Video Channel Indexer & Multi-Source Player |
| iyou_muse | indigo | Attribution-First Public Exhibition Gallery |
| iyou_hear | amber | Sovereign Audio, Podcast & Value-for-Value Stream Router |

**Available colors:** `amber` `purple` `emerald` `rose` `cyan` `teal` `indigo` `blue` `pink` `orange` `lime` `sky` `violet` `fuchsia` `red` `green` `yellow` `zinc`

**Static generation required:** Django template variables like `{{ accent_color }}` do NOT work because Tailwind needs static class strings at build time. Each app gets its own copy with the color hardcoded, generated via `generate_templates.py`.

### 8.4 Responsive Mobile Breakpoints

- **Horizontal swipe overrides** for ecosystem links on sub-375px screens.
- **Tokenized/iconographic auth labels** for small viewports (replace text labels with icons).
- **Ecosystem bar** scrolls horizontally on mobile when links overflow.

---

## 9. The Sovereign Spectrum

We recognize that "Total Sovereignty" is a high bar. We offer three modes of participation:

### Level 3 — Full Sovereignty
- User keys are stored locally in `iyou_home`.
- Signing requests are sent via the **Local WebSocket Bridge** (`ws://127.0.0.1:9001`).
- Multi-persona support with deterministic key derivation.
- Poll vote ledger maintained locally with Merkle anchoring.
- All services bind to `127.0.0.1` — no public exposure.

### Level 2 — Community Self-Signing
- Mobile DID wallet (`iyou_mobile`) for QR-code-based OOB signing.
- Keys stored on the mobile device.
- Suitable for community environments where desktop enclave is unavailable.

### Level 1 — Managed Convenience
- User keys are stored in a secure cloud vault (managed by `iyou_idp`).
- OAuth providers (Google, Apple, GitHub) + email/password scaffold.
- Passkey/FIDO2 support for hardware-bound credentials.
- Easiest for onboarding.

---

## 10. Strategic Directives for Developers

1. **Use the Enclave**: In `iyou_home`, never expose raw keys to the React frontend. Keep signing in the Rust backend. The frontend sees only `did:key:` strings.

2. **Standardize Envelopes**: All API responses involving verification must follow the JSON schema:
   ```json
   {"valid": true, "error": "", "details": {}}
   ```

3. **Relay to Home Base**: Satellite apps (`iyou_wun`, `iyou_poly`) must provide a "Sync to Home" mechanism that pushes user data/history to their local `iyou_home` instance for backup.

4. **127.0.0.1 Binding Rule**: ALL local services must bind to `127.0.0.1` — never `localhost`. This eliminates IPv6 ambiguity, ensures OIDC issuer matching, prevents cookie domain mismatches, and satisfies Safari PNA requirements.

5. **Cookie Isolation**: Every app must set unique `SESSION_COOKIE_NAME` and `CSRF_COOKIE_NAME` values (e.g., `play_sessionid`, `wun_csrftoken`) to prevent cross-app collisions on shared loopback.

6. **No Postgres for Primary Data**: Use Postgres only for indexing and local app state. Primary user data lives in content-addressed formats (Blossom, IPFS, local vault).

7. **Ecosystem Bar First**: Include `_ecosystem_bar.html` BEFORE `_standard_header.html` in all base templates. The ecosystem bar is the universal navigation fabric.

8. **Unique Accent Colors**: Every app MUST have a unique Tailwind accent color. Run `python3 generate_templates.py <slug> <color>` to generate compliant templates.

9. **Geographic Routing**: All apps that support localized content must implement `GeographicRoutingMiddleware` with right-to-left subdomain parsing. Raise `Http404` on unrecognized subdomain structures.

10. **Test the Bridge**: Always test WebSocket signing flows with both connected and disconnected states. The bridge probe must handle 300ms timeouts gracefully and fall back to manual paste.

---

## Appendix A: Port Map

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Signature Bridge | 9001 | WSS | Nostr/DID signing |
| Blossom | 9002 | HTTP | Content-addressed blob storage |
| Local Nostr Relay | 9003 | WebSocket | Sovereign event relay |
| XMPP (Chat) | 5222 | WSS | Encrypted messaging |
| iyou_idp | 8000 | HTTP | OpenID Provider |
| iyou_wun | 8001 | HTTP | Feed + social |
| iyou_poly | 8002 | HTTP | Governance engine |
| iyou_draw | 8011 | HTTP | Visual Creation Studio |
| iyou_dine | 8028 | HTTP | Sovereign Restaurant Operating System |
| iyou_show | 8029 | HTTP | Zero-Custody Video Channel Indexer |
| iyou_muse | 8030 | HTTP | Attribution-First Public Exhibition Gallery |
| iyou_hear | 8031 | HTTP | Sovereign Audio & V4V Stream Router |

## Appendix B: Nostr Event Kind Registry

| Kind | Name | Source | Purpose |
|------|------|--------|---------|
| 0 | Profile metadata | `iyou_home` | User identity |
| 1 | Short text note | `iyou_wun` | Microblogging |
| 7 | Reaction | `iyou_wun` | Emoji reactions |
| 1063 | Media (NIP-94) | `iyou_wun` + Blossom | File storage + metadata |
| 1111 | Threaded comment | `iyou_wun` | Contextual discussion |
| 1112 | Vote envelope | `iyou_wun` + Poly | Governance voting |
| 30023 | Long-form / Poll | `iyou_wun` + Poly | Articles + poll definitions |
| 9112 | Trust attestation | `iyou_safe` | Web-of-Trust graph sync |

## Appendix C: Ecosystem App Links (25-App Absolute Roster)

| Label | URL |
|-------|-----|
| idp | https://iyou.me |
| wun | https://wun.iyou.me |
| poly | https://poly.iyou.me |
| name | https://name.iyou.me |
| hive | https://hive.iyou.me |
| ride | https://ride.iyou.me |
| dctech | https://dctech.iyou.me |
| safe | https://safe.iyou.me |
| talk | https://talk.iyou.me |
| clar | https://clar.iyou.me |
| play | https://play.iyou.me |
| blog | https://blog.iyou.me |
| help | https://help.iyou.me |
| draw | https://draw.iyou.me |
| life | https://life.iyou.me |
| walk | https://walk.iyou.me |
| stay | https://stay.iyou.me |
| dev | https://dev.iyou.me |
| spot | https://spot.iyou.me |
| baba | https://baba.iyou.me |
| chat | https://chat.iyou.me |
| dine | https://dine.iyou.me |
| show | https://show.iyou.me |
| muse | https://muse.iyou.me |
| hear | https://hear.iyou.me |
