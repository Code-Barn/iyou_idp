# Omni-Social Peer Federation & Open Protocol Specification

**Specification Identifier:** `OMNI-FED-SPEC-V1`  
**Hub:** `omni_social`  
**Status:** Living Canonical Standard  
**Published:** 2026-08-30  
**Target Implementers:** Independent Hub Operators (e.g., `hub.community.org`, `node.domain.tld`), Satellite Application Developers, Client Integrators, Relay & Blossom Storage Operators  

---

## 1. Executive Summary & Federation Mandate

The **Omni-Social Federation Protocol** establishes an open, decentralized standard for sovereign digital life. In this architecture, user identity is self-custodied, data is cryptographically signed and content-addressed, governance is provably verifiable via Merkle structures, and communication meshes across autonomous peer hubs without single points of failure.

### 1.1 The Sovereign Mandate

Traditional federated social protocols (such as ActivityPub) tie user identity and data residency to a specific server domain. If the server goes offline or changes administration policies, the user loses their social graph, post history, and verified identity.

Omni-Social breaks this server-centric paradigm through five non-negotiable architectural mandates:

1. **Zero-Custody Cryptographic Identity:** Identity is rooted strictly in asymmetric keypairs (`did:key:z6Mk...` via Ed25519 for identity assertions, `secp256k1` via BIP-340 Schnorr for Nostr events). No server holds user private keys or passwords.
2. **Postgres is for Indexing, Not Ownership:** Relational databases serve exclusively as transient local projection caches. The canonical source of truth consists exclusively of signed Nostr events and content-addressed Blossom blobs.
3. **Decoupled Relay Gossip Federation:** Peer instances do not exchange messages via server-to-server HTTP inbox/outbox queues. Instead, peer hubs and clients synchronize via distributed Nostr relay meshes.
4. **Content-Addressed Binary Storage (Blossom BUD-01):** Binary media is addressed strictly by SHA-256 cryptographic hashes and replicated across a three-tier failover topology (Local Enclave $\rightarrow$ Peer Blossom Hubs $\rightarrow$ Global CDNs / IPFS).
5. **Deterministic Verifiability:** All ecosystem actions (social posts, threaded comments, media attachments, governance votes) are self-verifying cryptographic envelopes that can be independently audited by any node.

### 1.2 Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## 2. Identity Layer & Cryptographic Root of Trust

Identity in Omni-Social is self-sovereign, transport-independent, and cryptographically anchored.

```
                    ┌─────────────────────────────────────────┐
                    │      32-byte Master Root Seed           │
                    │      (Held in Local Secure Enclave)     │
                    └────────────────────┬────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
     Ed25519 DID Key Derivation                     secp256k1 Nostr Key Derivation
   SHA-256(seed || LE(derivation_index))       SHA-256("secp256k1-nostr" || seed || LE(idx))
                 │                                               │
                 ▼                                               ▼
         W3C DID Document                                Nostr Public Key
       `did:key:z6Mku...`                               64-character Hex String
                 │                                               │
                 └───────────────────────┬───────────────────────┘
                                         │
                                         ▼
                      ┌─────────────────────────────────────┐
                      │    Secretless OIDC PKCE Ingress     │
                      │  `sub` claim strictly pinned to DID │
                      │      Zero Passwords Permitted       │
                      └─────────────────────────────────────┘
```

### 2.1 W3C Decentralized Identifier (DID) Derivation

All participants in the Omni-Social federation are identified by a W3C Decentralized Identifier using the `did:key` method formatted with Multicodec and Multibase standards:

- **Algorithm:** Ed25519 (`ed25519-pub`, multicodec `0xed01` / `0xed`, raw 32-byte public key).
- **Multibase Encoding:** Base58BTC format indicated by the prefix character `z`.
- **String Format:** `did:key:z6Mk...` (53 characters total length).
- **Canonical Derivation Rule:**
  $$\text{Ed25519 Keypair} = \text{SHA-256}(\text{root\_seed} \parallel \text{LE32}(\text{derivation\_index}))$$
  $$\text{secp256k1 Keypair} = \text{SHA-256}(\text{"secp256k1-nostr"} \parallel \text{root\_seed} \parallel \text{LE32}(\text{derivation\_index}))$$

All derivations MUST use Little-Endian 32-bit integer encoding (`LE32`) for the index parameter.

### 2.2 Persona Hierarchy & Air-Gap Invariant

The deterministic derivation engine maintains three functional persona tiers:

| Tier | Derivation Index | Persona Identifier | Security Scope | Wire Invariant |
|:---|:---|:---|:---|:---|
| **Level 0** | Index `0` | `anchor` | **Air-Gapped Root Sanctum** | **MUST NOT** be exposed to browser pickers or public signing bridges. Reserved for peer-to-peer trust cards and root key containment. |
| **Level 1** | Index `1` | `primary` | **Default Public Signer** | Default active persona for OIDC PKCE ingress, social feed posting (`kind:1`, `kind:1111`), and public profile sync (`kind:0`). |
| **Level 2+**| Index $2 \dots n$ | Contextual UUID / Sock | **Disposable Burner Personas** | Context-specific personas for domain isolation, anonymous opining, and disposable interactions. |

Implementations **MUST** enforce the **Air-Gap Invariant**: Any bridge frame or external API call requesting signature or profile metadata for `derivation_index == 0` or `level == 0` MUST fail-closed with an immediate rejection (`ERR_AIR_GAP_VIOLATION`).

### 2.3 Secretless OIDC PKCE Ingress Protocol

Satellite applications and federated web services authenticate users through OpenID Connect (OIDC) with Proof Key for Code Exchange (PKCE, RFC 7636) in public client mode.

#### The Invariant of Identity Anchoring:
- The `sub` (Subject) claim in all issued ID tokens and UserInfo payloads **MUST** be strictly pinned to the user's canonical DID string (e.g., `did:key:z6Mku...`).
- Passwords are fundamentally eliminated across all services. The Django/backend password field MUST be marked as unusable (`set_unusable_password()`). No fallback password backend may authenticate users in production.

#### PKCE Protocol Sequence:

1. **Authorization Initiation:** Satellite client generates a cryptographically secure random `code_verifier` (43–128 characters, unreserved URL characters) and derives `code_challenge`:
   $$\text{code\_challenge} = \text{BASE64URL-NOPAD}(\text{SHA-256}(\text{code\_verifier}))$$
2. **Authorize Redirect:** Browser navigates to:
   ```http
   GET /openid/authorize/?client_id={slug}-satellite-client
     &redirect_uri=https://{app.domain.org}/oidc/callback/
     &response_type=code
     &scope=openid%20profile%20email
     &state={csrf_token}
     &code_challenge={code_challenge}
     &code_challenge_method=S256
   ```
3. **Cryptographic Challenge & Signing:** The Identity Provider creates a UUID challenge cached in memory with a 300s TTL. The client signs the challenge via the local enclave bridge (`ws://127.0.0.1:9001`) with their Level 1 Ed25519 key, generating a W3C Verifiable Presentation.
4. **Token Exchange:** The satellite server exchanges the authorization code for tokens over a backchannel:
   ```http
   POST /openid/token/
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code={auth_code}
   &redirect_uri=https://{app.domain.org}/oidc/callback/
   &client_id={slug}-satellite-client
   &code_verifier={code_verifier}
   ```
   **No `client_secret` parameter is sent or accepted.** The IDP validates the verifier against the cached challenge in constant time using `hmac.compare_digest()`.
5. **Token Verification:** Satellite validates the RS256 signature against the IDP JWKS endpoint (`/.well-known/jwks.json`) and binds the session user to `id_token.sub`.

---

## 3. Data Federation vs. Database Caches

A foundational architectural divide distinguishes Omni-Social from traditional federated web platforms.

### 3.1 The Canonical Rule: "Postgres is for Indexing, Not Ownership"

In the Omni-Social architecture:

> **Postgres is strictly a query optimization layer and local cache. Postgres owns nothing.**

- Primary user data (profiles, posts, thread comments, governance ballots, media links) is stored in **content-addressed blobs** and **digitally signed event streams**.
- A node operator can completely drop and purge their PostgreSQL database without data loss. Upon restarting, the node re-indexes historical Nostr events from configured relays and re-populates its query tables.
- Node databases MUST NOT generate surrogate synthetic primary keys that are treated as universal identifiers across nodes. All cross-system entity relationships MUST reference the Nostr Event ID (`id` 32-byte hex) or the Blossom Content Hash (`sha256` 32-byte hex).

### 3.2 Why Nostr Relay Meshes Replace ActivityPub Server Queues

Omni-Social explicitly rejects the ActivityPub server-to-server inbox/outbox federation queue model in favor of Nostr relay gossip meshes:

```
ActivityPub Model (Rejected):
┌────────────────┐      HTTP POST Queue       ┌────────────────┐
│  Server A      │───────────────────────────▶│  Server B      │
│  (Holds Key &  │   (Fails if B is offline   │  (Inbox Queue  │
│   User DB)     │    or domain changes)      │   Database)    │
└────────────────┘                            └────────────────┘

Omni-Social Model (Mandated):
┌───────────────────────────┐
│ User Client / Enclave     │
│ (Holds Keypair Sovereign) │
└─────────────┬─────────────┘
              │ Parallel Multi-Broadcast (Double-Broadcast)
    ┌─────────┼─────────┐
    ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌───────┐
│ Local │ │ Hub   │ │Global │  <── Relays do not communicate with each other;
│ Relay │ │ Relay │ │ Relays│      Clients subscribe to arbitrary relay sets.
└───────┘ └───────┘ └───────┘      No server queues, no lost inbox deliveries.
```

| Dimension | ActivityPub (Server-Centric) | Omni-Social (Relay Mesh + Content Addressing) |
|:---|:---|:---|
| **Identity Ownership** | Server owns username and private key | User strictly owns Ed25519/secp256k1 keypair |
| **Federation Mechanism**| Server-to-server point-to-point HTTP queues | Decentralized gossip over multi-relay WebSocket mesh |
| **Delivery Failure** | If recipient inbox is offline, message drops or retries fail | Relays store events permanently; clients backfill via filters |
| **Domain Portability** | Moving domain destroys identity & followers | Identity is domain-independent; follows are signed pubkey tags |
| **Censorship Model** | Server admin can censor/alter user history | Events are cryptographically signed; relay cannot tamper without invalidating signatures |
| **Large Media** | Uploaded to server disk; hotlinking fragile | Blossom SHA-256 binary blobs replicated across multi-node mesh |

---

## 4. Nostr Event Wire Registry

All social interactions, media declarations, and governance operations are formatted as Nostr events conforming to [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md).

### 4.1 Canonical Wire Envelope Schema

Every Nostr event transmitted across the federation MUST conform to the standard JSON structure:

```json
{
  "id": "<32-byte lowercase hex SHA-256 of serialized event data>",
  "pubkey": "<32-byte lowercase hex secp256k1 public key of author>",
  "created_at": 1725000000,
  "kind": 1,
  "tags": [
    ["p", "<target-pubkey-hex>", "wss://relay.hub.org"],
    ["e", "<referenced-event-id-hex>", "wss://relay.hub.org", "root"]
  ],
  "content": "Short text note content",
  "sig": "<64-byte lowercase hex BIP-340 Schnorr signature over id>"
}
```

#### Event ID Serialization Rule (NIP-01):
$$\text{id} = \text{SHA-256}(\text{json.dumps}([0, \text{pubkey}, \text{created\_at}, \text{kind}, \text{tags}, \text{content}], \text{separators}=(',', ':')))$$

### 4.2 Mandatory Event Kinds Catalog

```
┌─────────┬──────────────────────────────────┬────────────────────────────────────────────────────────┐
│ Kind    │ Designation                      │ Primary Functional Purpose                             │
├─────────┼──────────────────────────────────┼────────────────────────────────────────────────────────┤
│ 0       │ Profile Metadata (NIP-05)        │ Display name, bio, Blossom avatar, NIP-05 identifier   │
│ 1       │ Short Text Note                  │ Public microblogging, broadcast updates                │
│ 1063    │ Blossom Media Metadata (NIP-94)  │ Content-addressed binary attachment declaration        │
│ 1111    │ Threaded Contextual Comment      │ Hierarchical comment tree scoped to any ecosystem entity│
│ 1112    │ Verifiable Governance Envelope   │ Poly V2 cryptographically signed governance vote       │
│ 10002   │ Relay List Metadata (NIP-65)     │ User's preferred read/write gossip relay topology      │
│ 30023   │ Long-Form Markdown (NIP-23)      │ Articles, documentation, and poll proposals            │
│ 9112    │ Trust Attestation                │ Web-of-Trust graph declarations (Crisis / Safe mesh)   │
└─────────┴──────────────────────────────────┴────────────────────────────────────────────────────────┘
```

---

### 4.3 Detailed Wire Specifications for Mandatory Kinds

#### 4.3.1 `kind:0` — Profile Metadata & NIP-05 Identifier

Sets or updates user profile information. The `content` string contains a serialized JSON object.

```json
{
  "kind": 0,
  "pubkey": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
  "content": "{\"name\":\"alice\",\"display_name\":\"Alice of Sovereign Hub\",\"about\":\"Building peer federation.\",\"picture\":\"https://blossom.hub.community.org/3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\",\"nip05\":\"alice@hub.community.org\",\"lud16\":\"alice@hub.community.org\"}",
  "tags": []
}
```

- **NIP-05 Resolution Rule:** Clients resolving `alice@hub.community.org` MUST make an HTTPS GET request to `https://hub.community.org/.well-known/nostr.json?name=alice`. The response must match:
  ```json
  {
    "names": {
      "alice": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    },
    "relays": {
      "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d": [
        "wss://relay.hub.community.org",
        "wss://nos.lol"
      ]
    }
  }
  ```

#### 4.3.2 `kind:1` — Short Notes & Broadcast Updates

Standard microblogging post.

```json
{
  "kind": 1,
  "content": "Autonomous peer hub deployed at https://hub.community.org #federation #omnisocial",
  "tags": [
    ["t", "federation"],
    ["t", "omnisocial"],
    ["client", "omni_social_v2"]
  ]
}
```

#### 4.3.3 `kind:1111` — Threaded Contextual Comments (NIP-22 Standard)

Structured comment anchored to any root entity in the ecosystem (a short note, long-form article, Blossom media blob, or Poly governance proposal).

```json
{
  "kind": 1111,
  "content": "I have audited the Merkle tree root on-chain and verified the signature integrity.",
  "tags": [
    ["E", "a1b2c3d4e5f6...", "wss://relay.hub.community.org", "root-event-id"],
    ["K", "30023"],
    ["P", "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", "wss://relay.hub.community.org"],
    ["e", "d4e5f6a1b2c3...", "wss://relay.hub.community.org", "reply-event-id"],
    ["k", "1111"],
    ["p", "f6a1b2c3d4e5...", "wss://relay.hub.community.org"]
  ]
}
```

- Tag conventions:
  - `["E", "<event_id>", "<relay_url>", "<pubkey>"]`: Root scope identifier (capital `E` represents root target).
  - `["K", "<kind_int>"]`: Kind of the root entity being commented on.
  - `["e", "<event_id>", "<relay_url>", "reply"]`: Direct parent comment ID when participating in nested threads.

#### 4.3.4 `kind:1063` — Blossom Media Metadata (NIP-94 Standard)

Binds cryptographic hashes to binary file attachments hosted across Blossom servers.

```json
{
  "kind": 1063,
  "content": "Architectural topology diagram for the autonomous mesh network.",
  "tags": [
    ["url", "https://blossom.hub.community.org/b0a4805e197c36a3e20e980327f2c649987814b19db2a1975e533c3732386a65.png"],
    ["m", "image/png"],
    ["x", "b0a4805e197c36a3e20e980327f2c649987814b19db2a1975e533c3732386a65"],
    ["ox", "b0a4805e197c36a3e20e980327f2c649987814b19db2a1975e533c3732386a65"],
    ["size", "524288"],
    ["dim", "1920x1080"],
    ["blurhash", "L6Pj0^jE.AyE_3t7t7R**0o#DgR4"],
    ["alt", "Cluster mesh diagram"],
    ["fallback", "http://127.0.0.1:9002/b0a4805e197c36a3e20e980327f2c649987814b19db2a1975e533c3732386a65"],
    ["fallback", "https://ipfs.io/ipfs/bafkreic7x6n2..."]
  ]
}
```

- **Sovereignty Badge Semantics:** If `url` or `fallback` includes the local loopback endpoint (`127.0.0.1:9002`), clients render an **Amber Sovereign Key Badge** indicating that the media is hosted on the user's local sovereign enclave.

#### 4.3.5 `kind:1112` — Verifiable Governance Vote Envelope (Poly Protocol)

Cryptographically signed vote cast in a decentralized governance referendum.

```json
{
  "kind": 1112,
  "pubkey": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
  "content": "{\"poll_id\":\"b4e7a2-charter-amendment-2026\",\"option_id\":\"approve_budget\",\"timestamp\":1725000000,\"merkle_leaf\":\"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\"}",
  "tags": [
    ["poll", "b4e7a2-charter-amendment-2026"],
    ["option", "approve_budget"],
    ["merkle_root", "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"],
    ["geo", "9q8yyk8"],
    ["org", "iyou_community"]
  ]
}
```

- **Headless Signing:** The local desktop bridge (`ws://127.0.0.1:9001`) automatically validates and signs `kind:1112` events under headless `OMNI_SIGN_REQUEST` workflows when authorized for governance casting.

#### 4.3.6 `kind:30023` — Long-Form Markdown & Proposal Definitions (NIP-23)

Parameterized replaceable event used for rich articles, technical specs, and poll definitions.

```json
{
  "kind": 30023,
  "pubkey": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
  "content": "# Peer Federation Protocol RFC\n\nThis proposal establishes...",
  "tags": [
    ["d", "omni-federation-rfc-001"],
    ["title", "Peer Federation Protocol RFC"],
    ["published_at", "1725000000"],
    ["summary", "Technical specification for autonomous peer hub federation."],
    ["t", "governance"],
    ["t", "specification"]
  ]
}
```

#### 4.3.7 `kind:10002` — Relay List Metadata (NIP-65 Standard)

Declares a user's relay topology for optimal gossip discovery.

```json
{
  "kind": 10002,
  "tags": [
    ["r", "ws://127.0.0.1:9003", "write"],
    ["r", "wss://relay.hub.community.org", "read"],
    ["r", "wss://relay.hub.community.org", "write"],
    ["r", "wss://nos.lol", "read"],
    ["r", "wss://nos.lol", "write"]
  ]
}
```

---

## 5. Storage Interoperability (Blossom BUD-01)

Media storage across the Omni-Social federation is implemented via the **Blossom protocol** ([BUD-01](https://github.com/hzrd149/blossom)).

```
                               ┌─────────────────────────────┐
                               │     Blob Upload Request     │
                               │   (SHA-256 Content-Address) │
                               └──────────────┬──────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
        Local Storage Node (:9002)                         Hub Blossom Cluster
     Hot Storage / Local Sovereignty                   High-Availability Mirror
                     │                                                 │
                     └────────────────────────┬────────────────────────┘
                                              │
                                  Replication & Failover
                                              │
                                              ▼
                                 Global Cloud CDN / IPFS
                              Cold Archive / Censorship Shield
```

### 5.1 Content-Addressed Addressing Scheme

All binary files (images, audio, video, documents) are identified and retrieved strictly via the hexadecimal SHA-256 hash of their raw binary content.

- **URL Pattern:** `https://{blossom_host}/{sha256_hex}` or `https://{blossom_host}/{sha256_hex}.{ext}`
- **Example:** `https://blossom.hub.community.org/b0a4805e197c36a3e20e980327f2c649987814b19db2a1975e533c3732386a65.png`

### 5.2 Blossom HTTP Wire Interface

Every compliant Blossom node **MUST** support the following REST endpoints:

| Method | Endpoint | Authorization | Description |
|:---|:---|:---|:---|
| `GET` | `/{sha256}` | None (Public) | Retrieves the raw binary blob with proper `Content-Type`. |
| `HEAD` | `/{sha256}` | None (Public) | Returns HTTP headers (`Content-Length`, `Content-Type`) without payload. |
| `PUT` | `/upload` | Nostr Event Header (BUD-02) | Uploads a new binary blob. Computes SHA-256 and persists if authorized. |
| `DELETE` | `/{sha256}` | Nostr Event Header (BUD-02) | Deletes a previously uploaded blob (author-only). |
| `OPTIONS` | `/{sha256}` | None | Private Network Access (PNA) and CORS pre-flight. |

#### Required HTTP Response Headers:
Compliant nodes MUST return the following headers on all `GET`, `HEAD`, and `OPTIONS` responses:
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, HEAD, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type, *
Access-Control-Allow-Private-Network: true
Cache-Control: public, max-age=31536000, immutable
```

### 5.3 3-Tier Multi-Node Failover Resolution

When a client or satellite app requests an asset identified by SHA-256 hash $H$, resolution proceeds through a strict three-tier cascade:

```
[Request: Hash H]
       │
       ▼
1. Local Enclave Blossom (http://127.0.0.1:9002/H) ───[Found]───▶ Render Asset (Instant)
       │ [Fail / 404 / Offline]
       ▼
2. Peer Blossom Hubs (https://blossom.hub.community.org/H) ─[Found]─▶ Render & Cache Local
       │ [Fail / 404 / Offline]
       ▼
3. Global Gateway / IPFS (https://ipfs.io/ipfs/CID) ──[Found]──▶ Render & Mirror
       │ [Fail]
       ▼
[Surface Error: ERR_ASSET_UNAVAILABLE]
```

1. **Tier 1 (Local Sovereignty):** Client queries the local enclave at `http://127.0.0.1:9002/{hash}`. If present, media renders instantly with zero internet latency.
2. **Tier 2 (Peer Blossom Mesh):** If the local node does not hold the blob, the client iterates through Blossom servers listed in the `fallback` tags of the corresponding `kind:1063` event.
3. **Tier 3 (Global CDN & IPFS):** If all peer Blossom nodes fail, the client requests the asset from IPFS gateways or configured backup CDNs.

### 5.4 Client Integrity Verification Invariant

When receiving a binary blob from any remote source (Tier 2 or Tier 3), the client **MUST** recompute:
$$\text{computed\_hash} = \text{SHA-256}(\text{received\_binary\_bytes})$$
If $\text{computed\_hash} \neq \text{requested\_hash}$, the client MUST discard the data immediately and raise `ERR_CONTENT_HASH_MISMATCH`. No untrusted or corrupted blob may enter the application state.

---

## 6. Autonomous Hub Deployment & Domain Federation

Any organization, collective, or individual can deploy an independent Omni-Social Hub (e.g., `hub.community.org`).

### 6.1 Hub Architecture Stack

An autonomous Hub consists of four containerized core services orchestrated via K3s, Docker Compose, or Podman:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Autonomous Hub: hub.community.org                    │
│                                                                        │
│  ┌────────────────────┐   ┌────────────────────┐   ┌────────────────┐  │
│  │   Traefik Reverse  │   │   Nostr Relay      │   │ Blossom Blob   │  │
│  │   Proxy + TLS      │──▶│   (Rust / C++)     │   │ Server (:9002) │  │
│  │   (Port 80/443)    │   │   (Port 9003)      │   │                │  │
│  └─────────┬──────────┘   └────────────────────┘   └────────────────┘  │
│            │                                                           │
│            ▼                                                           │
│  ┌────────────────────┐   ┌────────────────────┐   ┌────────────────┐  │
│  │   Identity Provider│   │   PostgreSQL       │   │ Redis Cache    │  │
│  │   (iyou_idp OIDC)  │──▶│   (Indexing Cache) │   │ (Challenges)   │  │
│  └────────────────────┘   └────────────────────┘   └────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Standard Well-Known Discovery Endpoints

Every federated Hub MUST expose three standard well-known endpoints on HTTPS:

1. **NIP-05 Identity Resolution:**
   `GET https://{hub_domain}/.well-known/nostr.json?name={username}`
   Returns JSON mapping username to Nostr public key hex and preferred relays.
2. **OpenID Connect Discovery (RFC 8414):**
   `GET https://{hub_domain}/.well-known/openid-configuration`
   Returns OIDC endpoints (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`).
3. **Blossom Server Discovery (BUD-03):**
   `GET https://{hub_domain}/.well-known/blossom`
   Returns server capabilities, max upload sizes, and supported media codecs.

### 6.3 Domain Isolation & Sandboxed Storage

To ensure total isolation between peer satellites running on subdomains:
- Every satellite application MUST set independent, prefixed cookie names:
  ```python
  SESSION_COOKIE_NAME = "{app_slug}_sessionid"
  CSRF_COOKIE_NAME = "{app_slug}_csrftoken"
  ```
- `SESSION_COOKIE_DOMAIN` MUST NOT be set to the wildcard parent domain (`.community.org`), preventing cross-satellite session leakage.

---

## 7. Conformance Matrix & Verification Checklist

To achieve certified compliance with `OMNI-FED-SPEC-V1`, an implementation MUST pass the following verification tests:

| Check | Requirement | Verification Method | Pass Criteria |
|:---|:---|:---|:---|
| **CONF-01** | DID Derivation Determinism | Derive keypair from test vector seed | Matches `did:key:z6Mk...` exact string |
| **CONF-02** | Air-Gap Level 0 Guard | Request bridge sign with `index=0` | Bridge returns `ERR_AIR_GAP_VIOLATION` |
| **CONF-03** | Secretless PKCE S256 | Execute token exchange without `client_secret` | Token issued; verifier validated in constant time |
| **CONF-04** | Sub Claim DID Pinned | Parse RS256 `id_token` JWT | `claims["sub"] == user_did` |
| **CONF-05** | Double-Broadcast Relay | Publish `kind:1` note | Event arrives at local, hub, and global relays |
| **CONF-06** | Blossom Hash Verification | Download media attachment | `SHA-256(bytes) == tag_x` |
| **CONF-07** | Ephemeral DB Invariant | Drop Postgres cache and re-index | Social feed re-populates without loss |
| **CONF-08** | NIP-05 Discovery | Query `/.well-known/nostr.json` | Returns valid JSON mapping with pubkey |

---

## 8. Document History

- **2026-08-30 (v1.0.0):** Canonical baseline specification authored. Standardized DID derivation, secretless PKCE, Nostr wire registry, Blossom replication, and autonomous hub federation.
