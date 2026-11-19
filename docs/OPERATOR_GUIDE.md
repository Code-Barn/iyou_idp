# "Garden of IdPs" Operator Guide

This document is the authoritative operations, architecture, and production hardening manual for running a self-hosted `iyou_idp` node within the federated **"Garden of IdPs"** ecosystem.

Whether operating the canonical flagship root node (`iyou.me`) or deploying an autonomous community peer node (e.g., `hub.community.org`), this guide details configuration schemas, persistence requirements, cryptographic isolation guarantees, and compliance workflows.

---

## 1. Federation Model ("Garden of IdPs")

The iyou_ ecosystem rejects monolithic, centralized identity silos while avoiding the fragility of uncoordinated, unauthenticated peer networks. The resulting architecture is a federated **"Garden of IdPs"**: an open topology where independent operators host sovereign authentication hubs that seamlessly interoperate without central gatekeeping.

```
                      ┌──────────────────────────────┐
                      │      iyou.me (Flagship)      │
                      │   IDP_NODE_ROLE = flagship   │
                      │ did:web:iyou.me:user:{uuid}  │
                      └──────────────┬───────────────┘
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│  hub.community.org (Peer A)  │            │    mesh.lab.io (Peer B)      │
│ IDP_NODE_ROLE=community_peer │            │ IDP_NODE_ROLE=community_peer │
│ did:web:hub.community.org:…  │            │   did:web:mesh.lab.io:…      │
└──────────────┬───────────────┘            └───────────────┬──────────────┘
               │                                            │
               └─────────────────────┬──────────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────┐
                      │    Cross-Node Sovereign      │
                      │    Tier 2/3: did:key:...     │
                      │    (Universal Interop)       │
                      └──────────────────────────────┘
```

### 1.1 Namespace Isolation (`did:web:<domain>:user:{uuid}`)

Every `iyou_idp` instance establishes clear cryptographic and administrative boundaries for managed accounts:

1. **Domain Authority Boundary:**
   For Tier 1 (managed convenience) users, identities are anchored under the node's authoritative domain using W3C `did:web`:
   - Flagship root node: `did:web:iyou.me:user:{uuid}`
   - Community peer node: `did:web:hub.community.org:user:{uuid}`
2. **Impossibility of Cross-Node Collision:**
   User identifiers are generated with cryptographically unique UUIDs scoped under the operator's DNS domain (`IDP_WEB_DID_NAMESPACE`). A peer node cannot spoof, overwrite, or mutate identities belonging to another domain.
3. **Universal Interoperability via `did:key`:**
   Unlike Tier 1 managed accounts, Tier 2 (mobile QR) and Tier 3 (desktop enclave) identities rely on universal W3C `did:key` identifiers (Ed25519 multicodec `0xed01`). A sovereign user carries the exact same `did:key:` identity across every peer node in the federation without database synchronizations, identity migrations, or central permissioning.

### 1.2 WebAuthn RP IDs & Passkey Origin Sandboxing

Passkeys provide phishing-resistant authentication, but cross-domain security depends strictly on browser-enforced origin isolation:

- **RP ID Scoping:** In `iyou_idp`, the WebAuthn Relying Party ID (`RP_ID`) is derived from the host component of `IDP_BASE_URL`.
- **Phishing Prevention:** Passkey credentials registered at `https://iyou.me` (RP ID `iyou.me`) cannot be exercised, solicited, or replayed at `https://hub.community.org` (RP ID `hub.community.org`). The browser's WebAuthn client strictly enforces this boundary at the hardware authenticator level.
- **Operator Independence:** Each peer node operator maintains their own distinct credential ledger in `PasskeyCredential` without risk of credential theft across the federation.

### 1.3 Web-of-Trust Distance (`wot_distance`) & Sybil Defense

Without a centralized certificate authority or closed gatekeeper, distributed networks risk Sybil attacks where malicious actors flood the network with fake nodes or puppet identities.

`iyou_idp` prevents Sybil flooding via **Web-of-Trust (WoT) distance** and cryptographic capability tokens:

1. **Pre-Launch Airlock & RFC-002 Capability Tokens:**
   New identities entering the federation through gated environments must present an invite capability token minted by an existing trusted identity (`ADMIN_DID` or allowlisted peer).
2. **Quota Clamping by Issuer Trust:**
   - Flagship administrators and vetted peer operators are allocated wide mint budgets (`RFC002_COMMUNITY_MAX_USES = 100`).
   - Standard community members are clamped to tightly bounded budgets (`RFC002_MAX_USES_PER_TOKEN = 4`).
3. **Ephemeral Graph Topology (Anti-Surveillance Invariant):**
   To prevent self-hosted nodes from becoming subpoena-vulnerable surveillance honeypots, invite edges are **never stored relationally** in Postgres. Sponsoring issuer DIDs are held ephemerally in browser sessions (`session["sponsor_did"]`) and accessible once via `/auth/airlock/sponsor/` before being destroyed.
4. **Decentralized Evaluation:**
   Peer nodes compute trust distances based on direct cryptographic signatures and attested credentials, rejecting un-anchored identities without needing a central coordinator.

---

## 2. Environment Schema & Production Hardening

All node configuration is controlled via environment variables. In accordance with 12-factor principles and `django-environ`, variables use typed schemas with secure defaults.

### 2.1 Complete `IDP_*` Environment Schema

| Variable | Type | Default | Production Requirement | Purpose |
|:---|:---:|:---:|:---:|:---|
| `IDP_SECRET_KEY` | `str` | `django-insecure-...` | **MANDATORY** | Cryptographic signing key for Django sessions and CSRF tokens. Must not start with `django-insecure-` or `insecure-`. |
| `IDP_BASE_URL` | `str` | `http://...local:8000` | **MANDATORY** | Public HTTPS root URL of the node (e.g. `https://hub.community.org`). Drives OIDC discovery, WebAuthn RP ID, and redirect matching. |
| `IDP_NODE_ROLE` | `str` | `community_peer` | Optional | Role of the node: `flagship` or `community_peer`. Controls provenance footer pill rendering. |
| `IDP_OPERATOR_NAME` | `str` | `""` | Optional | Human-readable name of the entity operating the node (e.g., "Pacific Mesh Collective"). |
| `IDP_OPERATOR_CONTACT` | `str` | `""` | Optional | Public security or support contact (e.g. `mailto:ops@hub.community.org`). |
| `ADMIN_DID` | `str` | `did:key:z6Mku...` | **MANDATORY** | Master sovereign administrator DID (`did:key:...`). Auto-elevated to staff and superuser upon login. |
| `SYSTEM_GATE_ENABLED` | `bool` | `True` | Recommended `True` | Pre-launch Airlock gate. Blocks unverified public signups unless they possess a valid invite token or allowlist entry. |
| `IDP_ALLOW_EMERGENCY_BYPASS` | `bool` | `False` | **MUST BE `False`** | Critical security switch (`SEC-001`). When `False`, unsigned challenge nonce logins are completely blocked. |
| `DATABASE_URL` | `str` | `sqlite:///db.sqlite3` | **PostgreSQL** | Database connection string (e.g. `postgres://user:pass@db:5432/iyou_idp`). |
| `REDIS_URL` | `str` | `redis://...:6379/1` | **MANDATORY** | Connection string for Redis cache and token state. |
| `IDP_VAULT_ADDR` | `str` | `http://127.0.0.1:8200` | Optional | Address of HashiCorp Vault server for Tier 1 managed key custody. |
| `IDP_VAULT_TOKEN` | `str` | `""` | Optional | Authentication token for HashiCorp Vault. |
| `IDP_VAULT_KV_MOUNT` | `str` | `secret` | Optional | Mount path for Vault KV v2 engine storing identity keys. |
| `IDP_ALLOWED_HOSTS` | `list` | `[...]` | **MANDATORY** | Comma-separated list of fully qualified hostnames the node will accept requests for. |
| `IDP_CSRF_TRUSTED_ORIGINS`| `list` | `[...]` | **MANDATORY** | Comma-separated list of origins permitted to submit state-changing POST forms. |
| `IDP_CORS_ALLOWED_ORIGINS`| `list` | `[]` | **MANDATORY** | Comma-separated list of satellite application origins permitted to make cross-origin requests. |
| `IDP_DEBUG` | `bool` | `False` | **MUST BE `False`** | Disables Django debug mode, turns on production error handling, and activates deploy checks. |

### 2.2 Production Deploy Checks

The node includes automated deploy safety checks registered with Django's system check framework (`auth_bridge/checks.py`).

Before launching, execute:
```bash
uv run python manage.py check --deploy
```

The check verifies:
- `settings.DEBUG` is `False`.
- `settings.SECRET_KEY` does not start with `django-insecure-` or `insecure-`.
- `settings.IDP_BASE_URL` begins with `https://`.
- `settings.ADMIN_DID` is explicitly defined.
- `IDP_ALLOW_EMERGENCY_BYPASS` is `False`.

If any check fails, the process exits with an error code and startup is halted.

---

## 3. Stateful Infrastructure & Persistence

While the node emphasizes sovereign cryptographic proofs over persistent centralized data, certain stateful subsystems require high-availability persistence.

### 3.1 PostgreSQL Backup & Disaster Recovery

PostgreSQL stores core administrative configurations, public OIDC client registrations, user consent records, and immutable audit logs.

#### Backup Strategy
1. **Periodic Full Dumps:**
   Run automated daily logical snapshots using `pg_dump`:
   ```bash
   pg_dump -Fc -Z 6 -f /var/backups/idp/idp_$(date +%Y%m%d_%H%M%S).dump "$DATABASE_URL"
   ```
2. **Continuous WAL Archiving:**
   For high-traffic nodes, enable Write-Ahead Logging (WAL) archiving to an offsite S3-compatible bucket (e.g., using `pgBackRest` or `wal-g`) to achieve point-in-time recovery (PITR).
3. **Database Migrations:**
   Always run migrations as part of your deployment pipeline before starting web workers:
   ```bash
   uv run python manage.py migrate --noinput
   ```

### 3.2 Redis Persistence (AOF & RDB Invariants)

`iyou_idp` relies on Redis for fast, atomic operations:
- Active login challenges (`challenge:{id}`, 300s TTL).
- RFC-002 capability token quota tracking (`airlock:nonce:{nonce}:uses`).
- Single-use challenge consumption (`challenge_used:{challenge}`).
- Cross-account merge OTPs and email verification tokens.

> [!CRITICAL]
> If Redis restarts with ephemeral, unpersisted storage, consumed invite tokens and used authentication challenges could theoretically be replayed, and active quotas reset.

#### Required Redis Configuration
In your `redis.conf`:
```text
# Enable Append-Only File (AOF) persistence
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec

# Retain periodic RDB snapshots as secondary fallback
save 900 1
save 300 10
save 60 10000

# Prevent silent eviction of authentication nonces
maxmemory-policy volatile-ttl
```

### 3.3 HashiCorp Vault Setup & Unseal Procedures

When operating Tier 1 managed convenience accounts with server-custodied keys, HashiCorp Vault is required to secure raw Ed25519 identity seeds.

1. **Mount Path:**
   Enable KV v2 at the path configured in `IDP_VAULT_KV_MOUNT` (default: `secret`):
   ```bash
   vault secrets enable -path=secret kv-v2
   ```
2. **Access Policy:**
   Create an ACL policy restricting `iyou_idp` strictly to its designated identity namespace:
   ```hcl
   path "secret/data/identity/*" {
     capabilities = ["create", "read", "update"]
   }
   path "secret/metadata/identity/*" {
     capabilities = ["read", "delete"]
   }
   ```
3. **Unseal Operation:**
   Ensure your node operational runbook covers Vault unsealing following any host reboot:
   ```bash
   vault operator unseal <unseal_key_1>
   vault operator unseal <unseal_key_2>
   vault operator unseal <unseal_key_3>
   ```

### 3.4 RSA Token Signing Key Rotation (RS256 & JWKS)

OIDC ID tokens are signed with an RS256 private key. Relying party satellites cache the corresponding public keys from the node's JWKS endpoint (`/openid/jwks/`).

#### Key Generation
To mint a new RSA signing key:
```bash
uv run python manage.py creatersakey
```

#### Zero-Downtime Rotation Runbook
1. Mint the new RSA key using `creatersakey`. Both the old and new keys will be published on `/openid/jwks/`.
2. Allow a propagation window (minimum 1 hour) so all satellite caches refresh their JWKS sets.
3. Mark the new key as active in the database or via Django Admin (`/admin/oidc_provider/rsakey/`).
4. Once all active JWT tokens issued under the old key have elapsed their expiration window (e.g. 24 hours), deactivate and archive the legacy RSA key.

---

## 4. Satellite Registration & Federation

Satellites are relying party applications (such as `iyou_wun`, `omni_social`, or community-built apps) that delegate authentication to your node.

### 4.1 Secretless PKCE Client Provisioning

`iyou_idp` enforces RFC 7636 Proof Key for Public Client Exchange (PKCE) with S256 code challenges across all satellites. Shared static client secrets are forbidden in production.

#### Default Flagship Satellites
To populate standard ecosystem satellites on a flagship node:
```bash
uv run python manage.py seed_clients
```

#### Registering Custom Community Satellites
For custom satellites on peer nodes, register client entries via Django Admin or custom management scripts with the following parameters:
- **Client Type:** `public`
- **Client Secret:** `""` (Empty string)
- **Response Types:** `code`
- **JWT Algorithm:** `RS256`
- **Scope:** `openid profile email`
- **Require Consent:** `False` (For trusted first-party mesh satellites)
- **Reuse Consent:** `True`
- **Redirect URIs:** Exact HTTPS callback URIs (e.g. `https://forum.community.org/oidc/callback/`)
- **Post-Logout URIs:** Clean landing endpoints (e.g. `https://forum.community.org/`)

### 4.2 Multi-Issuer Configuration on Satellites (`TRUSTED_IDP_ISSUERS`)

Satellites participating in the federation can accept identities from multiple peer nodes by configuring their OIDC middleware to recognize trusted issuers:

```python
# Satellite configuration example (settings.py)
TRUSTED_IDP_ISSUERS = [
    "https://iyou.me",
    "https://hub.community.org",
    "https://mesh.lab.io",
]
```

The satellite dynamically routes authentication requests to the user's selected home IdP, validates the returned `iss` claim against `TRUSTED_IDP_ISSUERS`, and verifies the token against that issuer's public JWKS.

### 4.3 Legal, Regulatory & GDPR Conduit Responsibilities

As an independent node operator, you are a data controller or data processor under applicable data protection frameworks (such as GDPR or CCPA). `iyou_idp` provides automated compliance primitives:

#### 1. Affirmative Legal Consent Gate
- All newly minted accounts default to `show_legal_disclaimer = True`.
- `SovereignAuthorizeView` refuses to issue OIDC authorization codes until the user explicitly submits `consent_accepted=true` via `/auth/legal-disclaimer/acknowledge/`.
- The consent checkbox is unchecked by default, adhering to strict GDPR standards.
- Operators should customize the disclaimer text in `_legal_disclaimer_modal.html` to reflect their legal entity and jurisdiction.

#### 2. Right to Erasure / Account Purge (GDPR Art. 17)
- Authenticated users may unilaterally purge their identities via `POST /auth/account/purge/`.
- The purge cascadingly deletes the user record, linked emails (`LinkedEmail`), OAuth credentials (`FederatedIdentity`), passkeys (`PasskeyCredential`), and active sessions.
- In accordance with privacy principles, the audit log records the cryptographic receipt of erasure while deleting all personal data.

#### 3. Transparency & Operator Identity
- Configure `IDP_OPERATOR_NAME` and `IDP_OPERATOR_CONTACT` so community users know who operates the infrastructure and can direct privacy inquiries accordingly.

---

## 5. Operations Checklist

```
[ ] IDP_DEBUG set to False
[ ] IDP_SECRET_KEY set to strong random string (>= 50 chars, no insecure prefix)
[ ] IDP_BASE_URL begins with https://
[ ] ADMIN_DID configured with operator's sovereign did:key:...
[ ] IDP_ALLOW_EMERGENCY_BYPASS confirmed False
[ ] PostgreSQL configured and reachable via DATABASE_URL
[ ] Redis persistence confirmed (appendonly yes) via REDIS_URL
[ ] Reverse proxy forwards Host, X-Forwarded-Proto (https), and X-Forwarded-For
[ ] RSA key generated via python manage.py creatersakey
[ ] System deploy check passes: uv run python manage.py check --deploy
[ ] Public PKCE satellite clients registered
```
