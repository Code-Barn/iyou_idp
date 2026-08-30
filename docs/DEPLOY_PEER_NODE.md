# Autonomous Peer Node Deployment

Self-host a fully independent `iyou_idp` instance on your own domain (e.g.
`hub.community.org`), onboard users under your own domain authority, and stay
100% interoperable with sovereign `did:key` users from every other instance —
the canonical one at `iyou.me` included.

A peer node is **not** a fork of iyou_idp and is **not** dependent on any iyou
infrastructure at runtime. It runs the same image, the same OIDC/PKCE
protocols, and the same three-tier auth spectrum. Only the *domain* — and
therefore the *managed DID namespace* — changes.

---

## 1. The 3-Tier Auth Model in a Federated Context

Every iyou_idp node (flagship or peer) authenticates identities across the
same three tiers. The tiers differ in *who custodies the key material*, which
is exactly what makes federation safe: a peer never needs to import or migrate
another node's users to be interoperable.

### Tier 1 — Managed Convenience (domain-scoped `did:web`)

The node creates and custodies keys for convenience users. Each managed user
receives a **scoped** `did:web` identifier under **your** authority:

| Deployment | `IDP_BASE_URL` | `IDP_WEB_DID_NAMESPACE` | Minted managed DID |
|---|---|---|---|
| Flagship `iyou.me` | `https://iyou.me` | `did:web:iyou.me` (default) | `did:web:iyou.me:user:<uuid>` |
| **Your peer node** | `https://hub.community.org` | `did:web:hub.community.org` | `did:web:hub.community.org:user:<uuid>` |

Minting happens at user creation and just-in-time (JIT) on login:

- `auth_bridge/models.py:SovereignUserManager.create_user`
- `auth_bridge/views.py:managed_login`

Both call `apps/core/dids.managed_user_did()`, which reads
`IDP_WEB_DID_NAMESPACE` (falling back to deriving a `did:web` authority from
the `IDP_BASE_URL` hostname). **Set it to your own authority** — never leave
your peers minting under the `iyou.me` namespace.

Tier-1 login surfaces per node:

- Email/password at `POST /auth/managed-login/`
- Passwordless passkeys (WebAuthn / FIDO2) at `/auth/passkeys/…` — the RP-ID
  is derived from the `IDP_BASE_URL` hostname, so it is automatically correct
  per domain
- Optional managed OAuth (Google / GitHub / Apple) when provider credentials
  are configured

### Tier 2 — QR-Code OOB (Community Self-Signing)

Any universal `did:key` can sign in at **any** peer node with **zero account
migration**:

1. `POST /auth/challenge/` → signed challenge (Redis, 300s TTL, single-use)
2. Mobile `iyou_mobile` wallet scans the QR (`iyouauth://sign?ch=…&url=…`),
   signs with the user's existing Ed25519 key
3. `POST /auth/mobile-verify/` submits the W3C Verifiable Presentation
4. The browser polls `GET /auth/challenge-status/<id>/` until `solved`

The node looks up (or JIT-creates) a local `User` keyed by the **universal
`did:key`** in its `custodial_did` field. No emails, no passwords, no import;
the same key that works at `iyou.me` works at `hub.community.org`.

### Tier 3 — Desktop WebSocket (Full Sovereignty)

The `iyou_home` desktop enclave signs directly over its loopback bridge:

1. `POST /auth/challenge/` in the browser
2. Browser connects to `IDP_HOME_WS_URL` and asks the enclave to sign
3. `POST /auth/verify/` submits the VP (Python Ed25519 → Rust `verify_vp` →
   emergency bypass fallback chain)

The `did:key` holder controls *all* key material; the IdP only verifies
signatures. Graduated users are fully self-custodied and can authenticate at
any peer node with their own keys. The `ADMIN_DID` posture hook
(`evaluate_sovereign_admin_posture`) auto-elevates the configured operator DID
to staff/superuser on this node only.

### Interoperability guarantees

- `did:key` is **universal** — Tier 2/3 authentication is cross-instance by
  construction. Keys are verified cryptographically, never "imported".
- Accounts are keyed by `custodial_did`, **not** email
  (`User.get_or_create(custodial_did=holder_did)`), so nothing is migrated or
  vendored when a user switches nodes.
- OIDC `sub` / `preferred_username` claims carry the user's actual DID
  (`auth_bridge/oidc.py`), so relying parties see the identity, not the IdP.
- Tier 1 offers no cross-node portability by design — managed DIDs are scoped
  to the node that custodies them. That is what keeps each community's
  authority independent.

---

## 2. Prerequisites

- Docker with Compose v2 (`docker compose version`)
- A domain with a TLS-capable reverse proxy (Traefik, Caddy, nginx…)
- Two generated secrets: `IDP_SECRET_KEY` and `POSTGRES_PASSWORD`

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
# repeat twice — once for IDP_SECRET_KEY, once for POSTGRES_PASSWORD
```

DNS records to point at the node (TTL 300):

| Record | Value |
|---|---|
| `hub.community.org` | node IPv4 / IPv6 |
| `app.hub.community.org` | node IPv4 / IPv6 (your satellite, example) |
| `home.hub.community.org` | node IPv4/IPv6 (Tier-3 bridge, optional) |

---

## 3. Quick Start

```bash
git clone https://github.com/<you>/iyou_idp.git iyou_idp
cd iyou_idp

cp .env.peer.example .env.peer
# EDIT .env.peer:
#   IDP_BASE_URL=https://hub.community.org
#   IDP_WEB_DID_NAMESPACE=did:web:hub.community.org
#   IDP_ALLOWED_HOSTS=hub.community.org
#   IDP_CSRF_TRUSTED_ORIGINS=https://hub.community.org
#   IDP_CORS_ALLOWED_ORIGINS=https://hub.community.org,https://app.hub.community.org
#   IDP_SECRET_KEY=…   POSTGRES_PASSWORD=…

docker compose -f docker-compose.peer.yml up -d --build
docker compose -f docker-compose.peer.yml ps   # wait for idp health = healthy
```

On first boot the entrypoint runs `manage.py migrate` before Gunicorn starts
on `:8000`.

---

## 4. First-Boot Provisioning

### 4.1 Generate the OIDC signing RSA key (required)

OIDC ID tokens are signed RS256; with no key in the database the provider
rejects all token operations.

```bash
docker compose -f docker-compose.peer.yml run --rm --entrypoint python idp \
    manage.py creatersakey
```

### 4.2 Create the sovereign administrator

```bash
docker compose -f docker-compose.peer.yml run --rm --entrypoint python idp \
    manage.py createsuperuser_did
```

or authenticate with the `ADMIN_DID` `did:key` — `evaluate_sovereign_admin_posture`
auto-promotes the matching user to staff + superuser on first sign-in.

### 4.3 Register your satellite clients (secretless PKCE)

`iyou_idp` never stores or transmits cleartext client secrets. Satellite
clients are **public** OIDC clients whose every code exchange is gated by PKCE
`S256` at `/openid/token/` (`PkceTokenView`).

> `manage.py seed_clients` seeds the 18 flagship `*.iyou.me` satellites — do
> **not** run it on a peer. Register your own clients instead.

Per satellite, create an OIDC client in Django admin (`/admin/`, oidc_provider
Client), or via the API:

| Field | Value |
|---|---|
| Client ID | `hub-app-satellite-client` |
| Client type | `public` |
| Client secret | *(empty — secretless)* |
| Redirect URIs | `https://app.hub.community.org/oidc/callback/` |
| Post-logout redirect URIs | `https://app.hub.community.org/` |
| JWT Algorithm | `RS256` |
| Response Types | `code` |
| Scope | `openid profile email` |
| Require Consent | ☐ (unchecked) |
| Reuse Consent | ☑ (checked) |

Your satellites then start an Authorization Code + PKCE flow:

```
https://hub.community.org/openid/authorize/?client_id=hub-app-satellite-client
    &redirect_uri=https://app.hub.community.org/oidc/callback/
    &response_type=code
    &scope=openid%20profile%20email
    &state=…&nonce=…
    &code_challenge=<S256(code_verifier)>
    &code_challenge_method=S256
```

### 4.4 Health and hygiene checklist

```bash
docker compose -f docker-compose.peer.yml logs -f idp
curl -s https://hub.community.org/auth/challenge/          # 200 + {"challenge": …}
curl -s https://hub.community.org/api/v1/instance/        # instance descriptor
curl -s https://hub.community.org/openid/.well-known/openid-configuration/ | python3 -m json.tool
```

Grid:

- [ ] `IDP_DEBUG=False`
- [ ] `IDP_SECRET_KEY` set (never the dev fallback)
- [ ] `IDP_WEB_DID_NAMESPACE` = your authority
- [ ] TLS terminates at the reverse proxy with `X-Forwarded-Proto: https`
- [ ] `IDP_ALLOWED_HOSTS` includes the public host
- [ ] `IDP_CORS_ALLOWED_ORIGINS` lists every satellite origin
- [ ] `ALLOW_EMERGENCY_BYPASS=False`
- [ ] RSA key generated (`creatersakey`)
- [ ] At least one public PKCE satellite client registered

---

## 5. Configuration Reference

`.env.peer` (loaded by `docker-compose.peer.yml`) — every variable below.

| Variable | Type | Default | Purpose |
|---|---|---|---|
| `IDP_BASE_URL` | str | `http://iyou-idp.identity.svc.cluster.local:8000` | **Domain routing.** Public origin; drives all OIDC endpoints, challenge URLs, passkey RP-ID. |
| `IDP_WEB_DID_NAMESPACE` | str | `did:web:iyou.me` | Tier-1 managed DID authority, e.g. `did:web:hub.community.org`. |
| `IDP_ALLOWED_HOSTS` | list | `['iyou-idp.identity.svc.cluster.local', 'iyou-idp', 'localhost']` | Hosts the node answers to. (*The brief's `OIDC_ALLOWED_HOSTS` maps here.*) |
| `IDP_CSRF_TRUSTED_ORIGINS` | list | cluster origin | Origins allowed to POST CSRF-protected forms. |
| `IDP_CORS_ALLOWED_ORIGINS` | list | `[]` | Origins allowed for CORS — one per satellite. (*The brief's `CORS_ALLOWED_ORIGINS` maps here.*) |
| `IDP_DEBUG` | bool | `False` | Never `True` on a peer. |
| `IDP_SECRET_KEY` | str | dev fallback | Django `SECRET_KEY` — **required**. |
| `IDP_WUN_URL` | str | `http://127.0.0.1:8001` | Default post-login redirect (your primary satellite). |
| `IDP_HOME_URL` / `IDP_HOME_WS_URL` | str | cluster / `wss://home.iyou.me:9001/` | Tier-3 desktop bridge endpoint. Point at your own gateway. |
| `DATABASE_URL` | db URL | `sqlite:///db.sqlite3` | **Compose fills this** from `POSTGRES_*`. |
| `REDIS_URL` | redis URL | cluster headless | **Compose fills this** (`redis://redis:6379/1`). |
| `ADMIN_DID` | did:key | built-in dev key | Sovereign operator DID; auto-elevates to staff+superuser. |
| `ALLOW_EMERGENCY_BYPASS` | bool | `False` | Keep `False` (challenge-nonce-only auth is high risk). |
| `IDP_VAULT_ADDR` / `IDP_VAULT_TOKEN` | str | `http://127.0.0.1:8200` / `""` | HashiCorp Vault for Tier-1 key custody + identity graduation. Optional; without it managed-key export (`/api/v1/identity/…`) is unavailable. |
| `OAUTH_GOOGLE_*` / `OAUTH_GITHUB_*` / `OAUTH_APPLE_*` | str | `""` | Tier-1 social logins; empty = provider disabled. |

When `IDP_DEBUG=False` the node automatically sets
`SECURE_PROXY_SSL_HEADER` (trust `X-Forwarded-Proto`), and marks session/CSRF
cookies `Secure` (`idp_sessionid` / `idp_csrftoken`, `SameSite=Lax`).

---

## 6. Reverse Proxy & TLS

The container serves Gunicorn on `:8000`. Terminate TLS at a reverse proxy and
forward the proto header (required for secure cookies):

```yaml
# Caddy (simplest)
hub.community.org {
    reverse_proxy localhost:8000
    header_up X-Forwarded-Proto {scheme}
}
app.hub.community.org {
    reverse_proxy localhost:8001   # your satellite app
}
```

or Traefik `ForwardedHeaders` / nginx `proxy_set_header X-Forwarded-Proto $scheme;`.

Keep the `IDP_HTTP_PORT` mapping (`${IDP_HTTP_PORT:-8000}:8000`) as a loopback
port the proxy talks to; do not publish `9001` on the peer unless you run your
own `iyou_home` bridge.

---

## 7. Operations

### Backups

```bash
docker compose -f docker-compose.peer.yml exec db \
    pg_dump -U ${POSTGRES_USER:-iyou_idp} ${POSTGRES_DB:-iyou_idp} > iyou_idp_$(date +%F).sql
```

Back up the `postgres_data` volume **and** the OIDC RSA key: without the key,
cookies expire but new ID tokens can be re-issued after `creatersakey`; without
the DB, managed (Tier-1) users are gone.

### Upgrades

```bash
git pull
docker compose -f docker-compose.peer.yml up -d --build   # migrate runs in entrypoint
```

### Restart / teardown

```bash
docker compose -f docker-compose.peer.yml restart idp
docker compose -f docker-compose.peer.yml down            # keeps volumes
docker compose -f docker-compose.peer.yml down -v         # wipes DB + Redis
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `DisallowedHost` at `/api/v1/instance/` | `IDP_ALLOWED_HOSTS` lacks the public host | Set it to the public domain, restart |
| `no keys in database` during token ops | `creatersakey` never ran | `run --rm --entrypoint python idp manage.py creatersakey` |
| Foundation error: `AllowedHosts`/CSRF 403 behind proxy | Missing `X-Forwarded-Proto` | Set proto header at the proxy (TLS offload) |
| Challenge never resolves (`stored: false`) | Redis unreachable | `docker compose ps` → redis healthy; `REDIS_URL` correct |
| Tokens rejected: `invalid_grant` | PKCE verifier mismatch | Satellites must use `S256` + same verifier at token exchange |
| Peer minting `…iyou.me:user:…` DIDs | `IDP_WEB_DID_NAMESPACE` unset/wrong | Set it to your authority and recreate managed users |
| Managed-user exports fail | No Vault configured | Provide `IDP_VAULT_ADDR`/`IDP_VAULT_TOKEN` or skip Tier-1 export |
| `did:key` user can't reach Tier-2 QR at your domain | Mobile wallet `url=` origin mismatch | Publish `IDP_BASE_URL` over HTTPS; wallet must trust the HTTPS origin |

---

## 9. Validation

Run Django's environment validation from the repo root (development host, not
the container):

```bash
cp .env.peer.example .env   # optional: exercise the peer values locally
python manage.py check
# -> System check identified no issues (0 silenced).
```

The check confirms every `IDP_*` setting, `DATABASE_URL`, `REDIS_URL`, app
registration (`apps.core` included), and the OIDC provider wiring parse cleanly
under peer configuration.