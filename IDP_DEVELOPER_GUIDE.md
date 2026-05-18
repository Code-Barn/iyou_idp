# Developer Guide: Sovereign Identity Provider (IdP) [L1-536]

## Overview [L3-7]

The iYou IdP is a Django-based OIDC provider that authenticates users via
W3C Decentralised Identifiers (DIDs) instead of passwords.  A Rust extension
(`_crypto`) handles Ed25519 signature verification; the browser talks to a
desktop companion app (`iyou-home`) over a local WebSocket for native signing.

## Architecture [L7-20]

```
  Browser (login.html)          Django IdP (port 8001)         iYou Home (port 9001)
       │                              │                              │
       ├── GET /auth/login/ ─────────►│                              │
       │◄── login page (HTML+JS) ─────┤                              │
       │                              │                              │
       │  ── pre-flight probe ────────┼────── fetch OPTIONS ────────►│
       │◄────────── 200/404 ──────────┼──────────────────────────────┤
       │                              │                              │
       │  ── WebSocket handshake ─────┼──────── ws://local ─────────►│
       │◄────────── connected ────────┼──────────────────────────────┤
       │                              │                              │
       │  POST /auth/challenge/ ─────►│                              │
       │◄──── {challenge: uuid} ──────┤                              │
       │                              │                              │
       │  ── {type:sign,challenge} ───┼─────────────────────────────►│
       │◄── {type:signature,vp:...} ──┼──────────────────────────────┤
       │                              │                              │
       │  POST /auth/verify/ ────────►│                              │
       │◄── {redirect_url:...} ───────┤                              │
       │                              │                              │
       │  window.location = redirect  │                              │
       └──────────────────────────────┘                              ┘
```

## Project Structure [L20-67]

```
iyou_idp/
├── auth_bridge/                 # Django app — auth logic
│   ├── management/commands/
│   │   └── createsuperuser_did.py
│   ├── templates/auth_bridge/
│   │   └── login.html           # Full-page JS handshake UI
│   ├── __init__.py
│   ├── admin.py
│   ├── admin_views.py           # DID-based admin login views
│   ├── backend.py               # DIDAuthBackend
│   ├── models.py                # User (AbstractBaseUser)
│   ├── oidc.py                  # OIDC userinfo/id-token hooks
│   ├── tests.py                 # 8 integration tests
│   ├── urls.py
│   └── views.py                 # verify_signature, ChallengeView, LoginPageView
├── config/
│   ├── __init__.py
│   ├── settings.py              # IDP_* env vars, django-environ, production hardening
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── src/
│   └── iyou_idp/
│       ├── __init__.py
│       ├── _crypto.abi3.so      # Compiled Rust extension
│       ├── _core.abi3.so
│       └── _core.pyi
├── crates/
│   └── rust-did/                # Rust DID verification library
├── Cargo.toml                   # Rust crate config
├── pyproject.toml               # Python project + uv/gunicorn deps
├── Dockerfile                   # Multi-stage uv-based production build
├── docker-entrypoint.sh         # migrate + gunicorn entrypoint
├── .dockerignore                # Build context filter
├── .env.example
└── README.md
```

## Setup & Installation [L67-108]

### Prerequisites [L69-78]

- Python 3.10+
- Rust toolchain (`rustup`)
- Redis 6+ (running on `127.0.0.1:6379`)
- `uv` (Python package manager) or `pip`

### Installation [L78-108]

```bash
git clone https://github.com/your-org/iyou_idp.git
cd iyou_idp

# Create virtualenv and install Python deps
uv sync

# Build the Rust crypto bridge
maturin develop --manifest-path Cargo.toml

# Run migrations
uv run python manage.py migrate

# Generate an RSA signing key for OIDC tokens (mandatory — token issuance fails without it)
uv run python manage.py creatersakey

# Create a superuser for admin access
uv run python manage.py createsuperuser_did

# Start the dev server
uv run python manage.py runserver 0.0.0.0:8001
```

**Quick start with Docker:**
```bash
docker build -t iyou-idp:latest .
docker run -p 8000:8000 \
  -e IDP_SECRET_KEY="insecure-dev-key-only" \
  -e IDP_BASE_URL="http://localhost:8000" \
  -e IDP_DEBUG=True \
  -e IDP_ALLOWED_HOSTS="localhost,127.0.0.1" \
  -e IDP_CSRF_TRUSTED_ORIGINS="http://localhost:8000" \
  -e IDP_CORS_ALLOWED_ORIGINS="http://localhost:8000" \
  -e REDIS_URL="redis://host.docker.internal:6379/1" \
  iyou-idp:latest
```
The entrypoint runs `migrate` automatically and spawns Gunicorn on `:8000`.

**Intel Mac dual-stack binding:**  On Intel Macs the IPv6 loopback
(`[::1]:9001`) can cause a 60-second stall before falling back to IPv4.
Configure iYou Home to bind to `[::]:9001` (dual-stack) so the browser's
IPv6-localhost preference resolves immediately:

```rust
// iyou-home server bind
TcpListener::bind("0.0.0.0:9001")   // IPv4 only — may stall on Intel Mac
// vs.
TcpListener::bind("[::]:9001")        // dual-stack — no stall
```

The pre-flight probe (`fetch OPTIONS` with 500ms timeout) in `login.html`
detects this condition and falls back to manual paste before the browser
thread blocks.

**Mac bridge pathing:**  `config/settings.py` injects `src/` into `sys.path`:
```python
sys.path.append(os.path.join(BASE_DIR, 'src'))
```
If you see `"Rust Crypto Bridge not found"` at runtime, the `.so` wasn't
built or `src/` isn't reachable.  Re-run `maturin develop` or copy
`_crypto.abi3.so` from `.venv/lib/python3.*/site-packages/iyou_idp/` into
`src/iyou_idp/`.

## Core Components [L108-284]

### 1. User Model [L110-161]

**`class UserManager`** [L115-126]

```python
def create_user(self, did):       # Creates a user with DID as username
def create_superuser(self, did):  # Creates staff+superuser
```

**`class User`** [L129-158] — extends `AbstractBaseUser`:
- `username` — stores the DID string (e.g. `did:key:z6Mk...`)
- `is_active`, `is_staff`, `is_superuser`, `date_joined`
- `USERNAME_FIELD = 'username'`
- Indexed on `(username, is_active)` for fast DID lookups

```python
def __str__(self): return self.username
def has_perm(self, perm, obj=None): return self.is_superuser
def has_module_perms(self, app_label): return self.is_superuser
```

### 2. Challenge-Response Flow [L161-187]

```
POST /auth/challenge/  →  {challenge: "<uuid>", expires_in: 300}
POST /auth/verify/     →  {success: true, redirect_url: "...", user: {...}}
```

The challenge is stored in Redis with a **300-second (5-minute) TTL** so
manual copy-paste doesn't expire.  A cache miss returns HTTP 400 with
`"Challenge expired"` (not 404 — this is a client logic error, not a missing
resource).

The `verify_signature` view:
1. Parses the JSON body (`verifiable_presentation`, `challenge`, `next_url`)
2. Validates the challenge exists in Redis
3. Calls the Rust bridge via `verify_vp(json.dumps(vp_json))`
4. Extracts the `holder` DID from the VP
5. Deletes the challenge from Redis (one-time use)
6. Creates the user if they don't exist (`get_or_create`)
7. Calls `django.contrib.auth.login()` to establish the session
8. Calls `_build_oidc_redirect()` to optionally skip the OIDC consent page
9. Returns `{success: true, redirect_url: ..., user: {did, is_new_user, ...}}`

### 3. Rust Bridge [L187-209]

**`fn hello_from_bin`** [L193] — smoke-test function, returns a string.

**`fn verify_signature`** [L196-197] — (legacy) takes `(did, message, sig)`.

**`fn verify_vp`** [L200-203] — takes a JSON-serialized Verifiable
Presentation string, returns `{valid: true/false, error: "..."}`.

The bridge is imported via a three-tier fallback in `views.py`:

```python
try:
    from iyou_idp import _crypto       # Standard import (src/ on sys.path)
    verify_vp = _crypto.verify_vp
except ImportError:
    import _crypto                      # Bare import fallback
    verify_vp = _crypto.verify_vp
```

If all attempts fail, the view prints full `sys.path` plus the path it
probed for `_crypto.abi3.so` and returns `status=500` with instructions.

### 4. Creating a Superuser [L209-234]

```bash
uv run python manage.py createsuperuser_did
```

Options:
- `--did did:admin:myadmin` (default: `did:admin:superuser`)
- `--password <pass>` (or `DJANGO_SUPERUSER_PASSWORD` env var)
- `--no-input` (skip interactive prompts, useful in scripts)

If no password is set, the user can still log in via DID auth (the
`DIDAuthBackend` ignores passwords for DID users).

### 5. Authentication Backend [L234-258]

**`class DIDAuthBackend`** [L242-253]

```python
def authenticate(self, request, username=None, password=None, **kwargs):
    try:
        user = User.objects.get(username=username, is_active=True)
        return user  # Password is ignored for DID auth
    except User.DoesNotExist:
        return None
```

This backend is listed first in `AUTHENTICATION_BACKENDS` in settings.py,
followed by the standard `ModelBackend` (for admin password login).

### 5. OIDC Provider [L258-284]

**`def custom_userinfo_claims`** [L263-271] — adds `did`, `preferred_username`,
and `did_method` to the standard OIDC userinfo endpoint.

**`def custom_id_token_claims`** [L274-281] — adds `did` and `did_method`
claims to the ID token JWT.

**`def custom_sub_generator`** — returns the DID (user.username) as the
`sub` claim, ensuring the user's DID is the stable identifier across
sessions and clients.

## Authentication Flow (VerifySignatureView) [L284-314]

### Challenge-Response Cycle [L286-298]

1. User clicks "Request Challenge" → `POST /auth/challenge/`
2. Server generates UUID, stores in Redis with 300s TTL
3. JS receives `{challenge, expires_in}` and displays it
4. User signs the challenge with their DID wallet (or mock VP)
5. `POST /auth/verify/` with `{verifiable_presentation, challenge, next_url}`
6. Server validates challenge in Redis, calls `verify_vp()`, logs in user
7. Returns `{success, redirect_url, user}`

### Satellite-App Redirect Safety [L298-306]

The `redirect_url` in the verify response is derived from the `next_url`
that was passed in.  When the caller is the OIDC authorize flow, `next_url`
contains the full `/openid/authorize/?client_id=...&redirect_uri=...`
query string.  The `_build_oidc_redirect()` helper parses these params,
directly generates an OIDC authorization `Code`, and returns the client's
`redirect_uri?code=...&state=...` — **skipping the consent page entirely**.

This means the browser goes:
```
verify → (302) client callback with code
```
instead of the slower:
```
verify → (200) consent page → user clicks Allow → (302) client callback
```

### iYou Home Desktop Companion [L306-314]

The login page attempts a WebSocket connection to `ws://localhost:9001` for
native signing.  The wire protocol is a simple JSON request/response exchange:

**Request** (browser → iYou Home):
```json
{"type": "sign", "challenge": "<uuid>"}
```

**Response** (iYou Home → browser):
```json
{"type": "signature", "vp": {"@context": ["..."], "type": ["VerifiablePresentation"], "holder": "did:key:...", "proof": {...}}}
```

The `vp` value is the signed Verifiable Presentation, which the browser
relays to `POST /auth/verify/`.  If iYou Home sends the VP as an escaped
JSON string (rather than a nested object), the Django view handles it via an
`isinstance(vp_json, str)` guard that calls `json.loads()` a second time.

The handshake has several protection layers:

1. **Pre-flight probe** — `fetch('http://localhost:9001', {method:'OPTIONS', signal:AbortSignal.timeout(500)})` checks if the port is reachable before committing to `new WebSocket()` (avoids browser thread blocking from PNA checks).

2. **Kill Switch** — A "Cancel & Use Manual Paste" button appears
   **immediately** (no 0.5s delay) when the linking UI shows.  Clicking it
   calls `socket.close()` to abort any in-flight TCP connection.

3. **2-second force fallback** — If `socket.readyState !== WebSocket.OPEN`
   after 2 seconds, the socket is forcibly closed and the manual paste box
   appears (down from 3s).

4. **Alert-based debugging** — When a WebSocket message arrives,
   `alert("MESSAGE RECEIVED: " + event.data)` fires so the developer can
   confirm the browser actually received the payload (useful for diagnosing
   browser-level networking issues).

5. **Version logging** — `console.log("LOGIN UI VERSION: 2.0.5")` at script
   top and `console.log("!!! HANDSHAKE START VERSION 2.0.5 !!!")` in the
   `onopen` handler let you confirm the browser isn't serving a stale cached
   copy of the page.

6. **Cache busting** — `<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">` in `<head>` forces re-fetch on every navigation.

## API Endpoints [L314-343]

### Authentication Endpoints [L316-325]

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/login/` | Renders login page |
| POST | `/auth/challenge/` | Generates new challenge (300s TTL) |
| GET | `/auth/challenge/` | Health check |
| POST | `/auth/verify/` | Verifies VP, logs in, returns redirect |

### Admin DID Endpoints [L325-333]

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/auth/admin/did-login/` | DID-based admin login form |
| POST | `/auth/admin/did-verify/` | Verifies admin DID challenge |
| GET | `/auth/admin/did-dashboard/` | Admin dashboard (post-login) |

### OIDC Endpoints [L333-343]

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/openid/authorize/` | OIDC authorization endpoint |
| POST | `/openid/token/` | Token exchange endpoint |
| GET | `/openid/userinfo/` | Userinfo endpoint |
| GET | `/openid/.well-known/openid-configuration/` | Discovery document |
| GET | `/openid/jwks/` | JWKS endpoint |

## Development Workflow [L343-397]

### Adding New Features [L345-354]

1. Write a test first in `auth_bridge/tests.py`
2. Implement the feature
3. Run `uv run python manage.py test auth_bridge -v2`
4. Run `uv run ruff check auth_bridge/`
5. Run `uv run python manage.py check`

### Testing [L354-381]

```bash
# Run all auth tests
uv run python manage.py test auth_bridge -v2

# Run a single test
uv run python manage.py test auth_bridge.tests.ChallengeResponseCycleTest.test_full_cycle_creates_session -v2
```

The test suite creates Ed25519 keys, builds signed Verifiable Credentials
and Presentations, exercises the full challenge-response cycle, and
verifies OIDC redirects (both classic and direct-callback).

Key tests:
- `test_full_cycle_creates_session` — end-to-end: challenge → VP → verify → session
- `test_next_url_roundtrip` — non-OIDC next_url is echoed back as redirect_url
- `test_missing_fields_returns_400` — empty body returns 400
- `test_expired_challenge_returns_404` — expired/missing challenge returns 400
- `test_authorize_returns_code_for_authenticated_user` — classic OIDC authorize flow
- `test_verify_redirects_directly_to_client` — direct-callback: verify returns client URI with code
- `test_jwks_endpoint_returns_valid_key` — `/openid/jwks/` exposes at least one RSA key

### Debugging [L381-397]

- **WebSocket not connecting?** Open browser dev tools console.  Look for:
  - `"LOGIN UI VERSION: 2.0.5"` — confirms fresh JS
  - `"WS: Socket Created"` — WebSocket constructor succeeded
  - `"WS: Connection Opened"` — handshake completed
  - `"WS: Socket Error"` — browser blocked or server not listening
  - `"WS: Force-fallback timer expired"` — 2s timeout was reached
- **Signature not received?** The `alert("MESSAGE RECEIVED: ...")` in the
  `onmessage` handler is the definitive test.  If it fires, the browser got
  the data.  If not, the network is swallowing the message.
- **Server error on verify?** Look for `"VERIFY RESPONSE FULL:"` in the
  console — the full JSON response is logged.
- **Rust bridge not found?** Check the console for the `"="` banner with
  `sys.path` and the probe path.  Re-run `maturin develop`.

## Error Handling [L397-421]

### Common Errors & Solutions [L399-412]

| Error | Cause | Fix |
|-------|-------|-----|
| `no keys in database` | `creatersakey` was never run | Run `uv run python manage.py creatersakey` |
| `Rust Crypto Bridge not found` | `src/` not on `sys.path` or `.so` missing | Run `maturin develop` or check `sys.path` in `settings.py` |
| `Challenge expired` | Challenge TTL (300s) exceeded | Request a new challenge |
| `Missing required fields` | VP or challenge not in POST body | Check JS `submitVP()` sends all fields |
| 500 on POST to `/auth/verify/` | import or bridge crash | Check console for `VERIFY RESPONSE FULL` or server traceback |
| WebSocket never opens | Browser PNA blocking or iyou-home not running | Check pre-flight probe result; use manual paste |
| `data.redirect_url` not redirecting | `data.success` falsy or `redirect_url` missing | Check `VERIFY RESPONSE FULL` in console |

### Error Response Format [L412-421]

All JSON error responses follow this structure:
```json
{
  "error": "Human-readable message describing the issue"
}
```

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Bad request (missing fields, expired challenge, invalid VP structure) |
| 401 | Verification failed (signature invalid) |
| 403 | User account disabled |
| 500 | Internal error (bridge import failure, unexpected exception) |

## Deployment [L421-463]

### Production Checklist [L423-436]

- [ ] Set `IDP_SECRET_KEY` to a strong random value
- [ ] Set `IDP_BASE_URL` to the public-facing URL (e.g. `https://idp.example.com`)
- [ ] Set `IDP_DEBUG=False`
- [ ] Set `IDP_ALLOWED_HOSTS` to the domain(s) (comma-separated)
- [ ] Set `IDP_CSRF_TRUSTED_ORIGINS` to match the public origin(s)
- [ ] Set `IDP_CORS_ALLOWED_ORIGINS` to the satellite app origin(s) (or empty if all on same domain)
- [ ] Set `DATABASE_URL` to a production PostgreSQL connection string
- [ ] Configure a real Redis instance via `REDIS_URL`
- [ ] Deploy with `docker build -t iyou-idp .` (Rust is compiled in the builder stage)
- [ ] Set up the Traefik/nginx ingress proxy with HTTPS termination
- [ ] The entrypoint uses Gunicorn on `:8000` — no additional WSGI server needed

### Docker Deployment [L436-463]

The project ships a production-ready multi-stage `Dockerfile`:

```dockerfile
# Stage 1 (builder):   python:3.12-slim + Rust toolchain + uv
#   - Installs Python deps via uv sync --no-dev
#   - Compiles crates/rust-did via cargo build --release
#   - Runs collectstatic --noinput
# Stage 2 (runner):    python:3.12-slim
#   - Copies .venv, libdid_rust.so, and staticfiles from builder
#   - Runs docker-entrypoint.sh (migrate + gunicorn)
```

**Build and run:**
```bash
docker build -t iyou-idp:latest .
docker run -d --name iyou-idp \
  -p 8000:8000 \
  -e IDP_SECRET_KEY="<generated-secret>" \
  -e IDP_BASE_URL="https://idp.example.com" \
  -e IDP_DEBUG=False \
  -e IDP_ALLOWED_HOSTS="idp.example.com" \
  -e IDP_CSRF_TRUSTED_ORIGINS="https://idp.example.com" \
  -e IDP_CORS_ALLOWED_ORIGINS="https://app.example.com" \
  -e DATABASE_URL="postgres://user:pass@db:5432/iyou_idp" \
  -e REDIS_URL="redis://redis:6379/1" \
  iyou-idp:latest
```

**Environment variable reference:**

| Variable | Type | Default | Description |
|---|---|---|---|
| `IDP_SECRET_KEY` | `str` | (dev fallback) | Django secret key — required in production |
| `IDP_BASE_URL` | `str` | `http://127.0.0.1:8000` | Public-facing base URL for OIDC endpoints |
| `IDP_DEBUG` | `bool` | `False` | Enable debug mode (dev only) |
| `IDP_ALLOWED_HOSTS` | `list` | `127.0.0.1` | Comma-separated allowed host/domain list |
| `IDP_CSRF_TRUSTED_ORIGINS` | `list` | `http://127.0.0.1:8000` | Origins allowed to POST CSRF-protected forms |
| `IDP_CORS_ALLOWED_ORIGINS` | `list` | `[]` | Origins allowed for CORS (satellite app domains) |
| `DATABASE_URL` | `str` | `sqlite:///db.sqlite3` | Database connection string (use PostgreSQL in production) |
| `REDIS_URL` | `str` | `redis://127.0.0.1:6379/1` | Redis connection for challenge-response caching |

When `IDP_DEBUG=False`, the following are automatically enabled:
- `SECURE_PROXY_SSL_HEADER` — trusts `X-Forwarded-Proto: https` from Traefik/nginx
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`
- Cookie names are isolated to `idp_sessionid` / `idp_csrftoken` to prevent domain collisions on shared loopback.

## Security Considerations [L463-475]

### Best Practices [L465-475]

- Challenges are single-use (deleted from Redis after verification)
- Challenge TTL is 300 seconds (limited window for replay)
- DID verification happens in native Rust (memory-safe)
- WebSocket connection is restricted to `localhost:9001` (no remote attack surface)
- OIDC authorization codes are generated by the provider's standard `create_code()` utility
- `@csrf_exempt` on `verify_signature` is safe because the endpoint has no session side-effects (auth is purely cryptographic)
- The `next_url` is validated against the OIDC client's registered `redirect_uris` before code generation

## Troubleshooting [L475-516]

### Rust-Python Bridge Issues [L477-493]

**Symptom:** `No module named 'iyou_idp'` or `Rust Crypto Bridge not found`

This is typically a `sys.path` issue.  The project root folder name is
`iyou_idp`, which can shadow the `iyou_idp` package on some platforms
(especially Mac).  The fix is the `sys.path.append` in `config/settings.py`
that injects the `src/` directory, where the actual `iyou_idp/` package
(with `_crypto.abi3.so`) lives.

If the error persists:
1. Check `sys.path` in the debug banner printed by `views.py`
2. Verify `src/iyou_idp/_crypto.abi3.so` exists
3. Re-run `maturin develop --manifest-path Cargo.toml`
4. Or copy the `.so` from `.venv/lib/python3.*/site-packages/iyou_idp/`

### Submodule Issues [L493-506]

The `crates/rust-did/` submodule must be checked out:
```bash
git submodule update --init --recursive
```

### OIDC Configuration Issues [L506-516]

**Symptom:** OIDC authorize returns 200 (consent page) instead of 302 with code

The `_build_oidc_redirect()` helper in `views.py` is designed to skip this,
but it only activates when the `next_url` contains full OIDC params
(`client_id`, `redirect_uri`, `response_type`) AND the client is found in
the database AND the `redirect_uri` matches the client's registered URIs.
If any of these fail, the view falls back to returning `next_url` as-is,
and the standard OIDC authorize flow (with consent page) applies.

To force the direct-callback path, ensure:
- The OIDC `Client` is registered in the database
- The `redirect_uri` in the authorize URL matches exactly (trailing slash matters)
- The `client_id` in the authorize URL matches the registered client

## Roadmap [L516-536]

### Short-term Goals [L518-525]

- Add a health-check endpoint for the WebSocket bridge (`GET /health/`)
- Add docker-compose.yaml with Redis + PostgreSQL services
- Add OIDC `prompt=login` support to force re-authentication
- Add PKCE (S256) support in the direct-callback path

### Long-term Goals [L525-536]

- Support multiple DID methods (did:web, did:ethr, did:sol)
- Replace the current polling-based iyou-home handshake with a push model
- Add a self-service admin UI for OIDC client registration
- Performance testing under load (concurrent DID verifications)
- CI/CD pipeline with automated Rust bridge builds for Linux and macOS
