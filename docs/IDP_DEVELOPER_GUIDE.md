# Developer Guide: Sovereign Identity Provider (IdP) [L1-693]

## Overview [L3-22]

The iYou IdP is a Django-based OIDC provider that authenticates users via
W3C Decentralised Identifiers (DIDs) instead of passwords.  A Rust extension
(`_crypto`) handles Ed25519 signature verification, backed by a Python
`cryptography` primary path for defence-in-depth.

The identity vault supports **three authentication tiers** that welcome
users of all technical levels while preserving the DID architecture:

| Tier | Tab | Authentication Method | Identity Model |
|------|-----|----------------------|----------------|
| **3 — Full Sovereignty** | Full Sovereignty | Desktop WebSocket (`iyou-home`) + manual VP paste | `did:key` (user-controlled) |
| **2 — Community Self-Signing** | Community Self-Signing | OOB QR-code flow with mobile DID wallet (`iyou_mobile`) | `did:key` (user-controlled) |
| **1 — Managed Convenience** | Managed Convenience | OAuth providers (Google, Apple, GitHub) | `did:web:iyou.me:user:{uuid}` (server-managed) |

Tier 1 managed accounts use a **server-managed `did:web`** identity — no
Ed25519 keypair or `did:key` string is generated.  The user's identity is
anchored to their verified email via the `User` model's `custodial_did`
field, with a `FederatedIdentity` link table recording each OAuth provider
association.  A smart-merge pipeline (`pipeline.py`) resolves new logins
against existing accounts to prevent duplicate registrations.

The portal is served at the root URL (`/`) and at `/auth/login/` — both render
the same tiered login card (no landing-page hero content).  After
authentication the satellite app (WUN) is opened in a **new browser tab** via
the `redirect_url`, while the current tab stays on the IdP and transitions to
the authenticated profile interface at `/`.  If no explicit `next` URL was
provided, the default is the value of `IDP_WUN_URL`.

## Architecture [L23-76]

### Level 3 — Desktop WebSocket Flow (Full Sovereignty)

```
  Browser tab 1 (IdP)          Django IdP (port 8000)         iYou Home (port 9001)
       │                              │                              │
       ├── GET / or /auth/login/ ────►│                              │
       │◄── login page (HTML+JS) ─────┤                              │
       │                              │                              │
       │  ── pre-flight probe ────────┼────── fetch OPTIONS ────────►│
       │◄────────── 200/404 ──────────┼──────────────────────────────┤
       │                              │                              │
       │  ── WebSocket handshake ─────┼──────── ws://$IDP_HOME_WS    ►│
       │◄────────── connected ────────┼──────────────────────────────┤
       │                              │                              │
       │  POST /auth/challenge/ ─────►│                              │
       │◄── {challenge: uuid} ────────┤                              │
       │                              │                              │
       │  ── {type:sign,challenge} ───┼─────────────────────────────►│
       │◄── {type:signature,vp:...} ──┼──────────────────────────────┤
       │                              │                              │
       │  POST /auth/verify/ ────────►│                              │
       │◄── {redirect_url:...} ───────┤                              │
       │                              │                              │
       │  window.open(redirect,'_blank')──►  Browser tab 2 (WUN)     │
       │  window.location.href = '/'   │                              │
       │  (shows authenticated dash)   │                              │
       └──────────────────────────────┘                              ┘
```

### Level 2 — OOB QR-Code Flow (Community Self-Signing)

```
  Browser tab 1 (IdP)          Django IdP (port 8000)        iyou_mobile (phone)
       │                              │                              │
       │  POST /auth/challenge/ ─────►│                              │
       │◄── {challenge: uuid} ────────┤                              │
       │                              │                              │
       │  Render QR code              │                              │
       │  (iyouauth://sign?ch=…       │                              │
       │   &url=…&next=…)             │                              │
       │                              │  ─── scan QR code ──────────►│
       │                              │                              │
       │                              │  POST /auth/mobile-verify/ ─►│
       │                              │  {vp: …, challenge: uuid}    │
       │                              │◄── {solved: true} ───────────┤
       │                              │                              │
       │  GET /auth/challenge-status/ │                              │
       │      <uuid>/ (poll 1s) ─────►│                              │
       │◄── {solved:true,             │                              │
       │     redirect_url:…} ─────────┤                              │
       │                              │                              │
       │  window.open(redirect,'_blank')──►  Browser tab 2 (WUN)     │
       │  window.location.href = '/'   │                              │
       │  (shows authenticated dash)   │                              │
       └──────────────────────────────┘                              ┘
```

### Level 1 — Managed Convenience (OAuth2 Inbound)

```
  Browser (IdP)               Django IdP               Provider (Google/Apple/GitHub)
       │                          │                              │
       ├── GET /auth/oauth/       │                              │
       │   initiate/<provider>/   │                              │
       │   (state in session)     │                              │
       │──302────────────────────►│──302 auth endpoint──────────►│
       │                          │                              │
       │              User authenticates at provider             │
       │◄─────────────302 callback (code + state)───────────────┤
       │                          │                              │
       ├── GET /auth/oauth/       │                              │
       │   callback/<provider>/   │                              │
       │──state validation────────│                              │
       │──code exchange───────────│────POST token endpoint──────►│
       │                          │◄────access_token + id_token──┤
       │                          │                              │
       │                          │──GET userinfo endpoint──────►│
       │                          │◄────{sub, email, name}───────┤
       │                          │                              │
       │                          │──process_oauth_identity()────│
       │                          │  (smart-merge pipeline)      │
       │                          │  assign did:web:iyou.me:     │
       │                          │    user:{uuid}               │
       │                          │                              │
       │◄──login() + 302 redirect─│                              │
       │  (OIDC continuity or     │                              │
       │   IDP_WUN_URL)           │                              │
       └──────────────────────────┘                              ┘
```

## Project Structure [L78-123]

```
iyou_idp/
├── auth_bridge/                    # Django app — auth logic
│   ├── management/commands/
│   │   ├── createsuperuser_did.py  # Creates superuser with --email, --did
│   │   └── seed_clients.py         # Auto-seeds OIDC satellite clients
│   ├── templates/auth_bridge/
│   │   ├── login.html              # Shell: tab nav + includes + shared JS
│   │   ├── _tab_sovereign.html     # Tab 0: WebSocket + manual VP flow
│   │   ├── _tab_community.html     # Tab 1: OOB QR-code flow
│   │   ├── _tab_managed.html       # Tab 2: OAuth providers (live)
│   │   ├── _download_modal.html    # Desktop iYou Home download overlay
│   │   ├── _mobile_download_modal.html  # Mobile iYou download overlay
│   │   ├── authenticated_dashboard.html # Post-login profile interface
│   │   └── admin/                  # Admin DID login templates
│   ├── static/auth_bridge/
│   │   ├── js/
│   │   │   ├── download_modal.js          # Desktop modal controller (IIFE)
│   │   │   └── mobile_download_modal.js   # Mobile modal controller (IIFE)
│   │   └── img/
│   │       └── Tux.svg                    # Linux penguin icon
│   ├── migrations/
│   │   ├── 0001_initial_with_multi_auth.py  # UUID PK, User, FederatedIdentity
│   │   └── 0004_user_is_sovereign_passkeycredential.py  # is_sovereign flag + PasskeyCredential
│   ├── __init__.py
│   ├── admin.py
│   ├── admin_views.py              # DID-based admin login views
│   ├── apps.py                     # AppConfig with guarded seed_clients
│   ├── backend.py                  # DIDAuthBackend + evaluate_sovereign_admin_posture
│   ├── models.py                   # User (UUIDField PK) + FederatedIdentity
│   ├── oidc.py                     # OIDC userinfo/id-token hooks (custodial_did)
│   ├── pipeline.py                 # Smart-Merge: process_oauth_identity()
│   ├── passkeys.py                 # WebAuthn engine: Fido2Server wrapper, option serialization
│   ├── vault_client.py             # HashiCorp Vault KV v2 wrapper (identity key custody)
│   ├── views_graduation.py         # Identity Graduation: graduate_export, graduate_confirm
│   ├── views_passkeys.py           # Passkey ceremony endpoints (register/authenticate)
│   ├── tests/                      # Test package
│   │   ├── __init__.py             # Legacy integration tests
│   │   ├── test_graduation.py      # Graduation protocol tests (14)
│   │   └── test_passkeys.py        # Passkey ceremony tests (10)
│   ├── urls.py                     # Auth + OAuth + passkey routes
│   ├── urls_api.py                 # /api/v1/identity/ graduate routes
│   ├── views.py                    # verify_signature, ChallengeView, LoginPageView,
│   │                               # mobile_verify_signature, check_challenge_status,
│   │                               # managed_login, SovereignAuthorizeView, _build_oidc_redirect
│   └── views_oauth.py             # Tier 1 OAuth: OAuthInitiateView, OAuthCallbackView
├── config/
│   ├── __init__.py
│   ├── settings.py                 # IDP_* env vars, django-environ, production hardening
│   ├── urls.py                     # Root / → LoginPageView (login portal)
│   ├── wsgi.py
│   └── asgi.py
├── src/
│   └── iyou_idp/
│       ├── __init__.py
│       ├── _crypto.abi3.so         # Compiled Rust extension
│       ├── _core.abi3.so
│       └── _core.pyi
├── crates/
│   └── did_rust/                   # Rust DID verification library (submodule — shared with iyou_home)
├── Cargo.toml                      # Rust crate config
├── pyproject.toml                  # Python project + uv/gunicorn deps
├── Dockerfile                      # Multi-stage uv + maturin production build
├── docker-entrypoint.sh            # migrate + gunicorn entrypoint
├── .dockerignore                   # Build context filter
├── .env.example
├── scripts/
│   ├── build-image.sh              # Local container build wrapper
│   └── deploy-idp-remote.sh        # Cross-VM 6-stage deployment pipeline
└── README.md
```

## Setup & Installation [L125-199]

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
# Build using the convenience wrapper
./scripts/build-image.sh

# Or build directly
docker build -t iyou-idp:latest .

docker run -p 8000:8000 \
  -e IDP_SECRET_KEY="insecure-dev-key-only" \
  -e IDP_BASE_URL="http://localhost:8000" \
  -e IDP_WUN_URL="http://localhost:8001" \
  -e IDP_HOME_URL="http://localhost:9000" \
  -e IDP_HOME_WS_URL="ws://localhost:9001" \
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

## Core Components [L199-339]

### 1. User Model [L201-222]

**`class SovereignUserManager`** — extends `BaseUserManager`:

```python
def create_user(self, email, custodial_did=None, **extra_fields):
    # Generates did:web:iyou.me:user:{uuid} if custodial_did not provided

def create_superuser(self, email, custodial_did=None, **extra_fields):
    # Sets is_staff=True, is_superuser=True
```

**`class User`** — extends `AbstractBaseUser` + `PermissionsMixin`:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `UUIDField` (PK) | Auto-generated, non-editable |
| `email` | `EmailField` (unique) | `USERNAME_FIELD` — used for lookup |
| `custodial_did` | `CharField(255, unique)` | `did:web:iyou.me:user:{uuid}` — the canonical identity |
| `account_tier` | `CharField` | `"sovereign"`, `"community"`, or `"managed_free"` |
| `is_sovereign` | `BooleanField` | Default `False` — flipped to `True` by the Identity Graduation protocol; blocks front-channel OIDC issuance |
| `show_legal_disclaimer` | `BooleanField` | Default `True` — controls Legal Disclaimer Gate presentation on login |
| `disclaimer_acknowledged_at` | `DateTimeField` | Timestamp of explicit disclaimer acknowledgment (audit trail) |
| `is_active` | `BooleanField` | Default `True` |
| `is_staff` | `BooleanField` | For Django admin access |
| `is_superuser` | `BooleanField` | For Django admin access |
| `created_at` | `DateTimeField` | Auto-set on creation |
| `updated_at` | `DateTimeField` | Auto-updated |

```python
def __str__(self): return self.custodial_did
def has_perm(self, perm, obj=None): return self.is_superuser
def has_module_perms(self, app_label): return self.is_superuser
@property
def date_joined(self): return self.created_at  # OIDC provider compatibility
```

**`class FederatedIdentity`** — links OAuth provider accounts to users:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `AutoField` (PK) | |
| `user` | `ForeignKey(User)` | `on_delete=CASCADE` |
| `provider` | `CharField(50)` | `"google"`, `"github"`, `"apple"` |
| `provider_user_id` | `CharField(255)` | Provider's unique subject ID |
| `created_at` | `DateTimeField` | Auto-set on creation |

Unique constraint: `(provider, provider_user_id)` — prevents duplicate
provider accounts.

**`class PasskeyCredential`** — WebAuthn credentials bound to a user for the
passwordless Managed login factor:

| Field | Type | Notes |
|-------|------|-------|
| `id` | `UUIDField` (PK) | Auto-generated, non-editable |
| `user` | `ForeignKey(User)` | `related_name="passkeys"`, `on_delete=CASCADE` |
| `credential_id` | `BinaryField` (unique) | Raw WebAuthn credential ID — one row per authenticator |
| `public_key_cose` | `BinaryField` | CBOR-encoded COSE public key from the attestation |
| `sign_count` | `PositiveIntegerField` | Last assertion counter — powers clone detection |
| `transports` | `JSONField` (list) | e.g. `["internal"]`, `"hybrid"`, `"usb"` |
| `created_at` | `DateTimeField` | Auto-set on registration |
| `last_used_at` | `DateTimeField` | Null until first successful assertion |

**`AUTH_USER_MODEL`** is set to `"auth_bridge.User"` in `config/settings.py`.
All `ForeignKey` relationships must reference
`settings.AUTH_USER_MODEL`, not `User` directly.

### 2. Challenge-Response Flow [L222-269]

Every challenge is stored in Redis as a JSON dict with a **300-second TTL**:

```json
{"status": "pending", "did": null, "next_url": "/openid/authorize/?client_id=..."}
```

**Desktop WebSocket flow** (`POST /auth/verify/`):

```
POST /auth/challenge/  →  {challenge: "<uuid>", expires_in: 300, stored: true|false}
POST /auth/verify/     →  {success: true, redirect_url: "...", user: {...}}
```

The `verify_signature` view:
1. Parses the JSON body (`verifiable_presentation`, `challenge`, `next_url`)
2. Validates the challenge exists in Redis
3. Reconstructs the VP payload with keys in insertion order, runs the
   **three-tier verification pipeline**: Python Ed25519 → Rust `verify_vp` →
   emergency bypass (see §3. Rust Bridge)
4. Extracts the `holder` DID from the VP
5. Deletes the challenge from Redis (one-time use)
6. Creates the user if they don't exist (`get_or_create`)
7. Calls `django.contrib.auth.login()` to establish the session
8. Calls `_build_oidc_redirect()` to optionally skip the OIDC consent page
9. Returns `{success: true, redirect_url: ..., user: {did, is_new_user, ...}}`

**OOB mobile flow** (`POST /auth/mobile-verify/` + polling):

```
POST /auth/mobile-verify/  →  {solved: true}
GET  /auth/challenge-status/<uuid>/  →  {solved: true, redirect_url: "..."}
                                  or  {solved: false}
```

1. The browser fetches a challenge (`POST /auth/challenge/`) and renders it as
   a QR code encoding `iyouauth://sign?ch=<uuid>&url=<base>&next=<next>`.
2. The mobile app scans the QR code, signs the VP, and POSTs it to
   `{url}/auth/mobile-verify/`.
3. `mobile_verify_signature` verifies the VP through the **same three-tier
   pipeline** (Python → Rust → bypass) and updates the cache entry:
   `{"status": "solved", "did": "did:key:…"}`.  It rejects replays — if
   `status` is already `solved`, returns 400.
4. The browser polls `check_challenge_status` every 1 second.  Once the
   status is `solved`, the view creates the user, calls
   `django.contrib.auth.login()`, generates the OIDC redirect, deletes the
   challenge, and returns `{solved: true, redirect_url: "..."}`.

### 3. Verification Pipeline (Three-Tier Redundancy) [L269-305]

VP signature verification uses a **three-tier fallback pipeline** with the
Python `cryptography` library as the primary path, Rust `verify_vp` as
secondary, and an emergency bypass as last resort.  The pipeline is identical
in both `verify_signature` (desktop WebSocket) and `mobile_verify_signature`
(mobile OOB):

| Tier | Method | When Used |
|------|--------|-----------|
| **1 — Python Ed25519** | `cryptography.hazmat.primitives.asymmetric.ed25519` | Always attempted first |
| **2 — Rust `verify_vp`** | `_crypto.verify_vp()` via FFI | Tier 1 fails |
| **3 — Emergency bypass** | challenge-nonce match (no crypto) | Both tiers fail + strict security logging |

```python
def _get_rust_verify_vp():
    """Import and return the verify_vp callable from the Rust _crypto bridge."""
    try:
        from iyou_idp import _crypto
        return _crypto.verify_vp, None
    except ImportError:
        try:
            import _crypto
            return _crypto.verify_vp, None
        except ImportError as e:
            return None, [str(e)]
```

**Tier 1 — Python primary path (recommended):**

The VP payload is reconstructed with keys in insertion order, serialized with
`json.dumps(vp_payload, separators=(",", ":"))`, and verified via the
`cryptography` library.  This is the **production path** — it is immune to
the serde_json serialisation mismatch that historically broke the Rust bridge.

The correct key order is: **`@context, type, holder, challenge,
verifiableCredential, issuer`**.  This matches the insertion order used by
`did_rust::issue_vc` in `iyou_home` (`serde_json::to_vec(&vp)` with
`preserve_order` enabled).

```python
vp_payload = {}
vp_payload["@context"]     = vp_json.get("@context", [])
vp_payload["type"]         = vp_json.get("type", [])
vp_payload["holder"]       = vp_json.get("holder", "")
vp_payload["challenge"]    = vp_json.get("challenge", "")
vp_payload["verifiableCredential"] = vp_json.get("verifiableCredential", [])
vp_payload["issuer"]       = vp_json.get("issuer", holder_did)
vp_payload_bytes = json.dumps(vp_payload, separators=(",", ":")).encode("utf-8")
```

**Tier 2 — Rust `verify_vp` bridge:**

`verify_vp` takes a JSON-serialised Verifiable Presentation string, parses
it, removes the `proof` object, serialises the remainder back to bytes with
`serde_json::to_vec`, and calls Ed25519 verify against the DID document's
public key.  It returns `{valid: true/false, error: "..."}`.

This tier was historically **broken by code drift** between the two
`did_rust` submodule copies (see "Submodule Alignment Rule" below).  Now
that both copies are pinned to the same commit, it should work for all
root-login VPs (no embedded Verifiable Credential).  A full VC-chain
verification (recursive `verifiableCredential` traversal) is the long-term
goal.

**Tier 3 — Emergency bypass (logged, not for production):**

If both Tiers 1 and 2 fail, and the VP's `challenge` field matches the
challenge nonce in Redis, the view accepts the authentication anyway.
Every bypass attempt is logged with remote IP, DID, and challenge prefix so
admin audits can detect abuse.  This tier exists solely to prevent lock-out
during bridge alignment and must never be relied on in production.

### 4. Creating a Superuser [L297-311]

```bash
uv run python manage.py createsuperuser_did
```

Options:
- `--email admin@iyou.me` (required — used as `USERNAME_FIELD`)
- `--did did:web:iyou.me:user:admin` (default: auto-generated from UUID)
- `--password <pass>` (or `DJANGO_SUPERUSER_PASSWORD` env var)
- `--no-input` (skip interactive prompts, useful in scripts)

If no password is set, the user can still log in via DID auth (the
`DIDAuthBackend` ignores passwords for DID users) or via OAuth.

**Automatic elevation via `ADMIN_DID`:** Set the `ADMIN_DID` environment
variable to a `did:key:` multibase string — any user authenticating with
that DID is automatically promoted to `is_staff` + `is_superuser` with an
unusable password on every login.  This replaces the legacy database-password
superuser model for the sovereign admin at `iyou.me/admin`.  See the
[Admin DID Endpoints](#admin-did-endpoints-l449-457) section for details.

### 5. Authentication Backend [L311-327]

**`class DIDAuthBackend`** [L242-253]

```python
def authenticate(self, request, username=None, password=None, **kwargs):
    try:
        user = User.objects.get(custodial_did=username, is_active=True)
        return user  # Password is ignored for DID auth
    except User.DoesNotExist:
        return None
```

This backend is listed first in `AUTHENTICATION_BACKENDS` in settings.py,
followed by the standard `ModelBackend` (for admin password login).

**`evaluate_sovereign_admin_posture(user)`** — called after every auth
ingress (`verify_signature`, `check_challenge_status`, and
`custom_admin_verify`).  Checks if the authenticated user's `custodial_did`
matches the `ADMIN_DID` environment variable; on match, atomically elevates
to `is_staff=True`, `is_superuser=True` with an unusable password.  This
ensures the sovereign admin always has admin access regardless of how they
authenticated (DID, OAuth, or mobile).

### 6. OIDC Provider [L327-339]

**`def custom_userinfo_claims`** [L263-271] — adds `did` (`custodial_did`),
`preferred_username` (`custodial_did`), and `did_method` to the standard
OIDC userinfo endpoint.

**`def custom_id_token_claims`** [L274-281] — adds `did` and `did_method`
claims to the ID token JWT.

**`def custom_sub_generator`** — returns `user.custodial_did` as the
`sub` claim, ensuring the user's DID is the stable identifier across
sessions and clients.

The OIDC provider expects `user.date_joined` — solved via a `@property`
alias on the `User` model that returns `created_at`.

### 7. Post-Login Redirect Configuration

The constant `DEFAULT_NEXT_URL` in `auth_bridge/views.py` reads from
`settings.IDP_WUN_URL` environment variable.  It controls where the user
is directed after authentication when no explicit `next` URL was provided
by the OIDC client.

All entry points use this constant as their fallback:
- `verify_signature()` — WebSocket path
- `ChallengeView.post()` — stores it in the Redis JSON dict
- `check_challenge_status()` — polling path
- `LoginPageView.get()` — reads `?next=` from query params

**Authenticated-user redirect:** `LoginPageView.get()` also redirects
already-authenticated users directly to `IDP_WUN_URL`, **but only when no
`?next=` query parameter is present**.  This preserves the OIDC authorization
code exchange (where `next` contains critical OIDC params).  Unauthenticated
visitors always see the login card, regardless of `?next=`.

#### Dual-Window Behaviour

After a successful login the JavaScript handler calls `onAuthSuccess(redirectUrl)`:

1. **New tab**: the satellite app (`redirectUrl`, typically the WUN OIDC callback
   with `?code=...&state=...`) is opened via `window.open(url, '_blank')`.
2. **Same tab**: the IdP page reloads at `/` to reveal the authenticated profile
   interface (`authenticated_dashboard.html`).

**Popup-blocker resilience:** The `reserveAuthPopup()` helper fires
`window.open('', '_blank')` **synchronously** inside the user-click event
handler (`signWithIYouHome()` or `handleManualSubmit()`), which browsers
permit because it is a direct user gesture.  The real destination URL is
assigned later inside the async `fetch().then()` callback via
`authPopupRef.location.href`.  If the popup was blocked, a visible fallback
link appears after 500 ms.

The dual-window flow applies to all three auth tiers:
- **Tab 0 (Full Sovereignty):** `submitVerify()` success handler
- **Tab 1 (Community Self-Signing):** `startCommunityPolling()` success handler
- **Tab 2 (Managed Convenience):** `OAuthCallbackView._complete_login()` → 302 redirect

To configure the satellite destination, set the `IDP_WUN_URL` environment
variable (cluster-internal DNS or public domain).

#### Legal Disclaimer Gate

Every user authenticating through the identity provider passes through a legal disclaimer gate ("Sovereign Network Access & Legal Notice") prior to final redirection:

- **Overlay UI & Blocking:** Displayed as a modal dialog (`_legal_disclaimer_modal.html` and `legal_disclaimer.js`) or full-page view (`LegalDisclaimerView` at `/auth/legal-disclaimer/`), blocking interactions with background content until acknowledged.
- **Notice Contents:** Four explicit disclosure cards: Cryptographic Keyholder Liability, Neutral Conduit & Protocol Interface, Node Operator Policies (zero-tolerance CSAM & violence policy), and Open Source Ecosystem (GPLv3 / "as is").
- **Preference Persistence:** Includes a `"Show this legal disclaimer on next login"` checkbox checked by default (`true`). If unchecked and acknowledged, a POST to `/auth/legal-disclaimer/acknowledge/` sets `user.show_legal_disclaimer = False` and records `user.disclaimer_acknowledged_at` as an audit timestamp.
- **Routing Integrity:** Preserves the destination URL (including all OIDC `state`, `code`, and PKCE verifier exchanges) and performs navigation inline in the current window (`_self`). Fallbacks default to `IDP_WUN_URL`.

### 8. Passkey Authentication (WebAuthn)

Managed-tier identities authenticate with a **passkey as their primary
login factor**. The ceremonies are implemented server-side with the Python
`fido2` library (`auth_bridge/passkeys.py` engine + `views_passkeys.py`
endpoints). Standard Django password authentication is never consulted on
this path — the assertion itself is the credential, and on success the view
calls `django.contrib.auth.login(request, user,
backend="auth_bridge.backend.DIDAuthBackend")`, followed by
`evaluate_sovereign_admin_posture(user)`.

The Relying Party ID is derived from the hostname of `IDP_BASE_URL`; browser
origins must satisfy `fido2.rpid.verify_rp_id()` against it (HTTPS, or
`http://localhost` in dev).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/passkeys/register/begin/` | Session | Returns `{ceremony_id, publicKey: {challenge, rp, user, pubKeyCredParams, excludeCredentials, authenticatorSelection}}` |
| POST | `/auth/passkeys/register/complete/` | Session | Verifies attestation, persists `PasskeyCredential`; returns `{status: "registered", credential_id}` |
| POST | `/auth/passkeys/authenticate/begin/` | Anonymous | Discoverable-credential flow (no allow-list); returns `{ceremony_id, publicKey: {challenge, rpId, userVerification}}` |
| POST | `/auth/passkeys/authenticate/complete/` | Anonymous | Verifies assertion, logs the user in; returns `{status: "authenticated", did}` |

**Ceremony state:** each begin response carries a `ceremony_id`; the fido2
server state is cached under `passkey:reg:{id}` / `passkey:auth:{id}` with a
300-second TTL and single-use semantics (deleted on completion). Complete
calls must echo `ceremony_id` alongside the standard WebAuthn JSON response
(`id`, `rawId`, `type`, `response{...}`).

**Registration rules:**
- Requires an authenticated session; registration binds the credential to
  that account (`resident key` / discoverable credential required).
- Duplicate `credential_id` → `409 {"error": "credential_already_registered"}`.
- Invalid attestation (bad origin, RP hash, challenge, or format) →
  `400 {"error": "invalid_attestation"}`.

**Assertion rules (clone detection):**
1. `rawId` is looked up in `PasskeyCredential` before verification — unknown
   credentials are rejected with `400 {"error": "unknown_credential"}`.
2. fido2 verifies client data type, origin, RP ID hash, challenge and the
   ES256/EdDSA signature over `authenticatorData || SHA256(clientDataJSON)`.
3. Signature counter regression — if both stored and received counters are
   non-zero and `received <= stored`, the credential is treated as cloned:
   `400 {"error": "cloned_credential_detected"}`.
4. A returned `userHandle` must map to the credential owner's UUID, else
   `400 {"error": "user_handle_mismatch"}`.
5. On success `sign_count` and `last_used_at` are updated and the session is
   established via the DID backend.

### 9. Identity Graduation Protocol

Identity Graduation transitions a Level 1 Managed account to Level 2/3
Sovereign custody through a secure **export-and-purge** of the managed
Ed25519 key material held in HashiCorp Vault. Implementation lives in
`auth_bridge/views_graduation.py` with Vault access isolated behind
`auth_bridge/vault_client.py`.

**Vault layout (KV v2):** `secret/identity/{custodial_did}/ed25519` holding
`private_key_pem`, `public_key_pem`, `did`. Mount point configurable via
`IDP_VAULT_KV_MOUNT`.

#### Step 1 — Sealed Export

```
POST /api/v1/identity/graduate/export/
Body:  {"ephemeral_pubkey": "<hex-or-base64 X25519 public key>"}
Resp:  {"server_ephemeral_pub": "<hex>", "nonce": "<hex>", "ciphertext": "<hex>"}
```

Requires an authenticated session and a valid CSRF token. The private key
never crosses the transit boundary in plaintext:

1. Server reads the Ed25519 private key from Vault.
2. A fresh ephemeral X25519 keypair is generated per request.
3. `ECDH(server_ephemeral_priv × client_ephemeral_pub)` → shared secret.
4. `HKDF-SHA256(ikm=shared, salt=nonce, info="iyou-idp/graduation-export/v1")`
   → 32-byte wrapping key.
5. `AES-256-GCM(wrapping_key, nonce)` encrypts the 32-byte Ed25519 seed with
   the custodial DID as AAD.

iyou_home decrypts symmetrically: ECDH with its ephemeral secret against
`server_ephemeral_pub`, HKDF with the same salt/info, AESGCM open using
`did` as AAD.

#### Step 2 — Signed Receipt Confirmation

```
POST /api/v1/identity/graduate/confirm/
Body:  {"receipt": {"action": "graduate", "did": "did:web:iyou.me:user:{uuid}", "issued_at": <unix>},
        "signature": "<hex 64-byte Ed25519 signature>"}
Resp:  {"status": "graduated", "did": "...", "is_sovereign": true}
```

Verification pipeline (all failures return `400` and change nothing):
1. Session user must be authenticated and not already sovereign.
2. `receipt.did` must equal the session user's `custodial_did`.
3. `receipt.action` must be `"graduate"`.
4. `receipt.issued_at` must be within **600 seconds** of server time.
5. The Ed25519 signature over the **canonical receipt**
   (`json.dumps(receipt, sort_keys=True, separators=(",", ":"))`) must verify
   against the **public key stored in Vault** — proving custody of the
   exported key.

On success everything happens inside one `transaction.atomic()` block:

1. `user.is_sovereign = True`, `user.account_tier = "sovereign"` saved.
2. `vault_client.delete_identity_key(did)` shreds all versions + metadata at
   the Vault path.

Because the Vault deletion executes **inside** the transaction, any Vault
failure rolls the promotion back entirely (`502
{"error": "vault_shred_failed"}`, `is_sovereign` stays `False`, managed key
preserved).

#### Post-Graduation Front-Channel Lockout

`SovereignAuthorizeView.get()` checks `request.user.is_sovereign` **before**
issuing any authorization code and returns:

```json
{"error": "access_denied", "error_description": "Graduated sovereign identities must authenticate directly with their own DID."}
```

Graduated DIDs therefore can no longer mint IdP front-channel OIDC sessions;
satellites must verify the user's self-custodied DID directly. The OIDC
`sub` claim contract is unchanged — it remains the canonical
`custodial_did` via `custom_sub_generator`.

#### Graduation Error Codes

| Error | Status | Meaning |
|-------|--------|---------|
| `authentication_required` | 401 | No active session |
| `already_sovereign` | 400 | User already graduated |
| `malformed_json` / `malformed_payload` / `malformed_key_material` | 400 | Body structure or key encoding invalid |
| `receipt_did_mismatch` | 400 | Receipt DID ≠ session DID |
| `receipt_action_invalid` | 400 | Action ≠ `graduate` |
| `receipt_timestamp_missing` / `receipt_expired` | 400 | Stale or missing `issued_at` |
| `invalid_receipt_signature` | 400 | Signature fails verification |
| `managed_key_not_found` | 404 | No Vault secret at the identity path |
| `vault_unavailable` | 502 | Vault read failed |
| `vault_shred_failed` | 502 | Shred failed — promotion rolled back |

### Smart-Merge Pipeline (Anti-Sybil)

The `process_oauth_identity()` function in `auth_bridge/pipeline.py`
implements a **three-way account resolution** strategy that prevents
duplicate registrations while preserving existing sovereign identities:

| Condition | Action |
|-----------|--------|
| `FederatedIdentity` match exists | Return existing user (primary path) |
| No federated match, email matches existing `User` | Link provider to existing account (email-anchored merge) |
| No federated match, no email match | Create new user with `did:web:iyou.me:user:{uuid}` |

The pipeline never overwrites an existing `custodial_did`.  When a user
registers via GitHub and later logs in via Google with the same email, both
provider identities are linked to the same `User` record.

**Provider-specific profile extractors** in `views_oauth.py` handle the
differences between OAuth providers:
- **Google** — extracts `sub` and `email` from the JWT `id_token`
- **GitHub** — uses the `/user/emails` API endpoint for the primary verified
  email (the `/user` endpoint doesn't return email by default)
- **Apple** — extracts `sub` and `email` from the JWT `id_token`; name is
  parsed from the `name` claim object

### Authenticated Dashboard

When an already-logged-in user visits the IdP root (`/`) or `/auth/login/`
without an active OIDC flow, `LoginPageView.get()` renders
`authenticated_dashboard.html` instead of the login page.  The dashboard:

- Displays the user's DID.
- Provides an **"Enter iYou Home"** button linking to `IDP_WUN_URL` with
  `target="_blank" rel="noopener noreferrer"` so the satellite app opens
  in a new tab while the dashboard stays visible.
- Shows a disabled **iYou Mobile** placeholder.
- Offers a **Sign Out** link pointing to `/auth/logout/`.

If the `?next=` parameter IS present and contains OIDC authorization params
(`client_id`, `response_type`), the view redirects to the `next` URL so the
OIDC provider can issue an auth code directly (skipping the consent page for
already-authenticated users).

### Global Logout

An endpoint at `/auth/logout/` fully clears the IdP session:

```python
class GlobalLogoutView(View):
    def get(self, request):
        django_logout(request)
        next_page = request.GET.get('next', settings.IDP_WUN_URL + '/')
        return redirect(next_page)
```

Accepts an optional `?next=` parameter to control the post-logout redirect
(default: `IDP_WUN_URL + '/'` — WUN root).

## Authentication Flow [L339-434]

The login page is organised as three tabs, each implementing a different
authentication tier.  Tab switching is instant (client-side JS class toggling)
and never triggers a page reload.  A `?tab=<name>` query parameter or URL hash
persists the active tab across redirects.

### Tab 0 — Full Sovereignty (Challenge-Response Cycle)

1. User clicks "Request Challenge" → `POST /auth/challenge/`
2. Server generates UUID, stores in Redis with 300s TTL
3. JS receives `{challenge, expires_in}` and displays it
4. User signs the challenge with their DID wallet (or mock VP)
5. `POST /auth/verify/` with `{verifiable_presentation, challenge, next_url}`
6. Server validates challenge in Redis, calls `_get_rust_verify_vp()`, logs in user
7. Returns `{success, redirect_url, user}`
8. JS calls `onAuthSuccess(redirect_url)` → satellite in new tab, stays on IdP at `/`

### Tab 1 — Community Self-Signing (OOB Mobile Flow)

1. The tab fetches a challenge (`POST /auth/challenge/`) with the current
   `next_url` in the JSON body.
2. A QR code is rendered using the `qrcode` CDN library encoding the URI:
   `iyouauth://sign?ch=<challenge_id>&url=<origin>&next=<base64(next_url)>`
3. The mobile app scans the QR code, signs the challenge, and POSTs the VP
   to `{url}/auth/mobile-verify/`.
4. The browser polls `GET /auth/challenge-status/<challenge_id>/` every 1 s.
5. When the challenge is solved, the polling endpoint creates the user,
   calls `django.contrib.auth.login()`, generates the OIDC redirect, and
   returns `{solved: true, redirect_url: "..."}`.
6. The browser opens the redirect URL in a new tab and
   redirects the IdP tab to `/` (dual-window behaviour).

### Tab 2 — Managed Convenience (OAuth2)

- **OAuth buttons** for Google, Apple, and GitHub — each redirects to
  `GET /auth/oauth/initiate/<provider>/` which generates a state token,
  stores it in the session, and redirects to the provider's authorization
  endpoint.
- On callback (`GET /auth/oauth/callback/<provider>/`), the state is
  validated against the session, the authorization code is exchanged for
  tokens via back-channel POST, the provider profile is extracted, and
  the user is authenticated via the Smart-Merge pipeline.
- After successful OAuth login, the OIDC continuity flow resumes — the
  pending `next` URL (containing `/openid/authorize/` params) is used to
  generate an auth code and redirect back to the satellite, **skipping the
  consent page**.
- **Passkeys (WebAuthn)** — the server-side ceremonies are now **live** (see
  [§8 Passkey Authentication](#8-passkey-authentication-webauthn)):
  registration binds a credential to the account, assertion completes a
  fully passwordless login via `DIDAuthBackend`. Login-page button wiring
  for Tab 2 remains tracked on the roadmap.

### Satellite-App Redirect Safety [L378-396]

All three tiers share the same redirect mechanism.  The `redirect_url` is
derived from the `next_url` that was passed in.  When the caller is the OIDC
authorize flow, `next_url` contains the full
`/openid/authorize/?client_id=...&redirect_uri=...` query string.  The
`_build_oidc_redirect()` helper parses these params, directly generates an
OIDC authorization `Code`, and returns the client's
`redirect_uri?code=...&state=...` — **skipping the consent page entirely**.

```
verify → (302) client callback with code
```
Instead of the slower:
```
verify → (200) consent page → user clicks Allow → (302) client callback
```

### iYou Home Desktop Companion [L396-434]

The "Full Sovereignty" tab attempts a WebSocket connection to
`IDP_HOME_WS_URL` (default `wss://localhost:9001/`)
for native signing.  In local development override with `ws://localhost:9001`.
The wire protocol is a simple JSON request/response exchange:

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

1. **Mutex connection lock** — A `window.sovereignConnectionLock` state token
   (`"CONNECTING"` / `"OPEN"` / `"IDLE"`) is claimed *before* the
   `new WebSocket()` constructor runs, and is verified at the top of
   `tryConnectIYouHome()`.  Any duplicate call is blocked before any
   connection attempt begins, eliminating race conditions from rapid script
   re-evaluation.  A secondary `window.activeSovereignSocket.readyState` check
   acts as a fallback guard.

2. **Kill Switch** — A "Cancel & Use Manual Paste" button appears
   **immediately** when the linking UI shows.  Clicking it calls
   `socket.close()` and resets `sovereignConnectionLock` to `"IDLE"`.

3. **2-second force fallback** — If `socket.readyState !== WebSocket.OPEN`
   after 2 seconds, the socket is forcibly closed and the manual paste box
   appears.

4. **Version logging** — `console.log("LOGIN UI VERSION: 3.0.0")` at script
   top confirms the browser isn't serving a stale cached copy.

5. **Cache busting** — `<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">` in `<head>` forces re-fetch on every navigation.

## API Endpoints [L434-467]

### Authentication Endpoints [L436-449]

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Tiered login portal (same as `/auth/login/`) |
| GET | `/auth/login/` | Compact login page (OIDC redirect target) |
| POST | `/auth/challenge/` | Generates new challenge (300s TTL) — JSON dict in Redis; returns `{challenge, expires_in, stored}` |
| GET | `/auth/challenge/` | Health check |
| POST | `/auth/verify/` | Verifies VP (desktop WebSocket path), logs in, returns redirect |
| POST | `/auth/mobile-verify/` | Verifies VP (mobile OOB path), marks challenge `solved` |
| GET | `/auth/challenge-status/<uuid>/` | Polling — returns `{solved, redirect_url}` when mobile has signed |
| POST | `/auth/managed-login/` | Scaffold — accepts email+password, returns Django messages |
| GET | `/auth/logout/` | Global logout — clears IdP session, redirects to WUN (or `?next=`) |
| GET/POST | `/auth/oauth/initiate/<provider>/` | Tier 1 OAuth — generates state, redirects to provider |
| GET/POST | `/auth/oauth/callback/<provider>/` | Tier 1 OAuth — validates state, exchanges code, authenticates |
| POST | `/auth/passkeys/register/begin/` | Passkey registration ceremony start (session required) |
| POST | `/auth/passkeys/register/complete/` | Passkey attestation verification + credential persistence |
| POST | `/auth/passkeys/authenticate/begin/` | Passkey assertion ceremony start (discoverable credentials) |
| POST | `/auth/passkeys/authenticate/complete/` | Passkey assertion verification + passwordless login |

### Identity Graduation Endpoints

The export-and-shred protocol that graduates a Level 1 Managed identity to
Sovereign custody. Full protocol specification in
[§9 Identity Graduation Protocol](#9-identity-graduation-protocol).

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity/graduate/export/` | Seals the managed Ed25519 private seed to a client ephemeral X25519 key (session + CSRF required) |
| POST | `/api/v1/identity/graduate/confirm/` | Verifies Ed25519 receipt, atomically promotes `is_sovereign` and shreds the Vault key (session + CSRF required) |

### Admin DID Endpoints [L449-457]

Admin access at `iyou.me/admin` is governed by sovereign public key mapping,
not legacy relational database passwords.  Set the `ADMIN_DID` environment
variable to the master `did:key:` multibase URI — every authentication
ingress (`verify_signature`, `check_challenge_status`, and
`custom_admin_verify`) checks the authenticated user's DID against
`ADMIN_DID` and, on match, atomically elevates to `is_staff=True`,
`is_superuser=True` with an unusable password.  No manual `createsuperuser`
invocation is required for the sovereign admin DID.

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/auth/admin/did-login/` | DID-based admin login form |
| POST | `/auth/admin/did-verify/` | Verifies admin DID challenge (triggers sovereign posture evaluation) |
| GET | `/auth/admin/did-dashboard/` | Admin dashboard (post-login) |

### OIDC Endpoints [L457-467]

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/openid/authorize/` | OIDC authorization endpoint |
| POST | `/openid/token/` | Token exchange endpoint |
| GET | `/openid/userinfo/` | Userinfo endpoint |
| GET | `/openid/.well-known/openid-configuration/` | OIDC discovery document |
| GET | `/openid/jwks/` | JWKS endpoint |
| GET/POST | `/openid/introspect/` | Token introspection |
| GET/POST | `/openid/end-session/` | End session |

### OAuth2 Provider Endpoints [L467-480]

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/oauth/authorize/` | OAuth2 authorization endpoint |
| POST | `/oauth/token/` | Token exchange endpoint |
| POST | `/oauth/revoke_token/` | Token revocation |
| GET | `/oauth/userinfo/` | UserInfo endpoint |
| GET | `/oauth/.well-known/openid-configuration/` | OAuth2 discovery |
| GET | `/oauth/.well-known/jwks.json` | JWKS endpoint (JSON) |

### Complete URL Map

All registered URL patterns (as seen by `django.urls`):

```
/                               → LoginPageView (login portal)
/auth/login/                    → LoginPageView (same template)
/auth/challenge/                → ChallengeView
/auth/verify/                   → verify_signature
/auth/mobile-verify/            → mobile_verify_signature
/auth/challenge-status/<id>/    → check_challenge_status
/auth/managed-login/            → managed_login
/auth/logout/                   → GlobalLogoutView
/auth/admin/did-login/          → custom_admin_login
/auth/admin/did-verify/         → custom_admin_verify
/auth/admin/did-dashboard/      → custom_admin_dashboard
/auth/oauth/initiate/<provider>/ → OAuthInitiateView (Google/Apple/GitHub)
/auth/oauth/callback/<provider>/ → OAuthCallbackView (Google/Apple/GitHub)
/auth/passkeys/register/begin/     → passkey_register_begin
/auth/passkeys/register/complete/  → passkey_register_complete
/auth/passkeys/authenticate/begin/ → passkey_authenticate_begin
/auth/passkeys/authenticate/complete/ → passkey_authenticate_complete
/api/v1/identity/graduate/export/  → graduate_export
/api/v1/identity/graduate/confirm/ → graduate_confirm
/openid/authorize/              → OIDC Authorization Endpoint *
/openid/token/                  → Token exchange
/openid/userinfo/               → UserInfo
/openid/jwks/                   → JWKS
/openid/.well-known/openid-configuration/  → OIDC Discovery
/openid/introspect/             → Token introspection
/openid/end-session/            → End session
/oauth/authorize/               → OAuth2 Authorization Endpoint
/oauth/token/                   → Token exchange
/oauth/revoke_token/            → Token revocation
/oauth/userinfo/                → UserInfo
/oauth/.well-known/openid-configuration/  → OAuth2 discovery
/oauth/.well-known/jwks.json    → JWKS (JSON)
/admin/                         → Django admin
```

> The Relying Party (e.g. WUN) must redirect users to **`/openid/authorize/`**
> with standard OIDC query parameters (`client_id`, `response_type=code`,
> `redirect_uri`, `scope=openid`, `state`).  Using `/oauth/authorize/` or
> any `/auth/...` path will return a 404 or unexpected behaviour.

### Download Modals (Desktop & Mobile CTAs)

The login page offers two download overlay modals, each with a distinct CTA
placement strategy to avoid page-layout shift:

| Modal | Trigger | Opens On | Placement |
|-------|---------|----------|-----------|
| **Desktop** (`_download_modal.html`) | `.open-download-modal` / `#download-modal-btn` | Inline in Tab 0; global below card on Tabs 1 & 2 | **Tab 0:** inside the card; **Tabs 1-2:** below the card |
| **Mobile** (`_mobile_download_modal.html`) | `.open-mobile-download-modal` / `#mobile-download-modal-btn` | Same as desktop | Same as desktop |

**Desktop modal** (`_download_modal.html`):
- **OS auto-detection** — `download_modal.js` inspects
  `navigator.userAgentData.platform` (or `navigator.userAgent` as fallback) and
  highlights the detected OS group with an indigo ring + "Recommended" badge.
  The detected platform banner slides in at the top of the modal.  Three OS
  groups are available:

  | Group | Variants |
  |-------|----------|
  | Windows | GUI installer, portable ZIP |
  | macOS   | Intel DMG, Apple Silicon DMG |
  | Linux   | AppImage, deb package |

  Each variant lists three download sources:
  1. **GitHub Releases** (`/releases/latest/download/…`)
  2. **Magnet torrent link** (clicked → copies to clipboard via `navigator.clipboard.writeText`)
  3. **IPFS gateway** (placeholder)

- The Linux section header uses a static Tux SVG (`auth_bridge/static/auth_bridge/img/Tux.svg`).

**Mobile download hub** (`_mobile_download_modal.html`):

- **Bimodal distribution model** — two platform tabs (iOS / Android) with
  auto-detection via `navigator.userAgent`; detected platform gets an indigo
  ring + "Recommended" banner.
- Two tracks per platform:
  - **Managed Track** — App Store / Play Store deep-link targets with
    "Coming Soon" badge (`cursor-not-allowed`).
  - **Sovereign Track** — F-Droid repository URL (clipboard copy) + direct
    `.apk` download for Android; TestFlight placeholder for iOS.
  Explanatory copy below sovereign links notes that direct payloads use
  decentralized file layers for privacy and bandwidth preservation.
- `mobile_download_modal.js` — vanilla JS IIFE with document-level event
  delegation (catches `.open-mobile-download-modal` and
  `#mobile-download-modal-btn` from any template), platform detection, tab
  switching, clipboard helper, Escape/backdrop dismiss, MutationObserver.

**CTA placement logic (JavaScript in `login.html`):**
- Tab 0 (Full Sovereignty) has inline download buttons inside its own partial
  (`_tab_sovereign.html`) — the global `#global-download-ctas` footer is
  hidden when Tab 0 is active.
- Tab 1 (Community Self-Signing) and Tab 2 (Managed Convenience) hide the
  inline footer and rely on `#global-download-ctas` below the login card.
- The `activateTab()` function in `login.html` toggles `hidden` on
  `#global-download-ctas` based on the active tab index.
- Both `authenticated_dashboard.html` and `_tab_sovereign.html` also mount
  `.open-mobile-download-modal` buttons so authenticated and sovereignty-
  tab users can reach the mobile modal.

## Development Workflow [L467-521]

### Adding New Features [L469-477]

1. Write a test first in `auth_bridge/tests/` (package: legacy flows in
   `__init__.py`, graduation in `test_graduation.py`, passkeys in `test_passkeys.py`)
2. Implement the feature
3. Run `uv run python manage.py test auth_bridge -v2`
4. Run `uv run ruff check auth_bridge/`
5. Run `uv run python manage.py check`

### Testing [L477-500]

```bash
# Run all auth tests
uv run python manage.py test auth_bridge -v2

# Run a single test
uv run python manage.py test auth_bridge.tests.ChallengeResponseCycleTest.test_full_cycle_creates_session -v2
```

The test suite creates Ed25519 keys, builds signed Verifiable Credentials
and Presentations, exercises the full challenge-response cycle, and
verifies OIDC redirects (both classic and direct-callback). The suite now
also covers the passkey ceremonies (a software ES256 authenticator drives
real fido2 verification end-to-end) and the Identity Graduation protocol
(sealed export round-trip, transactional Vault rollback, malicious receipt
rejection) — 42 tests total.

Key tests:
- `test_full_cycle_creates_session` — end-to-end: challenge → VP → verify → session
- `test_full_graduation_loop` — export → unseal → signed receipt → `is_sovereign` + Vault shredded
- `test_vault_shred_failure_rolls_back_sovereign_flip` — Vault outage mid-shred rolls back the promotion
- `test_signature_by_foreign_key_rejected` — spoofed receipt changes nothing anywhere
- `test_passwordless_login_via_discoverable_assertion` — usernameless passkey login establishes a session
- `test_cloned_credential_counter_regression_detected` — sign-count regression rejected
- `test_next_url_roundtrip` — non-OIDC next_url is echoed back as redirect_url
- `test_missing_fields_returns_400` — empty body returns 400
- `test_expired_challenge_returns_404` — expired/missing challenge returns 400
- `test_authorize_returns_code_for_authenticated_user` — classic OIDC authorize flow
- `test_verify_redirects_directly_to_client` — direct-callback: verify returns client URI with code
- `test_jwks_endpoint_returns_valid_key` — `/openid/jwks/` exposes at least one RSA key
- `test_build_oidc_redirect_*` — OIDC redirect helper with various next_url formats

### Debugging [L500-521]

- **WebSocket not connecting?** Open browser dev tools console.  Look for:
  - `"LOGIN UI VERSION: 3.0.0"` — confirms fresh JS
  - `"WS: Concurrency lock claimed. Initializing secure socket..."` — mutex
    guard passed, connection starting
  - `"Guard: ... Suppressing duplicate call."` — duplicate connection blocked
  - `"WS: Socket Created"` — WebSocket constructor succeeded
  - `"WS: Connection successfully opened and locked."` — `onopen` fired,
    lock set to `"OPEN"`
  - `"WS: Connection Opened"` — handshake completed, UI activated
  - `"WS: Socket Error"` — browser blocked or server not listening
  - `"WS: Force-fallback timer expired"` — 2s timeout was reached
  - `"Critical error allocating socket:"` — `new WebSocket()` threw
- **Signature not received?** Look for `"WS: Message Received:"` in the
  console.  If it fires with a JSON payload, the browser got the data.  If
  not, the network is swallowing the message or `sovereignConnectionLock` is
  blocking the handshake.
- **OOB flow not completing?** Check:
  - The QR code rendered (inspect the `#qrcode` div in dev tools)
  - The browser logs `"Scan with your mobile app"` — challenge fetch succeeded
  - The network tab shows `GET /auth/challenge-status/<uuid>/` polling every 1s
  - When the mobile app POSTs, the poll response changes to `{solved: true, redirect_url: "..."}`
- **QR code shows scrambled vertical lines?** Upgrade the QR library — the
  old `qrcodejs` v1.0.0 produces canvas rendering artifacts on modern browsers.
  Switch the CDN script to `qrcode` v1.5.1+ and use `QRCode.toCanvas()`
  instead of `new QRCode()` (see `login.html`).
- **Static files (JS/CSS/images) returning 404?** Verify:
  1. WhiteNoise middleware is present in `MIDDLEWARE` (see Static File Serving section).
  2. `collectstatic --noinput` ran during the Docker build stage (check builder logs for the `collectstatic` step).
  3. The file exists in `STATIC_ROOT` — `ls staticfiles/auth_bridge/js/` inside the container.
  4. If using `runserver` locally, `IDP_DEBUG=True` is required (WhiteNoise is bypassed in DEBUG mode for the dev server).
- **Server error on verify?** Look for `"VERIFY RESPONSE FULL:"` in the
  console — the full JSON response is logged.
- **Rust bridge not found?** Check the console for the `"="` banner with
  `sys.path` and the probe path.  Re-run `maturin develop`.

## Error Handling [L521-554]

### Common Errors & Solutions [L523-538]

| Error | Cause | Fix |
|-------|-------|-----|
| `no keys in database` | `creatersakey` was never run | Run `uv run python manage.py creatersakey` |
| `Rust Crypto Bridge not found` | `src/` not on `sys.path` or `.so` missing | Run `maturin develop` or check `sys.path` in `settings.py` |
| `Challenge expired` | Challenge TTL (300s) exceeded | Request a new challenge |
| `Missing required fields` | VP or challenge not in POST body | Check JS `submitVP()` sends all fields |
| `Challenge already solved` | Mobile replayed a solved challenge | Generate a new QR code |
| `Challenge not found or expired` (mobile-verify) | Polling after TTL or bad UUID | Refresh tab to get a fresh challenge |
| 500 on POST to `/auth/verify/` | import or bridge crash | Check console for `VERIFY RESPONSE FULL` or server traceback |
| WebSocket never opens | iyou-home not running, browser PNA blocking, or mutex lock preventing duplicate | Check console for `Guard:` or `Critical error` messages; use manual paste |
| QR code not appearing or scrambled | `qrcode` CDN not loaded or challenge fetch failed | Check network tab for CDN or `/auth/challenge/` errors |
| `data.redirect_url` not redirecting | `data.success` falsy or `redirect_url` missing | Check `VERIFY RESPONSE FULL` in console |
| Satellite app not opening in new tab | Browser popup blocker | `reserveAuthPopup()` must fire synchronously in click handler; check console for `"Popup blocked"` warning; the 500 ms fallback link appears below the spinner |
| OAuth callback returns 403 | State mismatch or expired | Ensure cookies are enabled; state TTL is 300s; check session middleware |
| OAuth callback returns 502 | Token exchange failed | Verify provider client ID/secret in env vars; check provider's token endpoint |
| OAuth callback returns 400 (profile incomplete) | Provider returned missing email or ID | Check provider OAuth scopes; GitHub requires `user:email` scope |
| `managed_key_not_found` (404, graduation) | No Vault secret at `identity/{did}/ed25519` | Seed the key material into Vault before graduating |
| `invalid_receipt_signature` (400, graduation) | Receipt signed by a key other than the exported one | Re-export the key and sign the receipt with the recovered identity |
| `vault_shred_failed` (502, graduation) | Vault unreachable during shred — promotion rolled back | Restore Vault connectivity; retry confirm (DB state unchanged, key intact) |
| `cloned_credential_detected` (400, passkey) | Assertion counter regressed vs stored value | Re-register the passkey; investigate possible credential duplication |
| `unknown_or_expired_ceremony` (400, passkey) | Ceremony TTL (300s) exceeded or ceremony already consumed | Restart the begin/complete cycle |

### Error Response Format [L538-554]

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
| 403 | User account disabled / sovereign front-channel lockout |
| 404 | Managed key material not present in Vault (graduation export/confirm) |
| 500 | Internal error (bridge import failure, unexpected exception) |
| 502 | Vault unavailable or shred failed (graduation — DB rolled back) |
| — | `stored: false` in challenge response | Redis/cache unavailable — challenge not persisted; retry or fall back to desktop WebSocket flow |

## Deployment [L554-619]

### Production Checklist [L556-570]

- [ ] Set `IDP_SECRET_KEY` to a strong random value
- [ ] Set `IDP_BASE_URL` to the public-facing URL (e.g. `https://iyou.me`)
- [ ] Set `IDP_WUN_URL` to the satellite app URL (e.g. `https://wun.iyou.me`)
- [ ] Set `IDP_HOME_URL` and `IDP_HOME_WS_URL` for the desktop companion service
- [ ] Set `IDP_DEBUG=False`
- [ ] Set `IDP_ALLOWED_HOSTS` to the domain(s) (comma-separated)
- [ ] Set `IDP_CSRF_TRUSTED_ORIGINS` to match the public origin(s)
- [ ] Set `IDP_CORS_ALLOWED_ORIGINS` to the satellite app origin(s) (or empty if all on same domain)
- [ ] Set `DATABASE_URL` to a production PostgreSQL connection string
- [ ] Configure a real Redis instance via `REDIS_URL`
- [ ] Set `ADMIN_DID` to the sovereign master `did:key` URI for passwordless superuser elevation at `/admin/`
- [ ] Set `IDP_VAULT_ADDR` and `IDP_VAULT_TOKEN` to the production Vault instance (identity graduation requires it)
- [ ] Set `OAUTH_GOOGLE_CLIENT_ID` and `OAUTH_GOOGLE_CLIENT_SECRET` (or leave empty to disable Google)
- [ ] Set `OAUTH_APPLE_CLIENT_ID` and `OAUTH_APPLE_CLIENT_SECRET` (or leave empty to disable Apple)
- [ ] Set `OAUTH_GITHUB_CLIENT_ID` and `OAUTH_GITHUB_CLIENT_SECRET` (or leave empty to disable GitHub)
- [ ] Deploy with `docker build -t iyou-idp .` (Rust is compiled in the builder stage)
- [ ] Set up the Traefik/nginx ingress proxy with HTTPS termination
- [ ] The entrypoint uses Gunicorn on `:8000` — no additional WSGI server needed

### Docker Deployment [L570-619]

The project ships a production-ready multi-stage `Dockerfile`:

```dockerfile
# Stage 1 (builder):   python:3.12-slim + Rust toolchain + uv + maturin
#   - Installs Python deps via uv sync --no-dev
#   - Installs maturin, compiles _crypto.abi3.so via maturin build --release
#   - Installs the compiled wheel, removes maturin
#   - Runs collectstatic --noinput
# Stage 2 (runner):    python:3.12-slim
#   - Copies .venv, _crypto.abi3.so, staticfiles, and Django source from builder
#   - Non-root USER app, HEALTHCHECK on :8000/auth/challenge/
#   - Runs docker-entrypoint.sh (migrate + gunicorn)
```

**Build and run:**
```bash
docker build -t iyou-idp:latest .
docker run -d --name iyou-idp \
  -p 8000:8000 \
  -e IDP_SECRET_KEY="<generated-secret>" \
  -e IDP_BASE_URL="https://iyou.me" \
  -e IDP_WUN_URL="https://wun.iyou.me" \
  -e IDP_HOME_URL="http://iyou-home.user.svc.cluster.local:9000" \
  -e IDP_HOME_WS_URL="wss://localhost:9001" \
  -e IDP_DEBUG=False \
  -e IDP_ALLOWED_HOSTS="iyou.me" \
  -e IDP_CSRF_TRUSTED_ORIGINS="https://iyou.me" \
  -e IDP_CORS_ALLOWED_ORIGINS="https://wun.iyou.me" \
  -e DATABASE_URL="postgres://user:pass@db:5432/iyou_idp" \
  -e REDIS_URL="redis://redis:6379/1" \
  -e ADMIN_DID="did:key:z6MknA51zaT8CpPx3qvAoqHDiXpSZnp4EqpQnw8FKbnbR5YV" \
  -e OAUTH_GOOGLE_CLIENT_ID="" \
  -e OAUTH_GOOGLE_CLIENT_SECRET="" \
  -e OAUTH_GITHUB_CLIENT_ID="" \
  -e OAUTH_GITHUB_CLIENT_SECRET="" \
  -e OAUTH_APPLE_CLIENT_ID="" \
  -e OAUTH_APPLE_CLIENT_SECRET="" \
  iyou-idp:latest
```

**Environment variable reference:**

| Variable | Type | Default | Description |
|---|---|---|---|
| `IDP_SECRET_KEY` | `str` | (dev fallback) | Django secret key — required in production |
| `IDP_BASE_URL` | `str` | `http://iyou-idp.identity.svc.cluster.local:8000` | Public-facing base URL for OIDC endpoints |
| `IDP_WUN_URL` | `str` | `http://iyou-wun.satellite.svc.cluster.local:8001` | Satellite app URL — opened in new tab after login |
| `IDP_HOME_URL` | `str` | `http://iyou-home.user.svc.cluster.local:9000` | Desktop home app URL |
| `IDP_HOME_WS_URL` | `str` | `wss://localhost:9001/` | WebSocket URL for native desktop signing handshake |
| `IDP_DEBUG` | `bool` | `False` | Enable debug mode (dev only) |
| `IDP_ALLOWED_HOSTS` | `list` | `['iyou-idp.identity.svc.cluster.local', 'iyou-idp', 'localhost']` | Comma-separated allowed host/domain list |
| `IDP_CSRF_TRUSTED_ORIGINS` | `list` | `['http://iyou-idp.identity.svc.cluster.local:8000']` | Origins allowed to POST CSRF-protected forms |
| `IDP_CORS_ALLOWED_ORIGINS` | `list` | `[]` | Origins allowed for CORS (satellite app domains) |
| `DATABASE_URL` | `str` | `sqlite:///db.sqlite3` | Database connection string (use PostgreSQL in production) |
| `REDIS_URL` | `str` | `redis://iyou-redis-master.identity.svc.cluster.local:6379/1` | Redis connection for challenge-response caching |
| `ADMIN_DID` | `str` | `did:key:z6MknA51zaT8CpPx3qvAoqHDiXpSZnp4EqpQnw8FKbnbR5YV` | Sovereign master DID — authenticating as this DID auto-elevates to staff+superuser |
| `IDP_VAULT_ADDR` | `str` | `http://127.0.0.1:8200` | HashiCorp Vault address for managed-identity key custody |
| `IDP_VAULT_TOKEN` | `str` | `""` | Vault auth token (must hold KV v2 read/create/delete on the identity mount) |
| `IDP_VAULT_KV_MOUNT` | `str` | `secret` | KV v2 mount holding identity key material at `identity/{custodial_did}/ed25519` |
| `OAUTH_GOOGLE_CLIENT_ID` | `str` | `""` | Google OAuth2 client ID (empty = provider disabled) |
| `OAUTH_GOOGLE_CLIENT_SECRET` | `str` | `""` | Google OAuth2 client secret |
| `OAUTH_APPLE_CLIENT_ID` | `str` | `""` | Apple Sign In service ID |
| `OAUTH_APPLE_CLIENT_SECRET` | `str` | `""` | Apple Sign In client secret (JWT) |
| `OAUTH_GITHUB_CLIENT_ID` | `str` | `""` | GitHub OAuth App client ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | `str` | `""` | GitHub OAuth App client secret |

When `IDP_DEBUG=False`, the following are automatically enabled:
- `SECURE_PROXY_SSL_HEADER` — trusts `X-Forwarded-Proto: https` from Traefik/nginx
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`
- Cookie names are isolated to `idp_sessionid` / `idp_csrftoken` to prevent domain collisions on shared loopback.

### Static File Serving (WhiteNoise)

Static assets (JS, CSS, images) are served at runtime by **WhiteNoise**, not
Django's development server.  Configuration in `config/settings.py`:

```python
INSTALLED_APPS = [
    ...
    'django.contrib.staticfiles',   # (already present)
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',   # <-- added
    ...
]

STORAGES = {
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedStaticFilesStorage',
    },
}
```

`CompressedStaticFilesStorage` serves pre-compressed `.gz` variants when
available and falls back to uncompressed files — no manifest-hash lookup, so
dynamically referenced assets (e.g. `Tux.svg`) never cause a 404.

**Build-time collection:** `collectstatic --noinput` runs during the Docker
builder stage (not at container start), so the `staticfiles/` directory is
baked into the image layer.  The entrypoint only runs `migrate` + `gunicorn`.

To verify assets are reachable after deployment:
```bash
curl -sI https://iyou.me/static/auth_bridge/js/download_modal.js | head -5
# Expected: 200 OK, Content-Type: application/javascript
```

## Security Considerations [L619-634]

### Best Practices [L621-634]

- Challenges are single-use (deleted from Redis after verification)
- Challenge TTL is 300 seconds (limited window for replay)
- Challenge replay is prevented — `mobile_verify_signature` returns 400 if
  `status` is already `solved`
- **Three-tier verification pipeline**: Python Ed25519 (primary) → Rust `verify_vp`
  (secondary) → emergency bypass (last resort, logged).  No single point of
  cryptographic failure.
- **Bypass audit trail**: every emergency-bypass acceptance logs the remote IP,
  the holder DID, the challenge prefix, and a timestamp — admins can detect
  and investigate abuse.
- **OAuth state validation**: Tier 1 OAuth flows use `secrets.compare_digest()`
  to validate the `state` parameter against the session-stored value, preventing
  CSRF attacks on the callback endpoint.  State tokens are high-entropy
  (`secrets.token_urlsafe(32)`) with a 300-second TTL.
- **Smart-Merge anti-Sybil**: the `process_oauth_identity()` pipeline prevents
  duplicate account creation by anchoring to verified email addresses.  A user
  who registers via GitHub and later logs in via Google with the same email
  gets both providers linked to a single `User` record.
- WebSocket connection targets `IDP_HOME_WS_URL` (defaults to
  `wss://localhost:9001/`); override with `ws://localhost:9001` for local dev.
  In-cluster the companion service URL is set via environment variable.
  No remote attack surface is exposed.
- OIDC authorization codes are generated by the provider's standard `create_code()` utility
- `@csrf_exempt` on `verify_signature` and `mobile_verify_signature` is safe
  because both endpoints have no session side-effects (auth is purely cryptographic)
- The `next_url` is validated against the OIDC client's registered `redirect_uris` before code generation
- **Passkey ceremonies are origin-bound** — fido2 verifies client data type,
  origin, RP ID hash and challenge on every ceremony, so the `@csrf_exempt`
  passkey endpoints cannot be replayed cross-site; assertion signatures cover
  the challenge issued seconds earlier
- **Passkey clone detection** — signature counters are enforced: a non-zero
  assertion counter that does not advance past the stored value rejects the
  credential as potentially cloned
- **Graduation export is sealed end-to-end** — the managed private seed is
  encrypted to a per-request ephemeral X25519 keypair (ECDH → HKDF-SHA256 →
  AES-256-GCM, DID as AAD) and never transits in plaintext; the server keeps
  no record of the wrapping key
- **Graduation is all-or-nothing** — the sovereign promotion and the Vault
  shred run inside a single database transaction; a Vault outage rolls back
  the promotion instead of leaving a sovereign user with a still-custodied key
- **Graduation endpoints are CSRF-enforced** (`csrf_protect`) because they
  mutate state under an authenticated browser session — unlike the
  side-effect-free crypto endpoints
- **Receipts are single-purpose and fresh** — the Ed25519 receipt must be
  signed by the exported key (verified against the Vault-stored public key)
  within a 600-second window, and only an un-graduated user can confirm
- **Sovereign lockout** — graduated DIDs are blocked from front-channel OIDC
  code issuance at `SovereignAuthorizeView` before any token machinery runs

## Troubleshooting [L634-675]

### Rust-Python Bridge Issues [L636-652]

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

**Serialisation mismatch history:**

The Python Ed25519 primary path was added after weeks of debugging where
Rust `verify_vp` failed for all 6 canonical VP serialisation variants even
though the same VP payload was verified correctly by Python
`cryptography.hazmat.primitives.asymmetric.ed25519`.  The root cause was
**not** `serde_json` `preserve_order` (which was confirmed enabled in both
`Cargo.toml` files via `indexmap` in `Cargo.lock`), but **code drift**
between the two `did_rust` submodule copies (`iyou_idp` at `d2130ae`,
`iyou_home` at `f982010` — one unpushed commit ahead).  Now that both are
pinned to `cb3deb0`, the Rust path should be re-testable.

If new serialisation issues arise, add diagnostic hex-dump logging to
compare Python `json.dumps(vp_payload_bytes.hex())` against Rust
`serde_json::to_vec(&payload_value)` output for the same input.

### Submodule Issues [L652-659]

**Submodule Alignment Rule (critical):**

The `did_rust` crate exists as a **git submodule in two parent repos**:

| Parent | Path | Remote |
|--------|------|--------|
| `iyou_idp` | `crates/did_rust/` | `ssh://iyou@qnap:/share/homes/iyou/repos/did_rust.git` |
| `iyou_home` | `libs/did_rust/` | `ssh://iyou@qnap:/share/homes/iyou/repos/did_rust.git` |

Both **must point to the same commit** at all times.  If they diverge, the
FFI bridge (`_crypto.abi3.so`) compiled by `iyou_idp` will use different
serialisation logic than the `iyou_home` binary that signed the VP, causing
signature verification to fail despite both having `serde_json` with
`preserve_order` enabled.

Checkout / update command:
```bash
git submodule update --init --recursive
```

**Verification:** compare commit hashes:
```bash
git -C crates/did_rust rev-parse HEAD
git -C ../iyou_home/libs/did_rust rev-parse HEAD
```

**When pushing a `did_rust` change:**
1. Push from inside the submodule
2. Commit the new submodule pointer in **both** parent repos
3. Push both parent repos to all remotes (`pushall`)

The directory was **renamed from `crates/rust-did/` to `crates/did_rust/`**
on 2026-05-28 to match the crate name and the `iyou_home` path.  If you
see stale references to `crates/rust-did`, run:
```bash
git submodule deinit crates/rust-did
git rm --cached crates/rust-did
git submodule add <url> crates/did_rust
git mv .git/modules/crates/rust-did .git/modules/crates/did_rust
```

### OIDC Configuration Issues [L659-675]

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

**Symptom:** Relying Party gets 404 when redirecting to the IdP

The Relying Party must redirect the user's browser to
**`/openid/authorize/`** — not `/oauth/authorize/`, `/auth/login/`,
or any other path.  Common mistakes:

| Wrong URL | Correct URL |
|-----------|-------------|
| `http://127.0.0.1:8000/auth/login/?client_id=...` | `http://127.0.0.1:8000/openid/authorize/?client_id=...` |
| `http://127.0.0.1:8000/oauth/authorize/?client_id=...` | `http://127.0.0.1:8000/openid/authorize/?client_id=...` |
| `http://127.0.0.1:8000/openid/authorize?client_id=...` (no trailing slash) | `http://127.0.0.1:8000/openid/authorize/?client_id=...` (trailing slash) |

If the Relying Party uses OIDC discovery, the `authorization_endpoint` in
`http://127.0.0.1:8000/openid/.well-known/openid-configuration/` provides
the canonical URL.

**Symptom:** OAuth callback returns 403 "Invalid or expired OAuth state"

The OAuth state parameter is stored in the session and must match the value
returned by the provider.  Common causes:
- Session cookie was not sent (browser blocking third-party cookies)
- State expired (TTL is 300 seconds)
- Session middleware is not in `MIDDLEWARE` list

Check that `SESSION_ENGINE` is configured and `django.contrib.sessions` is
in `INSTALLED_APPS`.

## Roadmap [L675-694]

### Short-term Goals [L677-685]

- ✅ **Cryptographic structural redundancy** — Python Ed25519 primary path +
  Rust `verify_vp` secondary + emergency bypass safety net (2026-05-28)
- ✅ **Submodule alignment** — `crates/rust-did` renamed to `crates/did_rust`,
  both copies pinned to same commit, alignment rule documented (2026-05-28)
- ✅ **Multi-auth identity vault** — UUID PK, email-as-USERNAME_FIELD,
  `custodial_did` field, `FederatedIdentity` link table, Smart-Merge pipeline
  (2026-07-18)
- ✅ **Tier 1 OAuth inbound** — Google/Apple/GitHub initiation + callback
  views with state validation, back-channel token exchange, profile
  extraction, and OIDC continuity (2026-07-18)
- ✅ **Passkey (WebAuthn) engine + Identity Graduation protocol** — server-side
  passkey registration/assertion with clone detection; sealed export, signed
  receipt confirmation and transactional Vault shredding; sovereign
  front-channel lockout (2026-08-23)
- ⬜ Add OIDC `prompt=login` support to force re-authentication
- ⬜ Add PKCE (S256) support in the direct-callback path
- ⬜ Wire the Tab 2 login page UI to the live passkey endpoints

### Long-term Goals [L685-694]

- ✅ **OOB mobile auth** — QR-code flow for iyou_mobile (Level 2, Tab 1)
- ✅ **Root login portal** — Tiered login served directly at `/` (no landing page hero)
- 🔲 Support multiple DID methods (did:web, did:ethr, did:sol)
- 🔲 Replace the current polling-based iyou-home handshake with a push model
- 🔲 Add a self-service admin UI for OIDC client registration
- 🔲 Performance testing under load (concurrent DID verifications)
- 🔲 CI/CD pipeline with automated Rust bridge builds for Linux and macOS
