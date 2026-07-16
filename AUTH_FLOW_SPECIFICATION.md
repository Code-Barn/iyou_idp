# iyou_idp Authentication Flow — Authoritative Specification

This document is the single source of truth for how authentication works in the
iYou ecosystem. Every satellite relying party **must** conform to the flows and
contracts defined here.

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         iyou_idp (this app)                     │
│                                                                 │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │  Challenge   │   │   DID Auth   │   │   OIDC Provider      │  │
│  │  Service     │──▶│   Verify     │──▶│   (code + token)     │  │
│  │  (Redis)     │   │  (Ed25519)   │   │   (RSA-signed JWTs)  │  │
│  └─────────────┘   └──────────────┘   └──────────────────────┘  │
│         ▲                  ▲                       │             │
│         │                  │                       ▼             │
│    Desktop JS         Rust _crypto          Satellite Apps      │
│    Mobile App         Bridge + Python       (OIDC Clients)      │
└─────────────────────────────────────────────────────────────────┘
```

**Key invariant:** The IDP is the **only** entity that issues sessions and OIDC
tokens. Satellites never validate DID signatures directly — they receive
standard OIDC authorization codes and exchange them for signed JWTs.

---

## 2. The Three-Tier Auth Spectrum

| Tier | Name | Method | Used By |
|------|------|--------|---------|
| 3 | Full Sovereignty | Desktop WebSocket (`iyou-home`) + manual VP paste | Power users, admin |
| 2 | Community Self-Signing | OOB QR-code flow with mobile DID wallet | General users |
| 1 | Managed Convenience | OAuth providers + email/password | Scaffold (not wired) |

All tiers converge at the same point: `POST /auth/verify/` or
`GET /auth/challenge-status/<id>/` → `login()` → OIDC redirect.

---

## 3. OIDC Client Registration

Satellite apps are registered via `manage.py seed_clients` as **public** OIDC
clients. This means:

- `client_type = "public"` — no back-channel secret exchange
- `client_secret = ""` — empty; PKCE S256 replaces shared secrets
- `response_types = ["code"]` — authorization code flow only
- `jwt_alg = "RS256"` — ID tokens signed with server RSA key
- `_scope = "openid profile email"` — default scope set
- `require_consent = True` / `reuse_consent = True` — consent auto-granted for 90 days

**Client ID format:** `{slug}-satellite-client` (e.g., `iyou-wun-satellite-client`)

**Registered redirect URIs:** Each client has one or more `https://{subdomain}.iyou.me/oidc/callback/` URIs.

---

## 4. Complete Authorization Code Flow

### 4.1 Initiation

A satellite app redirects the user's browser to:

```
GET /openid/authorize/
    ?client_id={slug}-satellite-client
    &redirect_uri=https://{subdomain}.iyou.me/oidc/callback/
    &response_type=code
    &scope=openid profile email
    &state={opaque_state}
    &code_challenge={S256_hash}
    &code_challenge_method=S256
    &nonce={optional_nonce}
```

`django-oidc-provider`'s `AuthorizeView` checks if the user is authenticated.
If not, it redirects to:

```
/auth/login/?next=/openid/authorize/?client_id=...&redirect_uri=...&...
```

The full OIDC authorize URL is preserved in `?next=` so the IDP can issue a
code directly after DID verification.

### 4.2 Authentication (Browser → IDP)

The user authenticates via Tier 3 or Tier 2 (see Section 5). After successful
DID verification, the server:

1. Creates or retrieves the `User` by DID (`username` field)
2. Calls `evaluate_sovereign_admin_posture(user)` for admin elevation
3. Calls `django.contrib.auth.login(request, user)`
4. Calls `_build_oidc_redirect(next_url, user)` which:

   a. Parses `client_id`, `redirect_uri`, `response_type`, `code_challenge`,
      `code_challenge_method` from the `next_url` query string
   b. Validates the client exists and `redirect_uri` is registered
   c. Rejects non-`S256` challenge methods
   d. Creates an auth code via `oidc_provider.lib.utils.token.create_code()`
   e. Caches the PKCE challenge in Redis: `pkce:{code} → {code_challenge, method}` (300s TTL)
   f. Persists a `UserConsent` record (90-day expiry, auto-approve)
   g. Returns `{redirect_uri}?code={auth_code}&state={state}`

5. Returns JSON to the browser:
   ```json
   {
     "success": true,
     "redirect_url": "https://{subdomain}.iyou.me/oidc/callback/?code=...&state=...",
     "user": {
       "did": "did:key:z6Mk...",
       "is_new_user": false,
       "is_authenticated": true,
       "session_id": "..."
     }
   }
   ```

6. The browser JS navigates the current window **inline** to `redirect_url`
   via `window.location.href` — no new tab is opened. The satellite app
   receives the authorization code at its callback URL in the same tab.

### 4.3 Token Exchange (Satellite Server → IDP)

The satellite's backend receives `?code=...&state=...` at its callback URL
and exchanges it for tokens:

```
POST /openid/token/
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={auth_code}
&redirect_uri=https://{subdomain}.iyou.me/oidc/callback/
&client_id={slug}-satellite-client
&code_verifier={original_verifier}
```

**No `client_secret` is required** — this is a public client.

The IDP's `PkceTokenView` (intercepting `/openid/token/` before the library):

1. Looks up `pkce:{code}` in Redis
2. Computes `BASE64URL(SHA256(code_verifier))` and compares to stored `code_challenge`
3. Uses `hmac.compare_digest()` for constant-time comparison
4. Deletes the one-time PKCE entry from Redis
5. Delegates to `django-oidc-provider`'s `TokenView` to issue tokens

**Response:**
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "...",
  "scope": "openid profile email"
}
```

Both tokens are RS256-signed JWTs.

### 4.4 UserInfo (Satellite Server → IDP)

```
GET /openid/userinfo/
Authorization: Bearer {access_token}
```

Returns standard OIDC claims plus custom DID claims (see Section 7).

---

## 5. Authentication Flows in Detail

### 5.1 Tier 3 — Desktop WebSocket (Full Sovereignty)

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Browser  │         │  iyou_idp│         │iyou-home │
│  (JS)     │         │  (IDP)   │         │(Desktop) │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │  POST /auth/challenge/                   │
     │────────────────────▶│                    │
     │  {challenge: uuid}  │                    │
     │◀────────────────────│                    │
     │                     │                    │
     │  WS connect to IDP_HOME_WS_URL          │
     │─────────────────────────────────────────▶│
     │  {type:"sign", challenge: uuid}          │
     │◀─────────────────────────────────────────│
     │  {type:"signed", vp: {...}}              │
     │                     │                    │
     │  POST /auth/verify/ │                    │
     │  {vp, challenge,    │                    │
     │   next_url}         │                    │
     │────────────────────▶│                    │
     │                     │ Verify VP (Ed25519)│
     │                     │ login()            │
     │                     │ build OIDC code    │
     │  {success, redirect_url}                 │
     │◀────────────────────│                    │
     │                     │                    │
     │  Open redirect_url in new tab            │
     │  (satellite app gets ?code=...)          │
```

**Steps:**
1. JS calls `POST /auth/challenge/` → receives UUID, stored in Redis for 300s
2. JS opens WebSocket to `IDP_HOME_WS_URL`, sends `{type: "sign", challenge}`
3. iYou Home prompts user to confirm, signs the challenge with their Ed25519 key
4. Returns a W3C Verifiable Presentation over WebSocket
5. JS calls `POST /auth/verify/` with `{verifiable_presentation, challenge, next_url}`
6. Server verifies VP → creates User → evaluates admin posture → login → builds OIDC code
7. Returns `{redirect_url}` → JS navigates inline via `window.location.href`

### 5.2 Tier 2 — QR Code OOB (Community Self-Signing)

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Browser  │         │  iyou_idp│         │  Mobile  │
│  (JS)     │         │  (IDP)   │         │  Wallet  │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │  POST /auth/challenge/                   │
     │────────────────────▶│                    │
     │  {challenge: uuid}  │                    │
     │◀────────────────────│                    │
     │                     │                    │
     │  Render QR code     │                    │
     │  iyouauth://sign?   │                    │
     │  ch=uuid&url=...    │                    │
     │                     │    Scan QR         │
     │                     │◀───────────────────│
     │                     │                    │
     │                     │  POST /auth/mobile-verify/
     │                     │  {vp, challenge}   │
     │                     │◀───────────────────│
     │                     │  Verify VP         │
     │                     │  Update Redis      │
     │                     │  {solved, did}     │
     │                     │───────────────────▶│
     │                     │                    │
     │  Poll GET /auth/challenge-status/<id>/   │
     │────────────────────▶│                    │
     │  {solved: false}    │                    │
     │◀────────────────────│                    │
     │         ...         │                    │
     │────────────────────▶│                    │
     │  {solved: true,     │                    │
     │   redirect_url}     │                    │
     │◀────────────────────│                    │
```

**Steps:**
1. JS calls `POST /auth/challenge/` → receives UUID
2. JS renders QR code encoding `iyouauth://sign?ch=<uuid>&url=<idp_origin>&next=<base64(next_url)>`
3. Mobile wallet scans QR, user signs, mobile calls `POST /auth/mobile-verify/`
4. Server verifies VP, updates Redis entry to `{status: "solved", did: "..."}`
5. Desktop browser polls `GET /auth/challenge-status/<challenge_id>/` every ~1s
6. When `solved`: server creates User → evaluates admin posture → login → builds OIDC code
7. Returns `{solved: true, redirect_url}` → JS navigates inline via `window.location.href`

### 5.3 Tier 1 — Managed Convenience (Scaffold)

Email/password login at `POST /auth/managed-login/`. Currently returns a
"not yet wired" message. No backend logic implemented.

---

## 6. Admin Authentication

Admin access uses a **separate entry point** that requires both DID
verification AND a staff permission check.

### 6.1 Admin DID Login Flow

| Step | Endpoint | Action |
|------|----------|--------|
| 1 | `POST /auth/admin/did-login/` | Creates challenge in Redis (60s TTL, tagged `'admin_login'`) |
| 2 | DID wallet signs challenge | User's Ed25519 key signs the challenge |
| 3 | `POST /auth/admin/did-verify/` | Verifies VP via Rust `_crypto.verify_vp()`, checks `is_staff` |
| 4 | `GET /admin/` | Django admin interface |

### 6.2 Sovereign Admin Elevation

The function `evaluate_sovereign_admin_posture(user)` runs after **every**
successful DID verification (in `verify_signature`, `check_challenge_status`,
and `custom_admin_verify`):

```python
def evaluate_sovereign_admin_posture(user):
    target_admin_did = settings.ADMIN_DID  # e.g. "did:key:z6Mk..."
    if user.username == target_admin_did:
        if not user.is_staff or not user.is_superuser:
            user.is_staff = True
            user.is_superuser = True
            user.set_unusable_password()
            user.save(update_fields=["is_staff", "is_superuser", "password"])
    return user
```

**Behavior:**
- `ADMIN_DID` env var holds the DID of the sole admin
- On first login (or any subsequent login), the matching user is promoted to
  `is_staff=True, is_superuser=True`
- `set_unusable_password()` is called — no password will ever work for this user
- The promotion is idempotent — safe to call on every auth ingress

### 6.3 Admin Permission Chain

```
DID verification
  → evaluate_sovereign_admin_posture(user)  # auto-elevate if ADMIN_DID matches
  → user.is_staff check                     # reject non-staff
  → login(request, user)
  → redirect to /admin/
```

---

## 7. User Model Contract

```python
class User(AbstractBaseUser):
    username = CharField(max_length=255, unique=True)  # DID string
    is_active = BooleanField(default=True)
    is_staff = BooleanField(default=False)
    is_superuser = BooleanField(default=False)
    date_joined = DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'username'     # The DID IS the username
    REQUIRED_FIELDS = []            # createsuperuser_did takes only DID
```

**Key rules:**
- `username` stores the full DID (e.g., `did:key:z6Mk4XnY...`)
- `password` field exists (inherited from `AbstractBaseUser`) but is **never used**
  for DID auth; set to unusable on admin elevation
- `is_staff` / `is_superuser` are exclusively controlled by `ADMIN_DID` matching
- Users are created on first successful DID verification (`get_or_create`)

---

## 8. OIDC Token Claims

### 8.1 ID Token (RS256-signed JWT)

| Claim | Value | Source |
|-------|-------|--------|
| `sub` | `did:key:z6Mk...` | `custom_sub_generator` → `user.username` |
| `did` | `did:key:z6Mk...` | `custom_idtoken_processing_hook` |
| `did_method` | `key` | Extracted from DID (part after `did:`) |
| `iss` | `IDP_BASE_URL` | Library default |
| `aud` | `{client_id}` | Library default |
| `exp` | +1 hour | Library default |
| `iat` | issued at | Library default |
| `nonce` | from authorize request | Library default |

### 8.2 UserInfo Endpoint Response

| Claim | Value |
|-------|-------|
| `sub` | `did:key:z6Mk...` |
| `did` | `did:key:z6Mk...` |
| `preferred_username` | `did:key:z6Mk...` |
| `did_method` | `key` |
| `email` | (if available) |
| `name` | (if available) |

---

## 9. PKCE S256 Enforcement

The IDP enforces PKCE at **two** points:

### 9.1 Auth Code Issuance (`_build_oidc_redirect`)

- If `code_challenge` is present in the authorize URL, it **must** be
  `code_challenge_method=S256` — `plain` is rejected
- The challenge is cached in Redis: `pkce:{auth_code} → {code_challenge, "S256"}`
  with 300-second TTL

### 9.2 Token Exchange (`PkceTokenView`)

- Intercepts `POST /openid/token/` **before** `django-oidc-provider`'s `TokenView`
- Computes `BASE64URL(SHA256(code_verifier))` and compares to stored challenge
- Uses `hmac.compare_digest()` for timing-safe comparison
- Deletes the one-time Redis entry after verification
- Only `S256` method is accepted — `plain` returns `invalid_request`

**For public clients:** `code_verifier` is required in the token request.
No `client_secret` is needed.

---

## 10. Challenge-Response Lifecycle

### Challenge Generation

| Parameter | Value |
|-----------|-------|
| Format | UUID v4 |
| Storage | Redis (Django cache) |
| TTL | 300s (general auth) / 60s (admin login) |
| One-time use | Yes — deleted after verification |

### General Auth Challenge Cache Structure

```json
{
  "status": "pending",
  "did": null,
  "next_url": "https://..."
}
```

After mobile verification:
```json
{
  "status": "solved",
  "did": "did:key:z6Mk...",
  "next_url": "https://..."
}
```

### Admin Login Challenge Cache Structure

```
"admin_login"  (plain string, not JSON)
```

---

## 11. VP Verification Pipeline

When a Verifiable Presentation arrives at `POST /auth/verify/` or
`POST /auth/mobile-verify/`, verification follows this priority chain:

### 11.1 W3C VP Envelope Detection

If `vp.type` contains `"VerifiablePresentation"`:
1. Extract `proof.signatureValue` or `proof.proofValue`
2. Verify `proof.challenge` matches the expected challenge (nonce check)

### 11.2 Root Authentication Flow (No Inner VC)

If `vp.verifiableCredential` is absent or empty:

**Primary: Python Ed25519 Verification**
1. Extract public key from `holder` DID (`did:key:z6Mk...` → 32-byte Ed25519 key)
2. Reconstruct canonical VP payload: `{@context, type, holder, challenge, verifiableCredential, issuer}`
3. Serialize with `json.dumps(..., separators=(",", ":"))` (no spaces)
4. Verify Ed25519 signature against payload bytes

**Secondary: Rust `_crypto.verify_vp()` Bridge**
- Only attempted if primary fails AND `verifiableCredential` is present
- Serializes VP and passes to Rust for full VC chain verification

**Tertiary: Emergency Bypass**
- If both above fail, but the challenge exists in Redis, log in anyway
- **This is a development/debugging fallback — logged as `SECURITY AUDIT BYPASS`**
- Should be removed or gated behind `DEBUG=True` in production

### 11.3 Embedded VC Flow

If `vp.verifiableCredential` is present:
- Serialized VP is passed to Rust `_crypto.verify_vp()` for full verification
- Rust handles VC chain validation, issuer trust, credential expiry

---

## 12. URL Routing

```
/                              → LoginPageView (landing page)
/auth/challenge/               → ChallengeView (POST: create challenge)
/auth/verify/                  → verify_signature (POST: verify VP)
/auth/mobile-verify/           → mobile_verify_signature (POST: mobile VP)
/auth/challenge-status/<id>/   → check_challenge_status (GET: polling)
/auth/login/                   → LoginPageView (GET: login page)
/auth/admin/did-login/         → custom_admin_login (GET/POST)
/auth/admin/did-verify/        → custom_admin_verify (POST)
/auth/admin/did-dashboard/     → custom_admin_dashboard (GET)
/auth/managed-login/           → managed_login (POST: scaffold)
/auth/logout/                  → GlobalLogoutView (GET)
/openid/authorize/             → django-oidc-provider (browser redirect)
/openid/token/                 → PkceTokenView (custom PKCE gate → library)
/openid/userinfo/              → django-oidc-provider
/openid/.well-known/openid-configuration → django-oidc-provider
/openid/jwks/                  → django-oidc-provider
/admin/                        → Django admin (requires is_staff)
```

---

## 13. Satellite Client Requirements

Any satellite relying party **must** implement:

### 13.1 Client Registration

- Register as a **public** OIDC client (no `client_secret`)
- Use `response_type=code` (authorization code flow)
- Implement PKCE S256 (`code_challenge_method=S256`)
- Provide `redirect_uri` under `https://{subdomain}.iyou.me/oidc/callback/`

### 13.2 Authorization Request

When initiating login, redirect to:
```
/openid/authorize/
    ?client_id={slug}-satellite-client
    &redirect_uri=https://{subdomain}.iyou.me/oidc/callback/
    &response_type=code
    &scope=openid profile email
    &state={csrf_token}
    &code_challenge={BASE64URL(SHA256(code_verifier))}
    &code_challenge_method=S256
```

### 13.3 Callback Handling

At `/oidc/callback/`:
1. Receive `?code=...&state=...`
2. Validate `state` against session
3. Exchange code for tokens:
   ```
   POST /openid/token/
   grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&code_verifier=...
   ```
4. Validate the `id_token` signature against IDP's JWKS (`/openid/jwks/`)
5. Extract `sub` claim — this is the user's DID
6. Establish session

### 13.4 Token Refresh

- Use standard `grant_type=refresh_token` (handled by `django-oidc-provider`)
- No `client_secret` required for public clients
- Refresh tokens have standard library expiry

### 13.5 UserInfo

- Call `GET /openid/userinfo/` with `Authorization: Bearer {access_token}`
- Expect custom claims: `sub` (DID), `did`, `did_method`, `preferred_username`

---

## 14. Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `IDP_BASE_URL` | OIDC issuer URL | `https://idp.iyou.me` |
| `IDP_WUN_URL` | Default post-auth redirect | `https://wun.iyou.me` |
| `IDP_HOME_URL` | iYou Home desktop URL | `https://home.iyou.me` |
| `IDP_HOME_WS_URL` | WebSocket endpoint for Tier 3 | `wss://home.iyou.me:9001/` |
| `IDP_SECRET_KEY` | Django secret key | (random string) |
| `IDP_DEBUG` | Django DEBUG mode | `False` in production |
| `IDP_ALLOWED_HOSTS` | Django ALLOWED_HOSTS | `idp.iyou.me` |
| `IDP_CSRF_TRUSTED_ORIGINS` | CSRF trusted origins | `https://idp.iyou.me` |
| `IDP_CORS_ALLOWED_ORIGINS` | CORS allowed origins | `https://wun.iyou.me` |
| `DATABASE_URL` | PostgreSQL connection | `postgres://...` |
| `REDIS_URL` | Redis connection (challenges) | `redis://...` |
| `ADMIN_DID` | Sovereign admin DID | `did:key:z6Mk...` |

---

## 15. Security Properties

1. **No shared secrets** — Public clients use PKCE S256 exclusively
2. **One-time challenges** — Each challenge UUID is deleted after use
3. **Short-lived challenges** — 300s general, 60s admin
4. **Constant-time PKCE comparison** — `hmac.compare_digest()` prevents timing attacks
5. **Ed25519 signature verification** — Cryptographic proof of DID ownership
6. **RSA-signed ID tokens** — Server key signs JWTs, verifiable via JWKS
7. **Consent auto-granted for 90 days** — Reduces friction for returning users
8. **Single admin DID** — Only `ADMIN_DID` env var holder gets superuser
9. **Unusable passwords** — `set_unusable_password()` on elevation, no password auth
10. **Emergency bypass logged** — `SECURITY AUDIT BYPASS` entries in stdout for monitoring
