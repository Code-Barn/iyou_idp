# iYou Identity Provider — Agent Guide

## 🔒 CRITICAL: OpenID Connect & Ingress Invariants
All authentication and user provisioning logic in this repository MUST conform strictly to the canonical ecosystem specifications located at:
- `docs/ecosystem_shared/OMNI_SOCIAL_AUTH_STANDARDIZATION.md`
- `docs/ecosystem_shared/AUTH_FLOW_SPECIFICATION.md`

Reference Implementation to follow: `docs/ecosystem_shared/auth_pkce.py`

Do NOT implement cleartext client secrets, do NOT use email addresses as database lookup anchors, and ensure all post-auth logic implements the `evaluate_sovereign_admin_posture` routine.

## 🔒 CRITICAL: Auth Flow Specification Sync Rule
`docs/AUTH_FLOW_SPECIFICATION.md` is the **Single Source of Truth (SSOT)**. Any edit to this file **must** be propagated to both downstream copies in the same commit:
1. `docs/ecosystem_shared/AUTH_FLOW_SPECIFICATION.md` (local ecosystem mirror)
2. `/Users/macuser/CODE_BASE/omni_social/docs/AUTH_FLOW_SPECIFICATION.md` (omni_social repo)

Use `cp` to sync:
```bash
cp docs/AUTH_FLOW_SPECIFICATION.md docs/ecosystem_shared/AUTH_FLOW_SPECIFICATION.md
cp docs/AUTH_FLOW_SPECIFICATION.md /Users/macuser/CODE_BASE/omni_social/docs/AUTH_FLOW_SPECIFICATION.md
```

## Project
Django-based OIDC provider that authenticates users via W3C DIDs instead of passwords. Rust extension (`_crypto`) handles Ed25519 signature verification, backed by Python `cryptography` primary path.

## Quick commands
```bash
uv run python manage.py runserver 0.0.0.0:8001   # dev server
uv run python manage.py test auth_bridge -v2      # run tests
uv run ruff check auth_bridge/                    # lint
uv run python manage.py check                     # validate config
uv run python manage.py createsuperuser_did       # create superuser
uv run python manage.py creatersakey              # generate RSA key for OIDC
maturin develop                                   # rebuild Rust bridge
```

## Project structure
```
iyou_idp/
├── auth_bridge/              # Django app — auth logic
│   ├── backend.py            # DIDAuthBackend + evaluate_sovereign_admin_posture
│   ├── admin_views.py        # DID-based admin login views
│   ├── views.py              # verify_signature, ChallengeView, LoginPageView, etc.
│   ├── views_oauth.py        # Tier 1 OAuth: OAuthInitiateView, OAuthCallbackView
│   ├── pipeline.py           # Smart-Merge: process_oauth_identity()
│   ├── oidc.py               # OIDC userinfo/id-token hooks (custodial_did)
│   ├── models.py             # User (UUIDField PK, custodial_did) + FederatedIdentity
│   └── urls.py
├── config/
│   └── settings.py           # IDP_* env vars, OAUTH_* provider config
├── docs/
│   ├── IDP_DEVELOPER_GUIDE.md  # Full architecture docs
│   ├── AUTH_FLOW_SPECIFICATION.md  # SSOT for auth flows
│   └── ecosystem_shared/     # Shared specs (synced across repos)
├── src/iyou_idp/
│   └── _crypto.abi3.so       # Compiled Rust crypto bridge
└── crates/did_rust/          # Rust DID verification (git submodule — shared w/ iyou_home)
```

## Key architecture

**3-tier auth spectrum:**
| Tier | Name | Method |
|------|------|--------|
| 3 | Full Sovereignty | Desktop WebSocket (`iyou-home`) + manual VP paste |
| 2 | Community Self-Signing | OOB QR-code flow with mobile DID wallet |
| 1 | Managed Convenience | OAuth providers (Google, Apple, GitHub) — server-managed `did:web` |

**Auth flow:** `POST /auth/challenge/` → user signs challenge → `POST /auth/verify/` with VP → three-tier verification (Python Ed25519 → Rust `verify_vp` → emergency bypass) → `login()` → OIDC redirect.

**User model:** `UUIDField` PK, `email` as `USERNAME_FIELD`, `custodial_did` stores `did:web:iyou.me:user:{uuid}`, `FederatedIdentity` links OAuth providers. `is_staff`/`is_superuser` control Django admin access.

**Sovereign admin elevation:** Set `ADMIN_DID` env var to a `did:key:` multibase URI. `evaluate_sovereign_admin_posture()` runs after every auth ingress and auto-promotes the matching user to staff+superuser.

## Environment variables (all via `IDP_` prefix + `ADMIN_DID`)
`IDP_BASE_URL`, `IDP_WUN_URL`, `IDP_HOME_URL`, `IDP_HOME_WS_URL`, `IDP_SECRET_KEY`, `IDP_DEBUG`, `IDP_ALLOWED_HOSTS`, `IDP_CSRF_TRUSTED_ORIGINS`, `IDP_CORS_ALLOWED_ORIGINS`, `DATABASE_URL`, `REDIS_URL`, `ADMIN_DID`.

## Auth entry points (where `evaluate_sovereign_admin_posture(user)` is called)
- `views.py:verify_signature` — desktop WebSocket flow (main + bypass + fallback VP paths)
- `views.py:check_challenge_status` — mobile OOB polling flow
- `admin_views.py:custom_admin_verify` — admin DID login flow

## Conventions
- No comments in code unless legacy
- GPLv3 license header on all source files
- F-strings over `.format()` or `%`
- Type hints on function signatures
- `JsonResponse` with `{'error': '...'}` pattern for API errors
- `@csrf_exempt` on crypto endpoints (no session side-effects)
- `django-environ` for all config, `env.str()` / `env.bool()` / `env.list()` / `env.db_url()`
- `environ.Env()` instantiated once at module level in settings.py, `.env` loaded via `env.read_env()`

## Tests
- Located in `auth_bridge/tests.py`
- Generate Ed25519 keys, build signed VCs/VPs, exercise challenge-response cycle
- Run with `uv run python manage.py test auth_bridge -v2`

## Important gotchas
- `src/` is appended to `sys.path` in settings.py — Rust `.so` lives there
- `did_rust` is a **git submodule** shared with `iyou_home` — both copies must point to same commit or FFI breaks
- OIDC clients use `/openid/authorize/` (not `/oauth/authorize/` or `/auth/login/`)
- DIsable built-in `/admin/` login; admin auth goes through `/auth/admin/did-login/`
- Challenge TTL is 300 seconds; challenges are single-use
- Post-login routing is inline: `window.location.href` navigates the current tab to the satellite callback URL
