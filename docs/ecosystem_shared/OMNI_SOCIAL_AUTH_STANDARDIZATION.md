# OMNI_SOCIAL Authentication Standardization

**Canonical specification for OIDC/PKCE ingress across the iyou_ ecosystem.**
**Established:** 2026-07-13
**Status:** Enforced — all satellites must conform before deployment

---

## 1. Purpose

This document defines the **5 Uncompromising Rules of Ingress Federation** — the non-negotiable technical constraints that every iyou_ satellite application must satisfy to participate in the OIDC authentication mesh with iyou_idp.

These rules were established during the resolution of system-wide login crashes across the relying party grid. Every rule exists because a violation of it produced a specific, reproducible failure mode in production.

**Violation of any rule is a deployment blocker.**

---

## 2. Reference Implementation

The canonical source of truth is:

```
omni_social/templates/utils/auth_pkce.py
```

This module contains three classes that implement the complete PKCE authentication flow:

| Class | Role | Extends |
|:---|:---|:---|
| `PKCEOIDCAuthenticationRequestView` | Generates PKCE pair, redirects to iyou_idp | `mozilla_django_oidc.views.OIDCAuthenticationRequestView` |
| `PKCEOIDCAuthenticationCallbackView` | Handles callback, forwards verifier to backend | `mozilla_django_oidc.views.OIDCAuthenticationCallbackView` |
| `PKCEAuthenticationBackend` | Executes token exchange, provisions user | `django.contrib.auth.Backend` |

All satellite implementations must conform to the patterns in this module. Per-app customizations are permitted only within the override points documented below.

---

## 3. The 5 Uncompromising Rules

### Rule 1: Reverse-Proxy Header Awareness

**Every app MUST include:**

```python
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

**Why this rule exists:**

Satellites run behind a reverse proxy (nginx, Traefik, cloud LB) that terminates TLS. The Django application sees plain HTTP internally. Without this setting, Django's `request.is_secure()` returns `False`, which causes:

1. The OIDC `redirect_uri` built by `absolutify()` generates `http://` instead of `https://`
2. iyou_idp rejects the callback because the registered redirect URI is `https://`
3. The user sees an "invalid redirect_uri" error from the identity provider
4. Even if the flow completes, session cookies set without `Secure` flag are vulnerable to interception

**Implementation:**

```python
# settings.py — required in EVERY satellite
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

**Failure mode if omitted:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| "invalid redirect_uri" from iyou_idp | `absolutify()` generates `http://` URL | Add `SECURE_PROXY_SSL_HEADER` |
| Session cookies missing `Secure` flag | `request.is_secure()` returns `False` | Add `SECURE_PROXY_SSL_HEADER` |
| Login loop with no error detail | Redirect URI mismatch, silently rejected | Add `SECURE_PROXY_SSL_HEADER` |

**Validated across:** All 10 rendering satellites.

#### Rule 1 Extension: Inline Window Integrity

**Frontend authentication transitions MUST use single-tab navigation (`window.location.href`). Fabricated popup reservation blocks are strictly deprecated.**

The iyou_ ecosystem uses server-side OIDC redirects — the browser navigates away from the satellite to iyou_idp, authenticates, and redirects back. This flow requires the current tab to be the navigation target. Popup-based auth breaks this contract:

1. **Popup blockers** — Browsers aggressively block `window.open()` calls from non-user-initiated contexts. Auth popups silently fail, leaving the user on a stale page with no feedback.
2. **Session isolation** — A popup opens a separate browsing context with its own cookie jar. The OIDC callback lands in the popup, sets the session, but the original tab never receives it. The user sees a logged-out state in the main window.
3. **CSRF surface expansion** — Popups create additional entry points that bypass the main tab's CSRF token state, weakening the protection provided by Django's middleware.

**Forbidden patterns:**

```javascript
// DO NOT USE — popup-based auth is deprecated
window.open("/oidc/authorize/?...", "_blank");
reserveAuthPopup();
window.open(authUrl, "authPopup", "width=500,height=600");
```

**Required pattern:**

```javascript
// USE — single-tab navigation
window.location.href = "/oidc/authorize/?...";
```

**Failure mode if violated:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| Auth popup blocked by browser | `window.open()` from non-initiated context | Use `window.location.href` |
| User logged in inside popup but not in main tab | Session cookie scoped to popup context | Use single-tab navigation |
| "Auth popup closed" errors in console | Popup closed before callback completed | Remove popup flow entirely |
| CSRF token mismatch on callback | Popup bypasses main tab's CSRF state | Use single-tab navigation |

**Applies to:** All frontend JavaScript across the ecosystem — login buttons, re-authentication triggers, session refresh handlers.

---

### Rule 2: Public Client Protocol Strategy

**Satellites are explicitly registered as public client types.**

They rely on cryptographic PKCE verification matrices (S256 code challenge) instead of raw string secrets (`OIDC_RP_CLIENT_SECRET`).

**Why this rule exists:**

The original `mozilla_django_oidc` library assumes confidential clients — it enforces `OIDC_RP_CLIENT_SECRET` at the backend's `__init__` time. Satellite apps are public clients (browser-based, no server-side secret storage). Forcing a static secret into the codebase:

1. Exposes the secret in version control
2. Creates a single point of compromise across all satellites
3. Requires secret rotation coordination across 10+ deployments
4. Violates the principle that the PKCE verifier alone proves client possession

**Implementation:**

```python
# The backend inherits from auth.Backend, NOT OIDCAuthenticationBackend
class PKCEAuthenticationBackend(auth.Backend):
    """
    This avoids OIDCAuthenticationBackend's __init__ which enforces
    OIDC_RP_CLIENT_SECRET presence.
    """
```

```python
# Client secret is conditionally included — only if explicitly configured
client_secret = self._get_setting("OIDC_RP_CLIENT_SECRET", "")
if client_secret:
    token_payload["client_secret"] = client_secret
```

**Client ID alignment (4-point rule):**

| Source | Expected Value | Example (iyou_play) |
|:---|:---|:---|
| Helm `{{ .Release.Name }}-satellite-client` | `iyou-{app}-satellite-client` | `iyou-play-satellite-client` |
| Vault `oidc_rp_client_id` | `iyou-{app}-satellite-client` | `iyou-play-satellite-client` |
| `seed_clients.py` slug | `iyou-{app}-satellite-client` | `iyou-play-satellite-client` |
| IDP database `Client.client_id` | `iyou-{app}-satellite-client` | `iyou-play-satellite-client` |

**Failure mode if violated:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| `invalid_client` error from token endpoint | `client_id` mismatch across sources | Align all 4 sources |
| Silent login loop, no server error | Backend returns `None`, 302 redirect | Check client_id alignment |
| `OIDCAuthenticationBackend` crashes at init | Inherits secret enforcement | Use `auth.Backend` instead |

**Deployment pattern:**

```yaml
# Helm deployment.yaml
- name: OIDC_RP_CLIENT_ID
  value: {{ .Release.Name }}-satellite-client
- name: OIDC_RP_CALLBACK_URL
  value: https://{{ (index .Values.ingress.hosts 0).host }}/oidc/callback/
```

```bash
# Vault seeding
vault kv put "$VAULT_PATH" oidc_rp_client_id="iyou-{app}-satellite-client" ...
```

**Validated across:** All 10 rendering satellites.

---

### Rule 3: Instance State Relay Pattern

**Custom backends MUST forward transient PKCE arguments via the `get_backend_kwargs()` hook, NOT by intercepting the view's `get()` method.**

The callback view overrides `get_backend_kwargs(self, request)` to pop the verifier from the session and inject it into the backend kwargs dictionary. The parent class's `get()` method calls this hook internally and passes the returned dict as keyword arguments to `auth.authenticate()`.

**Why this rule exists:**

The original implementation overrode `get()` in the callback view, popped the verifier, and called `auth.authenticate(code_verifier=verifier)` directly. This bypassed the library's internal routing — the parent `get()` method never received the verifier because `get_backend_kwargs()` returned an empty dict. The backend's `authenticate()` received `code_verifier=None`, the token exchange failed with `invalid_grant`, and the user was redirected to the failure URL in an infinite loop.

**Correct pattern:**

```python
class PKCEOIDCAuthenticationCallbackView(OIDCAuthenticationCallbackView):

    def get_backend_kwargs(self, request):
        """Pop verifier from session, forward to backend via kwargs."""
        kwargs = super().get_backend_kwargs(request)

        code_verifier = request.session.pop("pkce_code_verifier", None)

        if code_verifier is None:
            logger.warning("No pkce_code_verifier in session")

        kwargs.update({"code_verifier": code_verifier})
        return kwargs
```

**Incorrect pattern (causes login loops):**

```python
class PKCEOIDCAuthenticationCallbackView(OIDCAuthenticationCallbackView):

    def get(self, request):
        code_verifier = request.session.pop("pkce_code_verifier", None)
        # This calls auth.authenticate() directly, bypassing the library's
        # internal get_backend_kwargs() → auth.authenticate() chain.
        # The backend never receives the verifier.
        self.user = auth.authenticate(
            request=request,
            code_verifier=code_verifier,
        )
        ...
```

**Session contract:**

```
Request view:
  request.session["pkce_code_verifier"] = code_verifier  (SET)

Callback view (get_backend_kwargs):
  code_verifier = request.session.pop("pkce_code_verifier", None)  (POP)
  kwargs.update({"code_verifier": code_verifier})  (FORWARD)

Backend (authenticate):
  code_verifier = kwargs.get("code_verifier")  (RECEIVE)
  token_payload["code_verifier"] = code_verifier  (EXCHANGE)
```

**Failure mode if violated:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| Login reload loop, no error | `get_backend_kwargs()` returns empty dict | Override `get_backend_kwargs()`, not `get()` |
| `invalid_grant` from token endpoint | Verifier not included in token POST | Forward verifier via kwargs |
| Silent 302 redirect cycle | Backend returns `None`, no exception logged | Check `get_backend_kwargs()` override |

**Validated across:** All 10 rendering satellites.

---

### Rule 4: Sovereign Profile Anchoring

**`get_username(claims)` MUST always be explicitly overridden to parse the `sub` claim DID key.**

User lookup queries must filter strictly on `username=claims.get("sub")`. Email string fields must never be used as lookup keys. This prevents database collision crashes when multiple DID records share an email address.

**Why this rule exists:**

The default `mozilla_django_oidc` backend uses `email__iexact` as the lookup filter. When two different DID identities (different `sub` values) share the same email address, the `get_or_create()` call hits a unique constraint violation and the backend crashes with an `IntegrityError`. Even without crashes, email-based lookup conflates distinct DID identities — a fundamental violation of the sovereign identity model.

**Correct pattern:**

```python
def _get_or_create_user(self, user_info):
    sub = user_info.get("sub")
    if not sub:
        return None

    username = sub  # DID string IS the username

    user, created = User.objects.get_or_create(
        username=username,  # Lookup on DID, NOT email
        defaults={
            "email": user_info.get("email", ""),
            "first_name": user_info.get("given_name", ""),
            "last_name": user_info.get("family_name", ""),
        },
    )
    return user
```

**Incorrect pattern (causes IntegrityError):**

```python
def _get_or_create_user(self, user_info):
    # WRONG: email lookup conflates distinct DID identities
    user, created = User.objects.get_or_create(
        email=user_info.get("email"),
        defaults={"username": user_info.get("sub")},
    )
```

**Privilege evaluation:**

Admin status is determined by comparing the `sub` claim against an environment variable, not a Django setting:

```python
admin_did = os.environ.get("ADMIN_DID", "")
is_admin = bool(admin_did) and sub == admin_did
```

This decouples privilege configuration from Django settings scaffolding and prevents settings import-time dependency issues.

**Dirty-flag pattern:**

```python
dirty = False
if is_admin and not user.is_superuser:
    user.is_superuser = True
    user.is_staff = True
    dirty = True
elif not is_admin and (user.is_superuser or user.is_staff):
    user.is_superuser = False
    user.is_staff = False
    dirty = True

if dirty:
    user.save()  # Only write when state actually changes
```

**Failure mode if violated:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| `IntegrityError` on login | Email-based lookup hits unique constraint | Override to `username=sub` |
| Two DID identities merged | Email lookup conflates distinct `sub` values | Override to `username=sub` |
| `ImproperlyConfigured` at import time | `getattr(settings, "ADMIN_DID")` used instead of `os.environ.get()` | Use environment variable |
| Unnecessary DB writes on every login | `user.save()` called unconditionally | Use dirty-flag pattern |

**Validated across:** All 10 rendering satellites.

---

### Rule 5: Explicit Logout View Architecture

**Every app MUST include a dedicated OIDC logout route in its primary URLconf:**

```python
# config/urls.py — required in EVERY satellite
from mozilla_django_oidc.views import OIDCLogoutView

urlpatterns = [
    path("oidc/logout/", OIDCLogoutView.as_view(), name="oidc_logout"),
    # ... other routes
]
```

**Why this rule exists:**

The iyou_ ecosystem uses session-based OIDC with signed cookies. When a user logs out of one satellite, the session teardown must propagate cleanly through `mozilla_django_oidc`'s `OIDCLogoutView` — which clears the local Django session, invalidates the OIDC tokens, and redirects to the IDP's logout endpoint for federated session termination.

Without an explicit logout route:

1. **Session teardown loops** — Django's default logout machinery may redirect back to itself or to a login view that immediately re-authenticates via the still-valid OIDC session cookie, creating an infinite redirect loop.
2. **Template reversing failures** — Dashboard templates and navigation macros that reference `{% url 'oidc_logout' %}` raise `NoReverseMatch` exceptions, breaking the UI for all users on that node.
3. **Federated logout incomplete** — The IDP's session is never terminated, so the user appears logged out locally but remains authenticated at the IDP — a security gap that allows silent re-authentication on any other satellite.

**Implementation:**

The route MUST be named `oidc_logout` (not `logout`, not `oidc_logout_view`) to match the convention used by `mozilla_django_oidc`'s default URL resolution and the dashboard templates shared across all satellites.

```python
# config/urls.py
from django.urls import path
from mozilla_django_oidc.views import OIDCLogoutView

urlpatterns = [
    path("oidc/logout/", OIDCLogoutView.as_view(), name="oidc_logout"),
]
```

**Companion setting (in settings.py):**

```python
# Required for OIDCLogoutView to redirect after logout
LOGOUT_REDIRECT_URL = "/"
```

**Failure mode if violated:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| Infinite redirect loop on logout | No `OIDCLogoutView` route — session cookie persists | Add `path("oidc/logout/", ...)` |
| `NoReverseMatch` in templates | `{% url 'oidc_logout' %}` has no matching URL | Name the route `oidc_logout` |
| User appears logged out but re-authenticates | IDP session not terminated | `OIDCLogoutView` handles federated logout |
| Dashboard nav shows "Log Out" link that 404s | Logout route missing from URLconf | Add the route |

**Validated across:** iyou_idp (system root), iyou_wun, iyou_poly, iyou_name, iyou_hive, iyou_ride, dc_tech_website, iyou_safe, iyou_talk, iyou_clar, iyou_play.

---

## 4. Required Settings Checklist

Every satellite MUST have these settings before deployment:

```python
# --- SSL / Proxy ---
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --- Session ---
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

# --- OIDC Provider ---
OIDC_RP_CLIENT_ID = "iyou-{app}-satellite-client"
OIDC_RP_SCOPES = "openid"
OIDC_OP_AUTHORIZATION_ENDPOINT = "https://iyou.me/openid/authorize/"
OIDC_OP_TOKEN_ENDPOINT = "https://iyou.me/openid/token/"
OIDC_OP_USER_ENDPOINT = "https://iyou.me/openid/userinfo/"

# --- Callback ---
OIDC_AUTHENTICATION_CALLBACK_URL = "oidc_authentication_callback"
LOGIN_REDIRECT_URL = "/"
LOGIN_REDIRECT_URL_FAILURE = "/"

# --- Auth Backend ---
AUTHENTICATION_BACKENDS = [
    "templates.utils.auth_pkce.PKCEAuthenticationBackend",
]
```

---

## 5. URLconf Template

```python
from templates.utils.auth_pkce import (
    PKCEOIDCAuthenticationRequestView,
    PKCEOIDCAuthenticationCallbackView,
)
from mozilla_django_oidc.views import OIDCLogoutView

urlpatterns = [
    path("oidc/authenticate/",
         PKCEOIDCAuthenticationRequestView.as_view(),
         name="oidc_authentication_init"),
    path("oidc/callback/",
         PKCEOIDCAuthenticationCallbackView.as_view(),
         name="oidc_authentication_callback"),
    path("oidc/logout/",
         OIDCLogoutView.as_view(),
         name="oidc_logout"),
]
```

---

## 6. Middleware Ordering

The session middleware MUST load before any custom middleware that touches `request.session`:

```python
MIDDLEWARE = [
    # ... Django core ...
    "django.contrib.sessions.middleware.SessionMiddleware",  # Index 2
    # ... custom middleware (prune, geographic routing, etc.) ...
    # ... Django auth ...
]
```

**Failure mode if misordered:** `AttributeError` on `request.session` in custom middleware that runs before `SessionMiddleware` initializes the session backend.

**Validated in:** iyou_ride (SessionMiddleware repositioned to index 2).

---

## 7. Resolved Failure Modes

These are the production failure modes that established the 4 rules above. They are documented here to prevent regression.

| App | Rule Violated | Failure Mode | Root Cause | Fix |
|:---|:---|:---|:---|:---|
| iyou_poly | Rule 3 | Login reload loop | Three-tier claims resolution needed | Claims fallback loop + dirty-flag elevation |
| iyou_name | Rule 4 | Identity mismatch | Username from wrong claim | Pin to `sub` claim, env-based DID lookup |
| dc_tech_website | Rule 4 | IntegrityError | `email__iexact` fallback in filter | Override to `username=did` lookup |
| iyou_ride | Rule 6 (middleware) | AttributeError | SessionMiddleware load order | Repositioned to index 2 |
| iyou_safe | General | HTTP 500 crash | Unhandled connection drop | `try/except requests.RequestException` guard |
| iyou_hive | Rule 3 | Cross-thread state loss | Session container override | Remove override line |

Full audit details: `docs/audits/2026_PKCE_IMPLEMENTATION_MATRIX.md` (Section 4)

---

## 8. Cross-References

| Document | Path | Purpose |
|:---|:---|:---|
| Canonical auth module | `templates/utils/auth_pkce.py` | Reference implementation |
| PKCE audit matrix | `docs/audits/2026_PKCE_IMPLEMENTATION_MATRIX.md` | Per-app session contracts and failure modes |
| Security hardening | `docs/strategy/SECURITY_HARDENING.md` | SEC-001 through SEC-008 roadmap |
| Satellite coordination | `docs/satellite-coordination.md` | Active tickets and registry |
| Sprint ledger | `docs/sprints/2026_LAYER0_STANDARDIZATION.md` | Layer 0-1 completion log |
| Developer guide | `OMNI_SOCIAL_DEVELOPER_GUIDE.md` | Onboarding and quick reference |

---

## 9. Canonical Passwordless Passthrough & Sovereign Admin Posture Matrix

> Design signatures extracted from iyou_idp's pass-through authentication
> layout, sourced from `docs/AUTH_FLOW_SPECIFICATION.md`. This is the
> definitive blueprint pattern that all 8 remaining satellite repos must
> copy to match the verified standard.

### 9.1 Scope Declaration

**Every app MUST declare:**

```python
OIDC_RP_SCOPES = "openid profile email"
```

This matches the IDP's default scope set (see `AUTH_FLOW_SPECIFICATION.md` Section 3: `_scope = "openid profile email"`).

**Why full scope is required:**

The IDP's `_build_oidc_redirect` (Section 4.2) and token endpoint (Section 4.3) expect `scope=openid profile email`. Restricting to `"openid"` alone causes:

1. IDP may reject or downgrade the token response
2. UserInfo endpoint (Section 4.4) returns fewer claims — satellites that need `preferred_username` or `did_method` get incomplete data
3. Consent auto-grant (90-day window, Section 3) may not activate correctly if scope doesn't match the registered client's default

**Implementation:**

```python
# settings.py — required in EVERY satellite
OIDC_RP_SCOPES = "openid profile email"
```

**Satellite behavior with full scope:**

The satellite backend receives these claims from `/openid/userinfo/` (Section 8.2):

| Claim | Value | Used by satellite |
|:---|:---|:---|
| `sub` | `did:key:z6Mk...` | Rule 4: username anchor |
| `did` | `did:key:z6Mk...` | Verification redundancy |
| `preferred_username` | `did:key:z6Mk...` | Display fallback |
| `did_method` | `key` | Method identification |
| `email` | (if available) | Stored as default, never used for lookup |
| `name` | (if available) | Stored as default |

**Critical constraint:** Even though `email` is returned, satellites MUST NOT use it for user lookup (Rule 4). The email claim is stored as a profile default but never used as an identity anchor.

**Failure mode if violated:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| Incomplete UserInfo claims | Scope too restrictive | Use `"openid profile email"` |
| Consent auto-grant not activating | Scope mismatch with registered client | Match IDP's default scope |
| `preferred_username` missing | `profile` scope not requested | Add `profile` to scopes |

**Validated in:** iyou_idp, iyou_wun.

---

### 9.2 Sovereign Admin Posture Hook

**Every satellite custom backend MUST evaluate this exact posture match after user provisioning.**

This is the canonical function from `AUTH_FLOW_SPECIFICATION.md` Section 6.2:

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

**What this hook does:**

1. Reads `ADMIN_DID` from Django **settings** (not `os.environ.get` — the IDP loads this at startup via `django-environ`)
2. Compares `user.username` (which IS the `sub` claim per Rule 4) against `target_admin_did`
3. If matched AND the user doesn't already have staff/superuser privileges, grants them
4. Calls `set_unusable_password()` — the admin account must never have a usable password
5. Uses `save(update_fields=[...])` — targeted save, not full model save
6. **Elevation only** — no demotion logic. The hook is idempotent and safe to call on every auth ingress.

**Why this function is idempotent:**

The guard `if not user.is_staff or not user.is_superuser` ensures the save only executes when promotion is actually needed. On subsequent logins, the user already has `is_staff=True` and `is_superuser=True`, so the function is a no-op (returns immediately after the comparison).

**Why `set_unusable_password()` is mandatory:**

The iyou_ ecosystem is passwordless. All authentication flows through iyou_idp via OIDC/PKCE. If an admin account has a usable password set (from a previous Django admin setup, a data migration, or a manual override), that password becomes a parallel attack vector that bypasses the entire OIDC mesh. `set_unusable_password()` sets `password = !` which Django's password hashers reject.

**Where this hook runs (from AUTH_FLOW_SPECIFICATION.md Section 6.2):**

The hook runs after **every** successful DID verification:
- `verify_signature` (Tier 3 Desktop WebSocket flow)
- `check_challenge_status` (Tier 2 QR Code polling flow)
- `custom_admin_verify` (Admin DID login flow)

**Satellite adaptation:**

In satellite backends, the hook is called inside `_get_or_create_user()` after the `get_or_create()` call:

```python
def _get_or_create_user(self, user_info):
    sub = user_info.get("sub")
    if not sub:
        return None

    user, created = User.objects.get_or_create(
        username=sub,
        defaults={"email": user_info.get("email", "")},
    )

    # Sovereign Admin Posture Hook (AUTH_FLOW_SPECIFICATION.md §6.2)
    evaluate_sovereign_admin_posture(user)

    return user
```

**Failure mode if omitted:**

| Symptom | Root cause | Fix |
|:---|:---|:---|
| Admin has usable password | `set_unusable_password()` never called | Add posture hook |
| Admin privileges not granted | Posture hook missing from backend | Add hook after `get_or_create()` |
| Admin password brute-forceable | Parallel auth path exists outside OIDC | `set_unusable_password()` blocks it |
| Full model save on every login | Using `user.save()` instead of `update_fields` | Use `save(update_fields=[...])` |

**Validated in:** iyou_idp (Identity Mesh Hardening), iyou_wun (Relying Party Hardening).

---

### 9.3 PKCE Enforcement Points

The IDP enforces PKCE at **two** points (from `AUTH_FLOW_SPECIFICATION.md` Section 9):

**Point 1 — Auth Code Issuance (`_build_oidc_redirect`):**

- Satellite sends `code_challenge` + `code_challenge_method=S256` in the authorize URL
- IDP validates method is `S256` — `plain` is rejected
- Challenge cached in Redis: `pkce:{auth_code} → {code_challenge, "S256"}` with 300s TTL

**Point 2 — Token Exchange (`PkceTokenView`):**

- Intercepts `POST /openid/token/` **before** `django-oidc-provider`'s `TokenView`
- Computes `BASE64URL(SHA256(code_verifier))` and compares to stored challenge
- Uses `hmac.compare_digest()` for timing-safe comparison
- Deletes the one-time Redis entry after verification
- Only `S256` method accepted — `plain` returns `invalid_request`

**Satellite implication:** The `code_verifier` MUST be included in the token POST body. The `get_backend_kwargs()` override (Rule 3) is the mechanism that ensures this happens.

---

### 9.4 Challenge-Response Lifecycle

From `AUTH_FLOW_SPECIFICATION.md` Section 10:

| Parameter | General Auth | Admin Login |
|:---|:---|:---|
| Format | UUID v4 | UUID v4 |
| Storage | Redis (Django cache) | Redis (Django cache) |
| TTL | 300s | 60s |
| One-time use | Yes — deleted after verification | Yes — deleted after verification |

**General auth challenge cache:**
```json
{"status": "pending", "did": null, "next_url": "https://..."}
```
After mobile verification:
```json
{"status": "solved", "did": "did:key:z6Mk...", "next_url": "https://..."}
```

**Satellite implication:** Satellites don't manage challenges directly — they receive the `code` and `state` at their callback URL after the IDP has already verified the challenge. But understanding this lifecycle helps debug timeout-related auth failures.

---

### 9.5 VP Verification Pipeline

From `AUTH_FLOW_SPECIFICATION.md` Section 11. Satellites don't implement this — it runs on the IDP. But it's documented here for awareness:

1. **W3C VP Envelope Detection** — if `vp.type` contains `"VerifiablePresentation"`, extract and verify `proof.challenge`
2. **Root Authentication Flow (No Inner VC)** — Python Ed25519 verification (primary), Rust `_crypto.verify_vp()` (secondary), Emergency bypass (tertiary — logged as `SECURITY AUDIT BYPASS`)
3. **Embedded VC Flow** — full VC chain verification via Rust bridge

**Satellite implication:** If a user reports "login succeeded but satellite didn't receive the code", the issue may be in the VP verification pipeline on the IDP side, not the satellite's callback handling.

---

### 9.6 Satellite Client Registration Requirements

From `AUTH_FLOW_SPECIFICATION.md` Section 13.1:

| Parameter | Required Value |
|:---|:---|
| `client_type` | `"public"` |
| `client_secret` | `""` (empty — PKCE replaces shared secrets) |
| `response_types` | `["code"]` |
| `jwt_alg` | `"RS256"` |
| `_scope` | `"openid profile email"` |
| `require_consent` | `True` |
| `reuse_consent` | `True` (90-day auto-grant) |
| `client_id` format | `{slug}-satellite-client` |
| `redirect_uri` format | `https://{subdomain}.iyou.me/oidc/callback/` |

**Registration via:** `manage.py seed_clients`

---

### 9.7 Complete Backend Template

This is the full backend class that all satellites must implement, aligned with `AUTH_FLOW_SPECIFICATION.md`:

```python
import hashlib
import logging
import secrets
import time
from base64 import urlsafe_b64encode
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.contrib import auth
from django.http import HttpResponseRedirect
from django.urls import reverse
from mozilla_django_oidc.utils import absolutify
from mozilla_django_oidc.views import (
    OIDCAuthenticationCallbackView,
    OIDCAuthenticationRequestView,
)

logger = logging.getLogger(__name__)


def evaluate_sovereign_admin_posture(user):
    """AUTH_FLOW_SPECIFICATION.md §6.2 — Canonical admin elevation."""
    target_admin_did = settings.ADMIN_DID
    if user.username == target_admin_did:
        if not user.is_staff or not user.is_superuser:
            user.is_staff = True
            user.is_superuser = True
            user.set_unusable_password()
            user.save(update_fields=["is_staff", "is_superuser", "password"])
    return user


class PKCEOIDCAuthenticationRequestView(OIDCAuthenticationRequestView):
    """§4.1: Generate PKCE pair, redirect to iyou_idp."""

    http_method_names = ["get"]

    def get(self, request):
        try:
            code_verifier = secrets.token_urlsafe(64)
            hash_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            code_challenge = urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

            request.session["pkce_code_verifier"] = code_verifier

            state = secrets.token_urlsafe(32)
            params = {
                "response_type": "code",
                "scope": "openid profile email",  # §3: IDP default scope
                "client_id": self.OIDC_RP_CLIENT_ID,
                "redirect_uri": absolutify(request, reverse("oidc_authentication_callback")),
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }

            if "oidc_states" not in request.session:
                request.session["oidc_states"] = {}
            request.session["oidc_states"][state] = {"added_on": time.time()}
            request.session.save()

            return HttpResponseRedirect(f"{self.OIDC_OP_AUTH_ENDPOINT}?{urlencode(params)}")
        except Exception:
            logger.exception("PKCE auth request failed")
            return HttpResponseRedirect(self.get_settings("LOGIN_REDIRECT_URL_FAILURE", "/"))


class PKCEOIDCAuthenticationCallbackView(OIDCAuthenticationCallbackView):
    """Rule 3: Override get_backend_kwargs(), NOT get()."""

    def get_backend_kwargs(self, request):
        kwargs = super().get_backend_kwargs(request)
        code_verifier = request.session.pop("pkce_code_verifier", None)
        if code_verifier is None:
            logger.warning("No pkce_code_verifier in session")
        kwargs.update({"code_verifier": code_verifier})
        return kwargs


class PKCEAuthenticationBackend(auth.Backend):
    """Rule 2 + Rule 4 + §6.2: Public client, DID lookup, Sovereign Posture."""

    def authenticate(self, request, code_verifier=None, **kwargs):
        if not request:
            return None

        code = request.GET.get("code")
        state = request.GET.get("state")
        if not (code and state):
            return None

        token_payload = {
            "client_id": self._get_setting("OIDC_RP_CLIENT_ID"),
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": absolutify(
                request, reverse(self._get_setting(
                    "OIDC_AUTHENTICATION_CALLBACK_URL",
                    "oidc_authentication_callback",
                ))
            ),
        }
        if code_verifier:
            token_payload["code_verifier"] = code_verifier

        try:
            resp = requests.post(
                self._get_setting("OIDC_OP_TOKEN_ENDPOINT"),
                data=token_payload,
                verify=self._get_setting("OIDC_VERIFY_SSL", True),
                timeout=self._get_setting("OIDC_TIMEOUT", 10),
            )
            resp.raise_for_status()
            token_info = resp.json()
        except requests.RequestException:
            logger.error("Token exchange failed")
            return None

        if "error" in token_info:
            return None

        try:
            resp = requests.get(
                self._get_setting("OIDC_OP_USER_ENDPOINT"),
                headers={"Authorization": f"Bearer {token_info['access_token']}"},
                verify=self._get_setting("OIDC_VERIFY_SSL", True),
                timeout=self._get_setting("OIDC_TIMEOUT", 10),
            )
            resp.raise_for_status()
            user_info = resp.json()
        except requests.RequestException:
            logger.error("UserInfo request failed")
            return None

        return self._get_or_create_user(user_info)

    def get_user(self, user_id):
        from django.contrib.auth import get_user_model
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            return None

    def _get_or_create_user(self, user_info):
        """Rule 4: username = sub. §6.2: Sovereign Admin Posture."""
        sub = user_info.get("sub")
        if not sub:
            return None

        from django.contrib.auth import get_user_model
        User = get_user_model()

        user, created = User.objects.get_or_create(
            username=sub,
            defaults={"email": user_info.get("email", "")},
        )

        evaluate_sovereign_admin_posture(user)

        return user

    @staticmethod
    def _get_setting(key, default=None):
        from django.conf import settings as _s
        return getattr(_s, key, default)
```

### 9.8 Compliance Checklist for New Satellites

When onboarding a new satellite, verify these items before marking it as aligned:

- [ ] `OIDC_RP_SCOPES = "openid profile email"` (matches IDP default, §3)
- [ ] Backend inherits `auth.Backend` (not `OIDCAuthenticationBackend`)
- [ ] Callback overrides `get_backend_kwargs()` (not `get()`)
- [ ] `get_or_create(username=sub)` — no email-based lookup (Rule 4)
- [ ] `evaluate_sovereign_admin_posture(user)` called after `get_or_create()` (§6.2)
- [ ] `user.save(update_fields=[...])` — not full model save
- [ ] `try/except requests.RequestException` on all HTTP calls
- [ ] `SECURE_PROXY_SSL_HEADER` present in settings (Rule 1)
- [ ] `OIDC_RP_CLIENT_SECRET` absent from codebase and container manifests (Rule 2)
