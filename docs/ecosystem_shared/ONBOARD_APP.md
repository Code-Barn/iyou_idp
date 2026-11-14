# ONBOARD_APP.md — Canonical Satellite App Onboarding Standard & OIDC Contract

**Single Source of Truth for scaffolding, authenticating, and deploying satellite applications in the `iyou_` sovereign mesh.**
**Maintained by:** `omni_social` (central hub)
**Status:** Mandatory & Immutable — follow verbatim for 100% first-run authentication and deployment alignment.

---

## Mandatory 5-Part Onboarding Architecture

Every satellite application in the `iyou_` ecosystem must implement this exact 5-part contract without deviation to prevent setting drift, split-brain cluster URLs, cross-subdomain cookie collisions, or divergent `auth_pkce.py` behavior.

---

### 1. Identity & OIDC URL Contract (Immutable)

- **External (Browser-Facing) Authorize Endpoint:**
  `OIDC_OP_AUTHORIZATION_ENDPOINT = "https://iyou.me/openid/authorize/"`
- **Internal Cluster Back-Channel Endpoints (Direct Pod-to-Pod via CoreDNS):**
  - `OIDC_OP_TOKEN_ENDPOINT = "http://iyou-idp.identity.svc.cluster.local/openid/token/"` (Port 80 ClusterIP)
  - `OIDC_OP_USER_ENDPOINT = "http://iyou-idp.identity.svc.cluster.local/openid/userinfo/"`
  - `OIDC_OP_JWKS_ENDPOINT = "http://iyou-idp.identity.svc.cluster.local/openid/jwks/"`

> **Note:** Must strictly use `/openid/`, **NEVER** `/oidc/`. The Kubernetes `ClusterIP` service port in the `identity` namespace is `80` (not `8000`).

---

### 2. Satellite Django `config/settings.py` Standard

Every satellite Django app must define:

```python
# Session & Proxy Security (App-Scoped signed cookies to prevent collisions across *.iyou.me)
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True
SESSION_COOKIE_NAME = env("SESSION_COOKIE_NAME", default=f"{APP_SLUG}_sessionid")
CSRF_COOKIE_NAME = env("CSRF_COOKIE_NAME", default=f"{APP_SLUG}_csrftoken")
SESSION_COOKIE_DOMAIN = None  # Strictly host-only, never wildcard .iyou.me
CSRF_COOKIE_DOMAIN = None
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False

# OIDC Client Configuration (PKCE Public Client)
OIDC_RP_CLIENT_ID = env("OIDC_RP_CLIENT_ID", default=f"iyou-{APP_SLUG}-satellite-client")
OIDC_RP_CLIENT_SECRET = None  # None for Public PKCE clients
OIDC_RP_SIGN_ALGO = "RS256"
OIDC_RP_SCOPES = "openid profile email"

# Endpoints
OIDC_OP_AUTHORIZATION_ENDPOINT = env("OIDC_OP_AUTHORIZATION_ENDPOINT", default="https://iyou.me/openid/authorize/")
OIDC_OP_TOKEN_ENDPOINT = env("OIDC_OP_TOKEN_ENDPOINT", default="http://iyou-idp.identity.svc.cluster.local/openid/token/")
OIDC_OP_USER_ENDPOINT = env("OIDC_OP_USER_ENDPOINT", default="http://iyou-idp.identity.svc.cluster.local/openid/userinfo/")
OIDC_OP_JWKS_ENDPOINT = env("OIDC_OP_JWKS_ENDPOINT", default="http://iyou-idp.identity.svc.cluster.local/openid/jwks/")

# Authentication Backend
AUTHENTICATION_BACKENDS = [
    "apps.core.auth_pkce.PKCEAuthenticationBackend",  # Canonical backend
    "django.contrib.auth.backends.ModelBackend",
]
LOGIN_URL = "/oidc/authenticate/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"
```

---

### 3. Standard URL Routing (`config/urls.py`)

Wire the canonical PKCE views and compatibility aliases in `config/urls.py`:

```python
from django.urls import path
from apps.core.auth_pkce import (
    PKCEOIDCAuthenticationRequestView,
    PKCEOIDCAuthenticationCallbackView,
    PKCEOIDCLogoutView,
)

urlpatterns = [
    path("oidc/authenticate/", PKCEOIDCAuthenticationRequestView.as_view(), name="oidc_authentication_init"),
    path("oidc/callback/", PKCEOIDCAuthenticationCallbackView.as_view(), name="oidc_authentication_callback"),
    path("oidc/logout/", PKCEOIDCLogoutView.as_view(), name="oidc_logout"),
    # Compatibility aliases
    path("accounts/login/", PKCEOIDCAuthenticationRequestView.as_view()),
    path("accounts/logout/", PKCEOIDCLogoutView.as_view()),
]
```

---

### 4. Helm `values.yaml` Contract (`k3s_vm/apps/iyou-<slug>/`)

Every Helm chart in the fleet must supply these exact environment variables:

```yaml
env:
  DEBUG: "False"
  ALLOWED_HOSTS: "<slug>.iyou.me,.<slug>.iyou.me,127.0.0.1,localhost,iyou-<slug>"
  CSRF_TRUSTED_ORIGINS: "https://<slug>.iyou.me,https://*.<slug>.iyou.me"
  OIDC_RP_CLIENT_ID: "iyou-<slug>-satellite-client"
  OIDC_OP_AUTHORIZATION_ENDPOINT: "https://iyou.me/openid/authorize/"
  OIDC_OP_TOKEN_ENDPOINT: "http://iyou-idp.identity.svc.cluster.local/openid/token/"
  OIDC_OP_USER_ENDPOINT: "http://iyou-idp.identity.svc.cluster.local/openid/userinfo/"
  OIDC_OP_JWKS_ENDPOINT: "http://iyou-idp.identity.svc.cluster.local/openid/jwks/"
  SESSION_COOKIE_NAME: "<slug>_sessionid"
  CSRF_COOKIE_NAME: "<slug>_csrftoken"
  SESSION_COOKIE_SECURE: "True"
  CSRF_COOKIE_SECURE: "True"
  SECURE_PROXY_SSL_HEADER: "HTTP_X_FORWARDED_PROTO,https"
```

---

### 5. Verification Checklist for Any New App

Before marking any satellite app as operational, verify:

- [ ] **Registered in `iyou-idp` client seeder** (`require_consent: False`, `reuse_consent: True`, PKCE public client, client ID `iyou-<slug>-satellite-client`, redirect URI `https://<slug>.iyou.me/oidc/callback/`).
- [ ] **Database migrations applied** (`auth_user` and `django_session` tables must exist).
- [ ] **Back-channel smoke test:** container can `curl http://iyou-idp.identity.svc.cluster.local/openid/jwks/` with HTTP 200.
- [ ] **Canonical `auth_pkce.py` installed:** copied verbatim from `omni_social/templates/core/auth_pkce.py` (synced to `docs/ecosystem_shared/auth_pkce.py`) into `apps/core/auth_pkce.py`:
  - `PKCEAuthenticationBackend` inherits from `ModelBackend` and implements `get_user(self, user_id)` for session rehydration.
  - Explicitly implements `verify_claims(self, claims)` checking `"sub" in claims` (never requiring `"email" in claims`, which fails for W3C DID subjects `did:key:...`):
    ```python
    def verify_claims(self, claims):
        if not claims or "sub" not in claims:
            return False
        return True
    ```
  - Decodes `sub` (W3C DID format `did:key:...` or `did:web:...`) into a deterministic user without crashing (`get_username` / `_normalize_sub_to_username`).
  - Sends back-channel `POST` to `OIDC_OP_TOKEN_ENDPOINT` formatted as `data=...` (`application/x-www-form-urlencoded`, never `json=...`).
  - Logs exact HTTP status and response body on non-200 token/userinfo responses before raising or returning an error.
  - Auto-creates the user (`set_unusable_password()`) and establishes the Django session via `django.contrib.auth.login(request, user, backend=...)`.
- [ ] **Automated Satellite Validator passes with 0 issues:**
  ```bash
  python scripts/audit_satellite_auth.py ../iyou_<slug>
  # Or auto-heal with:
  python scripts/audit_satellite_auth.py ../iyou_<slug> --fix
  ```

---

## UI Layer Stack & Template Integration

Every app joining the `iyou_` ecosystem must also satisfy the two shared UI layers managed by `omni_social`:

| Layer | Component | Owner | Purpose |
|:---|:---|:---|:---|
| **Layer 0** | Ecosystem bar (`_ecosystem_bar.html`) | `omni_social` | Mesh-wide navigation — fixed top bar linking all 22 ecosystem apps |
| **Layer 1** | Standard header (`_standard_header.html`) | `omni_social` | App identity — name, accent color, auth state, sign in/out |

### 22-App Ecosystem Roster (Protocol Order)

```
idp / wun / poly / name / hive / ride / dctech / safe / talk / clar / play / blog / help / draw / life / walk / stay / dev / spot / baba / chat / dine
```

### Automated Integration Script

```bash
cd ~/CODE_BASE/omni_social
python scripts/ecosystem_integration.py <slug> <color> --repo-dir ~/CODE_BASE/iyou_<app>/ --description "Your app description"
```

### Generating Header Templates

```bash
# Flat layout (play, wun, poly, name, safe, talk, help, draw, life, walk, stay, dev, spot, baba, chat, dine)
python scripts/generate_templates.py <slug> <color> --output-dir ~/CODE_BASE/iyou_<app>/templates/includes/

# Django project layout (ride)
python scripts/generate_templates.py <slug> <color> --output-dir ~/CODE_BASE/iyou_<app>/apps/core/templates/includes/

# Deep Django layout (dctech, clar, blog)
python scripts/generate_templates.py <slug> <color> --output-dir ~/CODE_BASE/iyou_<app>/apps/core/templates/core/includes/
```

### Wiring the 3-Layer Stack in `base.html`

```html
<body class="bg-gray-100 min-h-screen">
  {% include "includes/_ecosystem_bar.html" %}
  {% include "includes/_standard_header.html" %}
  <!-- Layer 2: app-specific fixed header at top-[52px] z-50 (if any) -->
  <main class="pt-[108px]">
    {% block content %}{% endblock %}
  </main>
</body>
```

### Propagating Shared Specs

```bash
python scripts/sync_ecosystem_specs.py
```
