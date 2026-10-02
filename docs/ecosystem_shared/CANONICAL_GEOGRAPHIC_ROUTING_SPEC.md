# Canonical Geographic Subdomain Routing Specification

**Specification ID:** SPEC-008  
**Title:** Multi-Tier Geographic Subdomain Routing & Locality Scoping Standard  
**Status:** Approved / Standard  
**Maintainer:** Omni Social Hub Core  
**Applicability:** All satellite applications with localized content (`iyou_*`)

---

## 1. Scope & Objective

This specification establishes the ecosystem standard for multi-tier geographic subdomain routing without requiring explicit per-locality DNS records.

Any satellite supporting locality-based discovery (e.g. `iyou_play`, `iyou_talk`, `iyou_poly`, `iyou_wun`, `iyou_life`, `iyou_safe`, `iyou_walk`, `iyou_stay`, `iyou_clar`) MUST implement this standard to guarantee consistent behavior, fail-closed security, cross-subdomain session isolation, and test parity.

---

## 2. Infrastructure Architecture

### 2.1 Authoritative DNS Record
- **Provider:** 1984.is (Sovereign DNS)
- **Apex Wildcard:** Standard RFC 1034 / RFC 4592 wildcard A record pointing to the edge proxy:
  ```zone
  *.iyou.me.   900   IN   A   89.127.234.121
  ```
- **Resolution Behavior:** This single record recursively resolves all nested subdomains (e.g., `dkc.il.us.play.iyou.me`, `il.us.play.iyou.me`, `play.iyou.me`) without needing per-locality entries or multi-wildcard syntax (`*.*.*.iyou.me`).

### 2.2 Edge Reverse Proxy (VPS)
- **Module:** Nginx Stream module (`ssl_preread on`)
- **Port 80:** Blind TCP passthrough to K3s cluster (`10.0.0.2:80`).
- **Port 443:** SNI inspection via `ssl_preread`. Routes `cdn.iyou.me` to local cache; forwards all other traffic to K3s Traefik ingress (`10.0.0.2:443`).

### 2.3 Kubernetes Cluster Ingress (K3s / Traefik)
- **Standard Ingress:** For apex satellite domain (`<app>.iyou.me`).
- **Traefik IngressRoute CRD:** To match recursive subdomains without losing the `Host` header:
  ```yaml
  apiVersion: traefik.io/v1alpha1
  kind: IngressRoute
  metadata:
    name: {{ include "<app>.fullname" . }}-wildcard
  spec:
    entryPoints:
      - websecure
    routes:
      - match: HostRegexp(`{subdomain:[a-z0-9.-]+}.<app>.iyou.me`)
        kind: Rule
        services:
          - name: {{ include "<app>.fullname" . }}
            port: 80
    tls:
      secretName: {{ .Values.ingress.tls.secretName }}
  ```

---

## 3. Django Settings Contract

Each satellite app MUST define the following configuration in `config/settings.py`:

```python
import environ

env = environ.Env()

# 1. Base Domain Setting
APP_BASE_DOMAIN = env("<APP>_BASE_DOMAIN", default="<app>.iyou.me")

# 2. ALLOWED_HOSTS with Leading-Dot Wildcard
# In Django, a leading dot matches the domain AND all its subdomains recursively
ALLOWED_HOSTS = env.list(
    "DJANGO_ALLOWED_HOSTS",
    default=[f".{APP_BASE_DOMAIN}", "localhost", "127.0.0.1", ".localhost"],
)

# 3. CSRF Trusted Origins for Cross-Subdomain Form Posts
CSRF_TRUSTED_ORIGINS = [
    f"https://*.{APP_BASE_DOMAIN}",
    f"https://{APP_BASE_DOMAIN}",
]

# 4. Proxy Headers (Preserves Host Header Dots)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

# 5. Cookie Scoping
# Bound strictly to the satellite base domain (.app.iyou.me)
# MUST NOT be scoped to apex (.iyou.me) to prevent cross-satellite session leakage
SESSION_COOKIE_NAME = "<app>_sessionid"
CSRF_COOKIE_NAME = "<app>_csrftoken"
SESSION_COOKIE_DOMAIN = f".{APP_BASE_DOMAIN}"
CSRF_COOKIE_DOMAIN = f".{APP_BASE_DOMAIN}"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
```

---

## 4. Canonical Middleware Implementation

### 4.1 Geo Data Module (`apps/core/geo_data.py`)

```python
"""Geographic and Locality Static Validation Sets for apps.core."""

from __future__ import annotations

# ISO-3166-1 alpha-2 lowercase country codes
VALID_COUNTRIES: frozenset[str] = frozenset({
    "us", "uk", "ca", "mx", "br", "de", "fr", "es", "it", "jp",
    "cn", "in", "au", "ru", "za", "kr", "se", "no", "fi", "dk",
    "nl", "be", "at", "ch", "pt", "ie", "nz", "sg", "il", "ae",
    "sa", "eg", "ng", "ke", "gh", "tz", "ar", "cl", "co", "pe",
    "ve", "ec", "bo", "py", "uy", "cr", "pa", "cu", "jm", "tt",
    "ht", "do", "hn", "sv", "ni", "gt", "bz", "pr", "gl", "pl",
    "cz", "ro", "hu", "ee", "lv", "lt", "is",
})

# Two-letter US state and territory postal abbreviations (lowercase)
VALID_US_STATES: frozenset[str] = frozenset({
    "al", "ak", "az", "ar", "ca", "co", "ct", "de", "fl", "ga",
    "hi", "id", "il", "in", "ia", "ks", "ky", "la", "me", "md",
    "ma", "mi", "mn", "ms", "mo", "mt", "ne", "nv", "nh", "nj",
    "nm", "ny", "nc", "nd", "oh", "ok", "or", "pa", "ri", "sc",
    "sd", "tn", "tx", "ut", "vt", "va", "wa", "wv", "wi", "wy",
    "dc", "pr", "vi", "gu", "as", "mp",
})

# Subdomains reserved for system operations (exempt from geographic containment)
SYSTEM_SUBDOMAINS: frozenset[str] = frozenset({
    "api", "admin", "static", "media", "ws", "relay", "auth", "blossom", "mods", "devs",
})

# Hierarchical jurisdiction depth mappings
JURISDICTION_TIERS: dict[int, str] = {
    1: "country",
    2: "state",
    3: "county",
    4: "city",
    5: "ward",
}
```

### 4.2 Middleware (`apps/core/middleware.py`)

```python
"""Geographic Subdomain Routing & Jurisdictional Containment Middleware."""

from __future__ import annotations

import ipaddress
from typing import Callable

from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponse

from .geo_data import JURISDICTION_TIERS, SYSTEM_SUBDOMAINS, VALID_COUNTRIES, VALID_US_STATES


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class GeographicRoutingMiddleware:
    """Extracts geographic locality from right-to-left subdomain tokens."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # 1. Health checks and cluster probes bypass
        if request.path_info in ("/health/", "/healthz"):
            self._set_global_scope(request)
            return self.get_response(request)

        try:
            host = request.get_host().split(":")[0].strip().lower()
        except Exception:
            host = (request.META.get("HTTP_HOST") or "localhost").split(":")[0].strip().lower()

        base_domain = getattr(settings, "<APP>_BASE_DOMAIN", "<app>.iyou.me").lower()

        # 2. Development, cluster IP, and apex root bypass
        if (
            host == base_domain
            or host in ("localhost", "127.0.0.1", "testserver")
            or _is_ip(host)
            or host.endswith(".cluster.local")
        ):
            self._set_global_scope(request)
            return self.get_response(request)

        # 3. Strip base domain / localhost dev suffix
        subdomain = ""
        if host.endswith("." + base_domain):
            subdomain = host[: -len("." + base_domain)]
        elif host.endswith(".localhost"):
            subdomain = host[: -len(".localhost")]
        elif host.endswith(".testserver"):
            subdomain = host[: -len(".testserver")]
        else:
            self._set_global_scope(request)
            return self.get_response(request)

        # Strip www. if present
        if subdomain.startswith("www."):
            subdomain = subdomain[4:]
        if not subdomain:
            self._set_global_scope(request)
            return self.get_response(request)

        # 4. Check for system subdomains
        tokens = subdomain.split(".")
        if tokens[0] in SYSTEM_SUBDOMAINS or tokens[-1] in SYSTEM_SUBDOMAINS:
            self._set_global_scope(request)
            return self.get_response(request)

        # 5. Right-to-left evaluation
        # Country token (tokens[-1])
        country = tokens[-1]
        if country not in VALID_COUNTRIES:
            raise Http404(f"Invalid country code in geographic scope: '{country}'")

        # State token (tokens[-2])
        if len(tokens) >= 2 and country == "us":
            state = tokens[-2]
            if state not in VALID_US_STATES:
                raise Http404(f"Invalid state code in geographic scope: '{state}'")

        # 6. Reconstruct canonical scope & jurisdiction level
        depth = len(tokens)
        if tokens[0].startswith("ward") or depth >= 5:
            jurisdiction_level = "ward"
        elif depth == 4:
            jurisdiction_level = "city"
        elif depth == 3:
            jurisdiction_level = "county"
        elif depth == 2:
            jurisdiction_level = "state"
        elif depth == 1:
            jurisdiction_level = "country"
        else:
            jurisdiction_level = JURISDICTION_TIERS.get(depth, "locality")

        request.geographic_scope = ".".join(tokens)
        request.scope_tokens = tuple(tokens)
        request.jurisdiction_level = jurisdiction_level

        return self.get_response(request)

    @staticmethod
    def _set_global_scope(request: HttpRequest) -> None:
        request.geographic_scope = None
        request.scope_tokens = ()
        request.jurisdiction_level = None
```

---

## 5. Canonical Test Suite (13 Core Scenarios)

Every satellite implementing this specification MUST maintain a test suite matching the following 13 cases (`tests/test_geographic_middleware.py`):

1. **`test_bare_domain_returns_global_scope`:** `<app>.iyou.me` $\rightarrow$ `scope is None`
2. **`test_single_country_code`:** `us.<app>.iyou.me` $\rightarrow$ `scope == "us"`, `level == "country"`
3. **`test_state_country_hierarchy`:** `il.us.<app>.iyou.me` $\rightarrow$ `scope == "il.us"`, `level == "state"`
4. **`test_county_state_country_hierarchy`:** `dkc.il.us.<app>.iyou.me` $\rightarrow$ `scope == "dkc.il.us"`, `level == "county"`
5. **`test_city_tier_hierarchy`:** `chi.cook.il.us.<app>.iyou.me` $\rightarrow$ `scope == "chi.cook.il.us"`, `level == "city"`
6. **`test_ward_tier_hierarchy`:** `ward5.chi.cook.il.us.<app>.iyou.me` $\rightarrow$ `scope == "ward5.chi.cook.il.us"`, `level == "ward"`
7. **`test_system_keyword_bypasses_geographic`:** `admin.<app>.iyou.me` $\rightarrow$ `scope is None`
8. **`test_api_keyword_bypasses_geographic`:** `api.<app>.iyou.me` $\rightarrow$ `scope is None`
9. **`test_www_stripped_correctly`:** `www.<app>.iyou.me` $\rightarrow$ `scope is None`
10. **`test_invalid_country_raises_404`:** `il.xx.<app>.iyou.me` $\rightarrow$ raises `Http404`
11. **`test_invalid_state_raises_404`:** `dkc.zz.us.<app>.iyou.me` $\rightarrow$ raises `Http404`
12. **`test_localhost_bare_returns_global`:** `localhost:8000` $\rightarrow$ `scope is None`
13. **`test_localhost_with_geo`:** `us.localhost:8000` $\rightarrow$ `scope == "us"`

---

## 6. Production Ingress & TLS Architecture

### 6.1 The HTTP-01 Wildcard Trap & Order Stalling
In Kubernetes clusters running cert-manager with Let's Encrypt HTTP-01 solvers (`letsencrypt-prod`), requesting wildcard domains such as `*.app.iyou.me` causes ACME Certificate requests and Challenge orders to **stall indefinitely**.

This occurs because:
1. **Boulder Protocol Enforcement:** The ACME specification (RFC 8555 §8.4) and Let's Encrypt's Boulder CA implementation strictly reject HTTP-01 challenges for wildcard identifiers (`acme:error:malformed: Cannot issue for wildcard domain: HTTP-01 challenge not supported`). Wildcard domains require DNS-01 verification.
2. **RFC 6125 Single-Label Limitation:** Even under DNS-01 validation, an x509 wildcard certificate (`*.app.iyou.me`) only validates a single domain label depth (`us.<app>.iyou.me`). It DOES NOT match multi-tier geographic subdomains such as `il.us.<app>.iyou.me` or `dkc.il.us.<app>.iyou.me`.
3. **Fallback Degrade:** When cert-manager stalls or fails to provision a certificate, Traefik serves its default self-signed certificate (`TRAEFIK DEFAULT CERT`), causing browser TLS warnings and API connection termination.

### 6.2 The Production Standard: Explicit Multi-SAN HTTP-01 Certificates
To achieve fully automated, trusted TLS across multi-tier geographic subdomains under sovereign network policies (without commercial DNS APIs), all satellite applications MUST use the **Multi-SAN HTTP-01** configuration established in production by `iyou_clar` (`k3s_vm/apps/iyou-clar/values.yaml`).

Helm chart `values.yaml` manifests MUST explicitly declare every tier of the geographic hierarchy under BOTH `ingress.hosts` and `ingress.tls.hosts`:

```yaml
ingress:
  enabled: true
  className: traefik
  clusterIssuer: letsencrypt-prod
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: <app>.iyou.me
      paths:
        - path: /
          pathType: ImplementationSpecific
    - host: us.<app>.iyou.me
      paths:
        - path: /
          pathType: ImplementationSpecific
    - host: il.us.<app>.iyou.me
      paths:
        - path: /
          pathType: ImplementationSpecific
    - host: dkc.il.us.<app>.iyou.me
      paths:
        - path: /
          pathType: ImplementationSpecific
  tls:
    - secretName: iyou-<app>-tls-http01
      hosts:
        - <app>.iyou.me
        - us.<app>.iyou.me
        - il.us.<app>.iyou.me
        - dkc.il.us.<app>.iyou.me
```

Because each SAN is a concrete fully qualified domain name (FQDN), cert-manager spins up standard HTTP-01 challenge pods and solves `/.well-known/acme-challenge/` tokens over port 80, obtaining a single valid, multi-SAN production certificate from Let's Encrypt.

### 6.3 Traefik IngressRoute Subdomain Capture
While standard Ingress resources handle ACME challenge path routing and TLS secret association, routing dynamic locality subdomains through the proxy to the container service MUST be handled via Traefik's `IngressRoute` CRD.

The `IngressRoute` MUST match subdomains using `HostRegexp` with dot-preservation regex:

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: {{ include "<app>.fullname" . }}-wildcard
spec:
  entryPoints:
    - websecure
  routes:
    - match: HostRegexp(`{subdomain:[a-z0-9.-]+}.<app>.iyou.me`)
      kind: Rule
      services:
        - name: {{ include "<app>.fullname" . }}
          port: {{ .Values.service.port }}
  tls:
    secretName: {{ .Values.ingress.tls[0].secretName }}
```

This ensures Traefik forwards all nested locality requests to Django with the full hostname intact, enabling `GeographicRoutingMiddleware` to parse and tokenize `request.get_host()` right-to-left.

---

## 7. Cross-Satellite Deep Linking Protocol (Wun <-> Poly)

### 7.1 Canonical Deep Link Formats
Cross-satellite references between civic deliberation (`iyou_wun`) and decisive voting dockets (`iyou_poly`) MUST strictly preserve the active geographic scope across subdomain hops.

1. **Wun Deliberation $\rightarrow$ Poly Voting Docket:**
   - **Scoped:** `https://{scope}.poly.iyou.me/dockets/{docket_identifier}/?origin_event={nostr_event_id}`
   - **Global:** `https://poly.iyou.me/dockets/{docket_identifier}/?origin_event={nostr_event_id}`
   - *Semantics:* Directs citizens from a Nostr deliberation thread on Wun directly to the corresponding voting docket on Poly. The `origin_event` query parameter anchors the ballot to the original deliberation thread event hash.

2. **Poly Ballot $\rightarrow$ Wun Discussion Thread:**
   - **Scoped:** `https://{scope}.wun.iyou.me/feed?thread={nostr_event_id}` (fallback: `https://{scope}.wun.iyou.me/feed?docket={docket_id}`)
   - **Global:** `https://wun.iyou.me/feed?thread={nostr_event_id}` (fallback: `https://wun.iyou.me/feed?docket={docket_id}`)
   - *Semantics:* Directs voting participants from Poly's voting chambers to the public deliberation feed on Wun. If the primary `nostr_event_id` is unknown, the satellite falls back to querying `?docket={docket_id}` to resolve the thread.

3. **Global Mesh Fallback:**
   - When `request.geographic_scope` is null, empty, or equals global scope, the `{scope}.` subdomain prefix **MUST BE OMITTED**:
     - `https://poly.iyou.me/dockets/{docket_identifier}/` $\longleftrightarrow$ `https://wun.iyou.me/feed?thread={nostr_event_id}`

### 7.2 Django Server-Side URL Builder Pattern
All satellites implementing SPEC-008 MUST provide the standard `build_scoped_url` utility (e.g. inside `apps/core/utils.py` or as a template tag):

```python
from django.http import HttpRequest


def build_scoped_url(target_app: str, path: str, request: HttpRequest) -> str:
    """Build a cross-satellite URL preserving the active geographic scope."""
    scope = getattr(request, "geographic_scope", None)
    base_host = f"{scope}.{target_app}.iyou.me" if scope else f"{target_app}.iyou.me"
    clean_path = path if path.startswith("/") else f"/{path}"
    return f"https://{base_host}{clean_path}"
```

In Django templates, satellites can expose this via a simple template filter or tag:
```django
<a href="{% scoped_url 'poly' docket.get_absolute_url %}" class="...">Vote on Ballot ↗</a>
```

### 7.3 Client-Side Scope Anchor Contract
For dynamic card rendering, client-side SPA views, and Nostr event renderers where HTML is generated in the browser, anchors targeting sibling satellites MUST include the `data-cross-satellite="{slug}"` attribute:

```html
<!-- Authored in Wun client card renderer -->
<a href="/dockets/dkt-2026-chi-042/" data-cross-satellite="poly" class="docket-link">
  Civic Ballot #42 ↗
</a>
```

During DOM hydration, client scripts scan for `[data-cross-satellite]` and dynamically prefix the active hostname scope:

```javascript
function hydrateCrossSatelliteAnchors() {
  const host = window.location.hostname.toLowerCase();
  const match = host.match(/^([a-z0-9-]+(?:\.[a-z0-9-]+)*)\.(?:[a-z0-9_-]+)\.iyou\.me$/);
  if (!match) return;
  const scope = match[1];
  const reserved = ['api', 'admin', 'ws', 'relay', 'localhost', '127.0.0.1', 'auth', 'media', 'static', 'blossom'];
  if (reserved.includes(scope)) return;

  document.querySelectorAll('a[data-cross-satellite]').forEach(el => {
    const targetSlug = el.getAttribute('data-cross-satellite');
    if (!targetSlug || targetSlug === 'idp' || targetSlug === 'dev') return;
    const path = el.getAttribute('href') || '/';
    const cleanPath = path.startsWith('/') ? path : '/' + path;
    el.href = `https://${scope}.${targetSlug}.iyou.me${cleanPath}`;
  });
}
```
This guarantees that deep links rendered via WebSocket pushes, Nostr event feeds, and asynchronous fetch updates never strip the user's locality jurisdiction.

