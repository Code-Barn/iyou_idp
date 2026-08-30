# Omni-Social Developer Translation Manual
### Building Satellites, Autonomous Clients & Interoperable Adapters

**Document Identifier:** `OMNI-DEV-MANUAL-V1`  
**Hub:** `omni_social`  
**Status:** Living Canonical Manual  
**Published:** 2026-08-30  
**Target Implementers:** Full-Stack Developers, Satellite Application Authors, UI/UX Integrators, Native Client Engineers  

---

## 1. Introduction & Developer Philosophy

The **Omni-Social Developer Translation Manual** provides the definitive, step-by-step engineering blueprint for creating new satellite applications, native clients, and protocol adapters that integrate into the Omni-Social sovereign mesh.

### 1.1 The Four Core Developer Invariants

Every application adhering to the Omni-Social standard MUST implement four architectural invariants:

1. **Secretless Authentication (Zero Shared Secrets):** Satellites are configured as **public OIDC clients** using PKCE S256 (`code_challenge_method=S256`). No client secrets are stored in satellite repositories or environment variables. Identity is anchored strictly by the `sub` claim which carries the user's W3C Decentralized Identifier (`did:key:z6Mk...`).
2. **Local-First Enclave Delegation:** High-assurance cryptographic operations (key management, DID presentation signing, Nostr event signing) are delegated to the local desktop/mobile enclave via the **Local Signature Bridge** on port `9001`.
3. **Strict UI Layout Hierarchy:** The visual hierarchy is structured in three strictly decoupled layers: **Layer 0** (Universal Ecosystem Navigation Bar), **Layer 1** (Standard Identity Header), and **Layer 2** (Application Canvas).
4. **Content-Addressed Data Storage:** High-volume user media and attachments are stored via **Blossom (BUD-01)** binary addressing and broadcast as Nostr `kind:1063` metadata events, keeping local relational databases (PostgreSQL/SQLite) purely as ephemeral query caches.

---

## 2. UI Layout Hierarchy & Presentation Specification

The Omni-Social visual interface is organized into a three-layer stack designed to provide continuous ecosystem awareness and sovereign identity controls without layout interference.

```
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 0: Ecosystem Bar (fixed top-0, z-[9999], 4px collapsed peek)     │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Standard Identity Header (sticky top, backdrop-blur, z-[50])  │
│ [ iyou_app_name ]                       [ ● did:key:z6Mk... | Logout ] │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 2: App Canvas & Viewport                                         │
│                                                                        │
│                       Application Content Area                         │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 2.1 Layer 0: Universal Ecosystem Navigation Bar (`_ecosystem_bar.html`)

The Ecosystem Bar sits at the absolute top of the viewport. It provides rapid switching across all applications in the federation while actively probing the presence of the local sovereign key enclave.

#### Functional Specifications:
- **Collapsed State:** Floats fixed at `top: 0, left: 0, width: 100%` with a subtle 4px bottom hint (`transform -translate-y-[calc(100%-4px)]`).
- **Expanded State:** Slides smoothly down to full height (`h-9`, 36px) upon cursor hover (`hover:translate-y-0 transition-all duration-300 ease-in-out`).
- **Z-Index:** Set to `z-[9999]` to guarantee overlay dominance over all application modals.
- **Roster Protocol Order:** Links all 19 ecosystem applications in the canonical protocol order:
  ```
  idp / wun / poly / name / hive / ride / dctech / safe / talk / clar / play / blog / help / draw / life / walk / stay / dev / spot
  ```
- **Active Application Indicator:** The currently active application link is rendered with `text-white font-bold tracking-normal snap-start`, and the top bar border is styled with the app's accent color (`border-b border-{color}-600/50`).
- **Mobile Horizontal Snap:** Renders with `overflow-x-auto whitespace-nowrap snap-x snap-mandatory` and hides native scrollbars across WebKit and Gecko engines.
- **Enclave Health Probe:** Includes a background probe script that queries the local signature bridge at `http://127.0.0.1:9001/` with a 300ms timeout every 15 seconds, toggling enclave connectivity indicators without blocking the main thread.

#### Canonical Template Reference (`_ecosystem_bar.html`):
```html
<style>
    #sovereign-ecosystem-topbar .sovereign-scroll::-webkit-scrollbar { display: none; }
    #sovereign-ecosystem-topbar .sovereign-scroll { scrollbar-width: none; }
</style>
<div id="sovereign-ecosystem-topbar"
     class="fixed top-0 left-0 w-full z-[9999] transform -translate-y-[calc(100%-4px)] hover:translate-y-0 transition-all duration-300 ease-in-out bg-slate-950 border-b border-__COLOR__-600/50 text-slate-400 px-4 py-1.5 shadow-2xl flex items-center h-9 min-h-[36px] max-h-[40px] font-mono text-[11px]">
    <span class="text-__COLOR__-400 font-bold tracking-wider uppercase shrink-0 mr-3">SOVEREIGN MESH:</span>
    <div class="sovereign-scroll flex items-center gap-4 overflow-x-auto whitespace-nowrap snap-x snap-mandatory scroll-smooth flex-1 min-w-0 -mb-px pb-px">
        <a href="https://iyou.me" class="text-slate-400 hover:text-white transition-colors duration-150 snap-start shrink-0">idp</a>
        <span class="text-slate-800 shrink-0">/</span>
        <a href="https://wun.iyou.me" class="text-slate-400 hover:text-white transition-colors duration-150 snap-start shrink-0">wun</a>
        <span class="text-slate-800 shrink-0">/</span>
        <a href="https://__SLUG__.iyou.me" class="text-white font-bold tracking-normal snap-start shrink-0">__SLUG__</a>
        <!-- additional roster links -->
    </div>
</div>
```

---

### 2.2 Layer 1: Universal Standard Identity Header (`_standard_header.html`)

The Standard Identity Header anchors the user's sovereign authentication status, theme preferences, and primary identity actions.

#### Functional Specifications:
- **Visual Styling:** Translucent sticky header (`backdrop-blur-sm bg-white/90 dark:bg-[#0B0F19]/90`) with subtle lower border (`border-b border-slate-200 dark:border-gray-800`).
- **Brand Title:** Renders `iyou_` prefix in muted slate alongside the application prefix formatted in the unique accent color (e.g., `<span class="text-violet-400">_wun</span>`).
- **Authentication State Widget:**
  - **Authenticated (`request.user.is_authenticated`):** Displays an active green pulsing dot (`w-2 h-2 rounded-full bg-emerald-500 animate-pulse`), the truncated DID username (`max-w-[140px] sm:max-w-[220px] truncate`), and a "Sign Out" button linking to `{% url 'oidc_logout' %}`.
  - **Unauthenticated:** Displays an amber static dot (`w-2 h-2 rounded-full bg-amber-400`), an indicator text *"Sovereign Key Required"*, and a prominent "Sign In" button styled with the application's unique accent color linking to `{% url 'oidc_authentication_init' %}`.
- **Theme Switcher (`#theme-toggle`):** Integrated Sun/Moon SVG icons toggling dark mode across Tailwind `dark:` classes, persisting state in `localStorage.getItem('{slug}_theme')`.

#### Zero-Flash Anti-Flicker `<head>` Script:
To prevent unsightly white-screen flashes when dark mode users navigate pages, all base templates MUST embed the following script directly in the HTML `<head>` before any body rendering occurs:

```html
<script>
(function() {
  var storedTheme = localStorage.getItem('{{ app_slug }}_theme');
  if (storedTheme === 'dark' || (!storedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
})();
</script>
```

---

### 2.3 Layer 2: App Canvas Layout & Tailwind Static Build Rules

The Application Canvas contains the functional workspace of the satellite app.

#### Mandatory Rules:
1. **Viewport Offset:** The main content wrapper `<main>` must account for the header offset using `pt-4` or container padding to ensure content does not collide with the sticky Layer 1 header.
2. **Rule 7: No Runtime CSS Compilers:** Applications **MUST NOT** include `cdn.tailwindcss.com` runtime script tags in production. All Tailwind utility classes must be compiled statically into static CSS assets.
3. **Accent Color Constraint (No Duplicates):** Every application in the federation is assigned an immutable, unique Tailwind color from the canonical roster.

#### Assigned Accent Color Roster:

| Application | Slug | Accent Color | Hex Code | Primary Role |
|:---|:---|:---|:---|:---|
| `iyou_idp` | `idp` | *(None — System Root)* | `#64748B` | Root Identity Provider & OIDC Bridge |
| `iyou_wun` | `wun` | `violet` | `#8B5CF6` | Social Hub & Mesh Activity Feed |
| `iyou_poly` | `poly` | `purple` | `#A855F7` | Ecosystem Core & Governance Polling Engine |
| `iyou_name` | `name` | `teal` | `#14B8A6` | Family Tree & Genealogy Registry |
| `iyou_hive` | `hive` | `orange` | `#F97316` | Legal Vault & Document Management |
| `iyou_ride` | `ride` | `lime` | `#84CC16` | Sovereign Transit & Ride-Sharing Marketplace |
| `dc_tech_website`| `dctech`| `indigo` | `#6366F1` | Corporate Hardening & Engineering Hub |
| `iyou_safe` | `safe` | `rose` | `#F43F5E` | Crisis Triage & Web-of-Trust Attestation |
| `iyou_talk` | `talk` | `cyan` | `#06B6D4` | Sovereign Mental Support & Peer Counseling |
| `iyou_clar` | `clar` | `emerald` | `#10B981` | Directory Ledger & Verified Business Directory|
| `iyou_play` | `play` | `amber` | `#F59E0B` | Athletics Master & Sports Protocol (Reference) |
| `iyou_blog` | `blog` | `sky` | `#0EA5E9` | Sovereign Long-Form Publishing on Nostr |
| `iyou_help` | `help` | `red` | `#EF4444` | Help & Technical Support Portal |
| `iyou_draw` | `draw` | `fuchsia` | `#D946EF` | Visual Creation Studio & Sovereign Canvas |
| `iyou_life` | `life` | `sky` | `#38BDF8` | Life Stories & Decentralized Legacy Archive |
| `iyou_walk` | `walk` | `green` | `#22C55E` | Pedestrian Mesh & Dog Walking Coordination |
| `iyou_stay` | `stay` | `yellow` | `#EAB308` | Sovereign Hospitality & Accommodation |
| `iyou_dev` | `dev` | `zinc` | `#71717A` | Developer Portal & API Documentation |
| `iyou_spot` | `spot` | `pink` | `#EC4899` | Local Discovery & Community Recommendations |

---

## 3. Local Signature Bridge Wire Contract (Port 9001)

The **Local Signature Bridge** runs inside the user's local `iyou_home` desktop enclave. It binds to `127.0.0.1:9001` with TLS termination (`wss://home.iyou.me:9001`) and serves as the sole cryptographic portal between web clients and private keys.

```
┌──────────────────────────────────────┐          WebSocket           ┌──────────────────────────────────────┐
│       Satellite Web Application      │─────────────────────────────▶│      iyou_home Rust Enclave (:9001)  │
│       (Browser Context)              │◀─────────────────────────────│      (Zero-Custody Private Keys)     │
└──────────────────────────────────────┘                              └──────────────────────────────────────┘
```

### 3.1 Pre-Gate Ingress Frames (Zero-Modal / Instant)

Pre-gate operations are handled inline by the Rust background thread. They require no user confirmation dialogs and strictly isolate root secret keys via the **Secret Adjacency Guard**.

#### 3.1.1 `ping` / `pong`
- **Request:** `{"type": "ping"}`
- **Response:** `{"type": "pong"}`

#### 3.1.2 `get_profile`
Returns the Level 1 Public Persona metadata. The Level 0 Anchor persona is strictly filtered out.
- **Request:** `{"type": "get_profile"}`
- **Response:**
  ```json
  {
    "type": "profile_sync",
    "profile": {
      "profile_id": "primary",
      "profile_name": "Alice Sovereign",
      "derivation_index": 1,
      "did": "did:key:z6MkuAliceKey...",
      "nostr_pubkey_hex": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
      "level": 1,
      "is_system_reserved": false
    }
  }
  ```

#### 3.1.3 `RESOLVE_PEER_ALIASES`
Performs read-only batch resolution of public keys against the local `contacts.json` book.
- **Request Frame:**
  ```json
  {
    "type": "RESOLVE_PEER_ALIASES",
    "pubkeys": [
      "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
      "did:key:z6MkSockAlias..."
    ]
  }
  ```
- **Response Frame:**
  ```json
  {
    "type": "peer_aliases_resolved",
    "matches": {
      "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d": {
        "nickname": "Alice",
        "trust_level": "Level0_5",
        "badge": "Trusted Alliance"
      }
    },
    "unknown": [
      "did:key:z6MkSockAlias..."
    ]
  }
  ```
- **Security Constraints:**
  - **Batch Frame Cap:** `1 <= pubkeys.length <= 256` (`MAX_RESOLVE_KEYS`). Oversized frames return `{"type":"error","message":"too_many_pubkeys"}`.
  - **Minimal Privacy Projection:** Hit records MUST contain only `{nickname, trust_level, badge}`. Aliases, attestation receipts, and timestamps MUST NOT be returned.

---

### 3.2 User-Gated Signing Frames (`PopupGuard`)

Gated operations involve cryptographic key signing. The bridge acquires the concurrency lock (`PopupGuard`) and presents a native React approval modal before returning signed data.

| Message Type | Direction | Payload Parameters | Response Type | Security Action |
|:---|:---|:---|:---|:---|
| `sign` | C $\rightarrow$ S | `challenge` (UUID), `profile_id` | `signed` | Generates W3C Verifiable Presentation signed with Ed25519 key. |
| `sign_event` | C $\rightarrow$ S | `event` (NIP-01 payload object) | `event_signed` | Computes BIP-340 Schnorr signature over event ID using secp256k1 key. |
| `sign_credential` | C $\rightarrow$ S | `credential_data` (JSON-LD) | `credential_signed` | Issues and signs a W3C Verifiable Credential. |
| `POLY_CREDENTIAL_REQUEST` | C $\rightarrow$ S | `required_credential_type`, `challenge` | `POLY_CREDENTIAL_PRESENTATION` | Filters matching credentials from vault, presents modal, returns signed VP. |

---

### 3.3 Headless Auto-Signing (`OMNI_SIGN_REQUEST`)

For seamless governance voting in `iyou_poly` and `iyou_wun`, the bridge supports headless auto-signing of standardized vote envelopes.

#### Request Frame:
```json
{
  "type": "OMNI_SIGN_REQUEST",
  "protocol": "POLY_V2",
  "poll_id": "b4e7a2-charter-amendment-2026",
  "option_id": "approve_budget",
  "timestamp": 1725000000
}
```

#### Enclave Execution:
1. Canonicalizes payload: `SHA-256("POLY_V2" || poll_id || option_id || timestamp)`.
2. Signs hash with derived Level 1 key.
3. Automatically formats and returns a valid Nostr **Kind 1112** vote envelope without triggering desktop popup interruptions.

---

### 3.4 Sovereign Data Synchronization (`SYNC_TO_HOME_REQUEST`)

Satellite applications provide users with a "Sync to Home Base" mechanism, pushing local activity, bookmarks, and governance vote receipts to the user's desktop vault for cold backup.

#### Request Frame:
```json
{
  "type": "SYNC_TO_HOME_REQUEST",
  "app_slug": "wun",
  "data_type": "vote_receipts",
  "payload": {
    "poll_id": "b4e7a2-charter-amendment-2026",
    "option_id": "approve_budget",
    "tx_signature": "e8d4a...",
    "merkle_leaf": "5e884..."
  },
  "timestamp": 1725000000
}
```

#### Response Frame:
```json
{
  "type": "SYNC_TO_HOME_RESPONSE",
  "status": "stored",
  "record_id": "rec_9f81a7b2",
  "synced_at": 1725000001
}
```

---

## 4. XMPP Real-Time Mesh & JID Sanitization Rules

Real-time instant messaging and coordinate telemetry utilize XMPP servers (Prosody on port `5222`) with OMEMO end-to-end encryption.

### 4.1 The RFC 7622 / XEP-0106 Nodeprep Problem

Raw Decentralized Identifiers (e.g., `did:key:z6Mku...`) contain colons (`:`). Under XMPP Address Format rules (RFC 7622) and SASLprep / nodeprep string normalization, colons are strictly prohibited in the localpart of a bare JID. Supplying raw DIDs causes connection rejection during the SASL handshake.

### 4.2 Canonical JID Construction Mandate

All applications **MUST** derive the XMPP JID localpart from the 64-character lowercase hexadecimal Nostr public key string:

$$\text{Bare JID} = \text{\{nostr\_pubkey\_hex\}@\{xmpp\_domain\}}$$

```
Django User.username (DID: "did:key:z6Mk...")
        │
        ▼
did_to_pubkey()  ──▶ Base58BTC decode multibase, extract 32-byte pubkey
        │
        ▼
nostr_pubkey_hex (64-char hex: "3bf0c63fcb9346...")
        │
        ▼
XMPP JID = "3bf0c63fcb9346...@iyou.me"
```

### 4.3 Python Reference Implementation (`did_to_pubkey`)

```python
import base58

def did_to_pubkey(did_string: str) -> str:
    """
    Converts a W3C did:key:z6Mk... identifier to a canonical
    64-character lowercase hex string suitable for XMPP JID localparts.
    """
    if not did_string.startswith("did:key:z"):
        raise ValueError(f"Invalid DID prefix for: {did_string}")
    
    # Strip 'did:key:z' prefix and decode multibase Base58BTC
    multibase_data = did_string[9:]
    raw_bytes = base58.b58decode(multibase_data)
    
    # Multicodec for Ed25519-pub is 0xed01 (2 bytes prefix)
    # The remaining 32 bytes represent the raw public key
    if raw_bytes[:2] == b'\xed\x01':
        pubkey_bytes = raw_bytes[2:]
    else:
        pubkey_bytes = raw_bytes[-32:]
        
    return pubkey_bytes.hex().lower()
```

### 4.4 Converse.js Canonical Configuration Directives

Chat interfaces embedding Converse.js MUST set `discover_connection_methods: false` to suppress noisy `.well-known/host-meta` probes and enforce direct WebSocket transport:

```javascript
converse.initialize({
    bosh_service_url: undefined,
    websocket_url: '{{ xmpp_ws_url }}',
    jid: '{{ user_pubkey }}@{{ xmpp_domain }}',
    password: '{{ xmpp_token }}',
    authentication: 'login',
    discover_connection_methods: false,
    persistent_store: 'session',
    keepalive: false,
    allow_logout: false,
    view_mode: 'fullscreen',
    theme: 'light'
});
```

---

## 5. Step-by-Step Satellite Onboarding Walkthrough

Follow this 8-step recipe to onboard a new Django-based satellite application into the federation.

### Step 1: Claim Unique Accent Color & Register Slug
Select an unused color from the palette and assign the port allocation in `docs/OMNI_SOCIAL_PROTOCOL_V2.md`.

### Step 2: Generate Template Assets
Run the template generator from the `omni_social` repository:
```bash
python scripts/generate_templates.py <slug> <color> --output-dir ~/CODE_BASE/iyou_<slug>/templates/includes/
```

### Step 3: Configure Secretless PKCE OIDC in `settings.py`
```python
# OIDC RP Configuration (Secretless PKCE)
OIDC_RP_CLIENT_ID = "iyou-<slug>-satellite-client"
# OIDC_RP_CLIENT_SECRET MUST NOT be present
OIDC_OP_AUTHORIZATION_ENDPOINT = "https://iyou.me/openid/authorize/"
OIDC_OP_TOKEN_ENDPOINT = "https://iyou.me/openid/token/"
OIDC_OP_USER_ENDPOINT = "https://iyou.me/openid/userinfo/"
OIDC_OP_JWKS_ENDPOINT = "https://iyou.me/openid/jwks/"
OIDC_RP_SCOPES = "openid profile email"
OIDC_RP_SIGN_ALGO = "RS256"

# Authentication Backends
AUTHENTICATION_BACKENDS = [
    "apps.core.auth.SovereignOIDCBackend",
    "django.contrib.auth.backends.ModelBackend",
]
```

### Step 4: Implement Sovereign OIDC Backend (`apps/core/auth.py`)
```python
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
import requests

class SovereignOIDCBackend(OIDCAuthenticationBackend):
    def get_username(self, claims):
        # Strict Invariant: Pin username strictly to the 'sub' claim (DID)
        return claims.get("sub")

    def create_user(self, claims):
        username = self.get_username(claims)
        user = self.UserModel.objects.create_user(username=username)
        user.set_unusable_password()
        return user

    def update_user(self, user, claims):
        # Prevent unnecessary writes if state is unchanged
        return user
```

### Step 5: Configure Sandboxed Session & CSRF Cookies
```python
SESSION_COOKIE_NAME = "<slug>_sessionid"
CSRF_COOKIE_NAME = "<slug>_csrftoken"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = "Lax"
```

### Step 6: Configure Reverse Proxy Header
```python
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
```

### Step 7: Wire Ingress URLs (`urls.py`)
```python
from django.urls import path, include
from mozilla_django_oidc.views import OIDCAuthenticationRequestView, OIDCLogoutView

urlpatterns = [
    path("oidc/authenticate/", OIDCAuthenticationRequestView.as_view(), name="oidc_authentication_init"),
    path("oidc/callback/", include("mozilla_django_oidc.urls")),
    path("oidc/logout/", OIDCLogoutView.as_view(), name="oidc_logout"),
    # ... application views
]
```

### Step 8: Propagate & Verify Specifications
Execute spec synchronization from the `omni_social` repository:
```bash
python scripts/sync_ecosystem_specs.py
```

---

## 6. Verification & Conformance Checklist

Before certifying a satellite for production deployment, verify the following:

- [ ] **No Secrets:** Verified that `OIDC_RP_CLIENT_SECRET` does not appear in `settings.py`, `.env`, or container manifests.
- [ ] **DID Anchoring:** Verified that `request.user.username` returns `did:key:z6Mk...` upon login.
- [ ] **Zero Passwords:** Verified that `user.has_usable_password()` returns `False`.
- [ ] **Static CSS:** Verified that `cdn.tailwindcss.com` is not present in base templates.
- [ ] **Bridge Gating:** Verified that bridge operations properly reject Level 0 targets with fail-closed security.
- [ ] **XMPP Sanitization:** Verified that JIDs are generated as `{hex_pubkey}@{domain}` without colons.
- [ ] **Cookie Isolation:** Verified unique `SESSION_COOKIE_NAME` and `CSRF_COOKIE_NAME`.
