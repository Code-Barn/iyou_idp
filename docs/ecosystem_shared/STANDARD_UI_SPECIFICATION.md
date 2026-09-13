# Standard UI Specification: Sovereign Mesh Navigation & Persona Enclave

**Canonical Reference for Layer 0 Ecosystem Bar, Layer 1 Standard Header, Modular Persona Enclave, Mascot Footer, and PWA Standards**  
**Version:** 3.0.0  
**Status:** Authoritative Ecosystem Specification  

---

## 1. Overview & Architectural Hierarchy

The iYou ecosystem presentation tier is structured into strict horizontal layers across all 19 satellite applications:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ Layer 0: Sovereign Ecosystem Bar (Contrast-inverted drawer, 4px lip shown)  │
│          Light: deep #0B0F19 / Dark: crisp slate-100 (inverted)            │
├────────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Application Brand & Sovereign Identity Header                      │
│   ├── Left: Brand Lockup (squircle stamp + iyou_{slug} + DOMAIN BADGE)     │
│   └── Right:                                                               │
│       ├── Notification Bell (#notification-bell-btn)                       │
│       ├── Modular Persona Enclave Partial (_persona_enclave.html)          │
│       │     └── @handle + L1/L2+ level chips, Flyout with Public Profile   │
│       ├── Action Links ([ ⚙️ Edit ], Sign Out)                             │
│       ├── Logged-Out: "• Sovereign Key Required" capsule + "🔑 Authenticate"│
│       └── Outline Theme Toggle (☀ in Light / ☾ in Dark)                    │
├────────────────────────────────────────────────────────────────────────────┤
│ Layer 2: Application Sub-Nav Ribbon (_nav.html, max-w-7xl width contract)  │
├────────────────────────────────────────────────────────────────────────────┤
│ Main Content Area (max-w-7xl or data-viz full-bleed)                       │
├────────────────────────────────────────────────────────────────────────────┤
│ Canonical Mascot Footer ("The Polly Pattern" / _footer.html)               │
│   ├── Mascot Image Block (Light/Dark responsive PNG assets)                │
│   ├── Brand Lockup & Version Badge (iyou_{slug} vX.Y)                      │
│   └── Telemetry & Protocol Strip (Relay, Enclave Bridge, License)          │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer 0: Sovereign Ecosystem Bar

The Layer 0 bar provides continuous, non-intrusive navigation across all 19 applications of the sovereign mesh.

### 2.1 Structural & Motion Design
- **Positioning**: Fixed to the viewport top (`fixed top-0 left-0 right-0 z-[9999]`).
- **Initial Resting State**: Hidden above the viewport with only a 4px activation lip visible (`-translate-y-[calc(100%-4px)]`).
- **Desktop Hover Expansion**: Smoothly expands to full height on hover (`sm:hover:translate-y-0`) with hardware-accelerated transitions (`transition-transform duration-300 ease-in-out`).
- **Surface Styling**: Glassmorphic deep dark surface in light mode with a crisp white drawer in dark mode (Section 2.4).
- **Close Action**: Explicit top-right close button (`#close-ecosystem-bar`) calling `closeEcosystemBar(event)`.
- **Mobile Pull Handle**: Bottom 8px strip (`h-2 w-full bg-{color}-600 dark:bg-{color}-500 cursor-pointer`) containing a centered accent pill (`w-8 h-1 bg-{color}-200 dark:bg-{color}-900 rounded-full opacity-80`) hooked to `toggleEcosystemBar(event)`. The collapsed lip dynamically binds to the satellite's accent color so the resting trigger is always visible against the app below.

### 2.4 Layer 0 High-Contrast Inversion Contract
The Layer 0 drawer inverts its chroma between color schemes to remain intentionally readable against both modes:

```html
<div id="sovereign-ecosystem-topbar"
     class="fixed top-0 left-0 right-0 z-[9999] transition-transform duration-300 ease-in-out -translate-y-[calc(100%-4px)] sm:hover:translate-y-0 bg-[#0B0F19]/95 text-slate-300 border-b border-violet-500/50 dark:bg-slate-100 dark:text-slate-900 dark:border-b-2 dark:border-violet-600 shadow-2xl">
  <div class="max-w-7xl mx-auto px-3 sm:px-6 py-2">
    <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 dark:text-slate-600 pb-1 mb-1 border-b border-slate-800 dark:border-slate-300">
      <span class="text-violet-400 dark:text-violet-700 font-bold tracking-wider">SOVEREIGN MESH ECOSYSTEM</span>
      <button type="button" id="close-ecosystem-bar"
              class="text-xs text-slate-400 hover:text-white dark:text-slate-600 dark:hover:text-slate-900 px-2 py-0.5 rounded bg-slate-800/80 dark:bg-slate-200 dark:hover:bg-slate-300 transition"
              onclick="closeEcosystemBar(event)">✕ Close</button>
    </div>
    <!-- 19-App Links Flow (per-app colors + dark variants) -->
  </div>
  <div class="h-2 w-full bg-{color}-600 dark:bg-{color}-500 cursor-pointer flex justify-center items-center select-none" onclick="toggleEcosystemBar(event)">
    <div class="w-8 h-1 bg-{color}-200 dark:bg-{color}-900 rounded-full opacity-80"></div>
  </div>
</div>
```

- **Light mode (`bg-[#0B0F19]/95 text-slate-300 border-b border-violet-500/50`)**: Deep dark drawer, violet mesh accent border/title.
- **Dark mode (`dark:bg-slate-100 dark:text-slate-900 dark:border-b-2 dark:border-violet-600`)**: Crisp light drawer with functional violet-700 labels and slate-200 close button.
- **Link contrast**: Every app link ships paired light/dark classes (e.g. `text-violet-400 hover:text-violet-300 dark:text-violet-700 dark:hover:text-violet-600`) so the per-app color stream remains legible in both modes. Section separators use `<span class="text-slate-700 dark:text-slate-400">/</span>`.
- **Mesh chrome is violet**: The Layer 0 bar border and title use the violet mesh identity (not the per-app accent). Per-app accents appear in the link stream and in the collapsed 4px lip / pull handle (`bg-{color}-600 dark:bg-{color}-500` strip + `bg-{color}-200 dark:bg-{color}-900` pill), which binds to each satellite's accent color so the resting lip is always visible.

### 2.2 The 19-App Multi-Colored Stream
Links are ordered by protocol topology and color-coded with distinct Tailwind CSS palette accents, separated by dark slashes (`<span class="text-slate-700">/</span>`). The active application is highlighted using `text-__COLOR__-400 font-bold underline`:

| App Slug | Subdomain | Palette Color Class | Semantic Domain |
|:---|:---|:---|:---|
| `idp` | `https://iyou.me` | `text-slate-400 hover:text-white` | Root Identity Provider |
| `wun` | `https://wun.iyou.me` | `text-violet-400 hover:text-violet-300` | Profile & Sovereign Space |
| `poly` | `https://poly.iyou.me` | `text-purple-400 hover:text-purple-300` | Consensus & Governance |
| `name` | `https://name.iyou.me` | `text-teal-400 hover:text-teal-300` | Decentralized Naming |
| `hive` | `https://hive.iyou.me` | `text-orange-400 hover:text-orange-300` | Communal Vaults & Storage |
| `ride` | `https://ride.iyou.me` | `text-lime-400 hover:text-lime-300` | Sovereign Transport |
| `dctech`| `https://dctech.iyou.me` | `text-indigo-400 hover:text-indigo-300`| Developer Portal |
| `safe` | `https://safe.iyou.me` | `text-rose-400 hover:text-rose-300` | Key Escrow & Recovery |
| `talk` | `https://talk.iyou.me` | `text-cyan-400 hover:text-cyan-300` | P2P Encrypted Comms |
| `clar` | `https://clar.iyou.me` | `text-emerald-400 hover:text-emerald-300`| Verification & Auditing |
| `play` | `https://play.iyou.me` | `text-amber-400 hover:text-amber-300` | Entertainment & Media |
| `blog` | `https://blog.iyou.me` | `text-sky-400 hover:text-sky-300` | Sovereign Publishing |
| `help` | `https://help.iyou.me` | `text-red-400 hover:text-red-300` | Support & Documentation |
| `draw` | `https://draw.iyou.me` | `text-fuchsia-400 hover:text-fuchsia-300`| Collaborative Canvas |
| `life` | `https://life.iyou.me` | `text-sky-400 hover:text-sky-300` | Health & Wellbeing |
| `walk` | `https://walk.iyou.me` | `text-green-400 hover:text-green-300` | Navigation & Tracking |
| `stay` | `https://stay.iyou.me` | `text-yellow-400 hover:text-yellow-300` | Hospitality & Spaces |
| `dev` | `https://dev.iyou.me` | `text-zinc-400 hover:text-zinc-300` | Mesh Testbed |
| `spot` | `https://spot.iyou.me` | `text-pink-400 hover:text-pink-300` | Events & Geolocation |

### 2.3 Drawer State JavaScript
All Layer 0 templates embed the standard drawer controllers:
```javascript
function openEcosystemBar() {
  const bar = document.getElementById('sovereign-ecosystem-topbar');
  if (!bar) return;
  bar.classList.remove('-translate-y-[calc(100%-4px)]');
  bar.classList.add('translate-y-0');
}

function closeEcosystemBar(e) {
  if (e) e.stopPropagation();
  const bar = document.getElementById('sovereign-ecosystem-topbar');
  if (!bar) return;
  bar.classList.remove('translate-y-0');
  bar.classList.add('-translate-y-[calc(100%-4px)]');
  if (document.activeElement) document.activeElement.blur();
}

function toggleEcosystemBar(e) {
  if (e) e.stopPropagation();
  const bar = document.getElementById('sovereign-ecosystem-topbar');
  if (!bar) return;
  if (bar.classList.contains('translate-y-0')) {
    closeEcosystemBar(e);
  } else {
    openEcosystemBar();
  }
}
```

---

## 3. Layer 1: Application Brand & Sovereign Identity Header

### 3.1 Header Layout & Width Contract
All Layer 1 headers across the ecosystem share one mandatory width and spacing contract regardless of app or viewport:

```html
<header class="relative z-30 border-b backdrop-blur-sm transition-colors duration-200 bg-white/90 border-slate-200 text-slate-900 dark:bg-[#0B0F19]/90 dark:border-gray-800 dark:text-gray-100">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
    <!-- Left: Brand Lockup -->
    <!-- Right: Action & Identity Controls -->
  </div>
</header>
```

- **Outer `<header>`**: `relative z-30 border-b backdrop-blur-sm transition-colors duration-200 bg-white/90 border-slate-200 text-slate-900 dark:bg-[#0B0F19]/90 dark:border-gray-800 dark:text-gray-100`.
- **Inner flex row**: `max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between` — fixed 64px (h-16) header height floor with items vertically centered.
- Data-visualization viewports (`name`, `draw`, `spot`) may permit full-bleed `<main class="w-full">`, but headers and footers **MUST** strictly remain `max-w-7xl mx-auto`.

### 3.2 Standard Header Components
The canonical `_standard_header.html` provides (all slots visible in both authenticated and unauthenticated states):

1. **Session DID Binding**:
   ```javascript
   window.CURRENT_SESSION_DID = "{{ current_session_did|default:user.username|escapejs }}";
   ```

2. **Left Brand Lockup (Squircle + Name + Domain Badge)**:
   ```html
   <div class="flex items-center gap-3">
     <a href="/" class="flex items-center gap-2 text-2xl font-bold tracking-tight hover:opacity-90 transition-opacity" title="iyou_{app_slug}">
       <img src="{% static 'img/logo_square_sm.png' %}"
            onerror="this.onerror=null;this.src='{% static 'img/logo_square.png' %}';"
            alt="{app_slug}"
            class="h-8 w-8 aspect-square rounded-lg object-cover shadow-sm border border-slate-200 dark:border-slate-800 group-hover:scale-105 transition-transform duration-150" />
       <span class="flex items-center">
         <span class="text-slate-400 dark:text-slate-500 font-medium">iyou</span>
         <span class="text-{color}-600 dark:text-{color}-400 font-extrabold">_{slug}</span>
       </span>
     </a>
     <span class="hidden sm:inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-slate-100 dark:bg-slate-800/80 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700/60">
       __BADGE__
     </span>
   </div>
   ```
   Brand text renders at `text-2xl font-bold tracking-tight` with `iyou` in `font-medium text-slate-400` and `_{slug}` in `font-extrabold text-{color}-600`.

3. **Notification Bell**: Button `#notification-bell-btn` with safe function guard:
   ```html
   onclick="typeof toggleNotificationDrawer === 'function' && toggleNotificationDrawer()"
   ```
   Unread badge ping: `#notification-unread-dot` using the app accent color.

4. **Modular Persona Enclave Partial**: `{% include "includes/_persona_enclave.html" %}` — renders `@handle` and level chips (`L1` violet, `L2+` amber) via the canonical context processor (Section 6).

5. **Direct Actions** (authenticated only):
   - `[ ⚙️ Edit ]` linking to `{% url 'dashboard' %}`
   - `Sign Out` linking to `{% url 'oidc_logout' %}`

6. **Logged-Out Canonical Poly Flow** (Section 3.4):
   - Soft capsule pill for "Sovereign Key Required"
   - Solid vibrant accent button for "Authenticate"

7. **Outline Theme Toggle**: Sun in light mode, Moon in dark mode (Section 3.5).

### 3.3 Domain Badge
A rectangular monospace label rendered inline in the brand lockup, providing immediate semantic classification for every satellite app:

```html
<span class="hidden sm:inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-slate-100 dark:bg-slate-800/80 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700/60">
  __BADGE__
</span>
```

| App | Badge Label |
|:---|:---|
| `idp` | `IDENTITY ROOT` |
| `wun` | `SOCIAL HUB` |
| `poly` | `CONSENSUS ENGINE` |
| `name` | `SOVEREIGN` |
| `hive` | `EVIDENCE VAULT` |
| `ride` | `TRANSIT` |
| `dctech` | `HARDENING` |
| `safe` | `CRISIS TRIAGE` |
| `talk` | `SUPPORT` |
| `clar` | `DIRECTORY` |
| `play` | `ATHLETICS` |
| `blog` | `PUBLISHING` |
| `help` | `COMMUNITY` |
| `draw` | `CANVAS` |
| `life` | `MEMORIAL` |
| `walk` | `TRANSIT` |
| `stay` | `HOSPITALITY` |
| `dev` | `OPERATIONS` |
| `spot` | `EXPLORER` |

The badge is sourced from `APP_METADATA` in `scripts/generate_templates.py` and is templated via `__BADGE__` → `{badge}` in the standard header generator.

### 3.4 Logged-Out Authentication Block (The Poly Standard)
When no active session exists, the standard header renders a two-part authenticated gate matching `iyou_poly` production screenshots:

```html
<!-- Logged-Out Canonical Poly Flow -->
<div class="flex items-center gap-2 text-xs">
  <!-- Soft Capsule Indicator -->
  <div class="flex items-center gap-2 px-3 py-1.5 rounded-full border border-amber-500/20 bg-amber-50/50 dark:bg-amber-950/20 text-amber-800 dark:text-amber-300">
    <span class="w-2.5 h-2.5 rounded-full bg-amber-500 shrink-0"></span>
    <span class="italic text-xs text-slate-600 dark:text-slate-400">Sovereign Key Required</span>
  </div>
  <!-- Solid Vibrant Authenticate Button -->
  <a href="{% url 'oidc_authentication_init' %}" class="px-3 py-1.5 rounded-lg bg-{color}-600 hover:bg-{color}-700 text-white font-medium text-xs shadow-sm transition-all flex items-center gap-1.5">
    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>
    </svg>
    <span>Authenticate</span>
  </a>
</div>
```

- **Capsule**: `rounded-full` amber border/bg (`border-amber-500/20 bg-amber-50/50 dark:bg-amber-950/20 text-amber-800 dark:text-amber-300`), italic text, `w-2.5 h-2.5` amber-500 dot.
- **Authenticate Button**: Solid `px-3 py-1.5 rounded-lg bg-{color}-600 hover:bg-{color}-700 text-white font-medium text-xs shadow-sm` with key SVG icon (`w-3.5 h-3.5`) and `gap-1.5`.

### 3.5 Outline Theme Toggle (☀ Light / ☾ Dark)
The `#theme-toggle` button uses the `block dark:hidden` / `hidden dark:block` pattern to show the correct icon per mode without JavaScript class toggling:

```html
<button id="theme-toggle" type="button" class="p-1.5 rounded-lg text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition focus:outline-none" aria-label="Toggle theme">
  <svg id="icon-sun" class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
    <path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
  </svg>
  <svg id="icon-moon" class="w-5 h-5 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
    <path stroke-linecap="round" stroke-linejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
  </svg>
</button>
```

### 3.6 Dual-Asset Logo Hierarchy
To optimize performance and eliminate loading high-res square master assets (~512–768px) for the 36–40px (`w-9 h-9 sm:w-10 sm:h-10`) rendering slot, satellites implement a dual-asset logo hierarchy:
- **`static/img/logo_square_sm.png`**: 64×64 or 96×96 px — dedicated for the Layer 1 header squircle stamp. Minimizes network payload and ensures sharp rasterization on standard and Retina displays.
- **`static/img/logo_square.png`**: High-res square master — dedicated for `_footer.html`, favicons, Apple Touch icons, and PWA icon generation.
- **Graceful Fallback Invariant**: Standard headers must implement the `onerror` fallback:
  ```html
  onerror="this.onerror=null;this.src='{% static 'img/logo_square.png' %}';"
  ```
  This ensures satellites that haven't generated `logo_square_sm.png` yet safely resolve to `logo_square.png` without displaying a broken image box.

### 3.7 Unified Standard Header — No Custom Exceptions
All 19 satellite applications now receive the standardized canonical `_standard_header.html` from `generate_templates.py` — no exceptions. The domain badge (`APP_METADATA.badge`) provides the per-app differentiation previously handled by custom layouts:

```python
PRESERVE_LAYER_1_APPS = set()  # All apps use the canonical header
```

- **`iyou_poly`**: Now renders `CONSENSUS ENGINE` badge via the canonical header — no custom governance layout.
- **`iyou_name`**: Now renders `SOVEREIGN` badge via the canonical header — no custom registry styling.

The `--skip-header` flag and `PRESERVE_LAYER_1_APPS` guard are retained for future use but no longer activated for any satellite.

---

## 4. Layer 2: Application Sub-Navigation Contract (`_nav.html`)

Satellites that implement a custom Layer 2 navigation ribbon (`_nav.html`) MUST obey the same horizontal width contract as Layer 1:

### 4.1 Width & Scaffolding Contract
- All navigation items and controls MUST be wrapped inside a single scroll-locked container:
  ```html
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2.5 flex items-center justify-between">
  ```
- Layer 2 **MUST NEVER** stretch to full browser width. It must remain column-aligned with the Layer 1 header and Layer 0 drawer on all viewports.
- The `<nav>` element itself may carry its own surface styling (e.g. `border-b border-slate-200 dark:border-gray-800/80 bg-white/70 dark:bg-[#070A10]/70 backdrop-blur-sm`), but the inner scaffolding wrapper above is mandatory and fixed.
- Canonical reference implementation: `iyou_poly/templates/includes/_nav.html`.

---

## 5. Modular Persona Enclave Partial (`_persona_enclave.html`)

The Persona Enclave quick-switcher is fully decoupled into `templates/includes/_persona_enclave.html`:

```html
{% load static %}
<!-- Persona Enclave Quick-Switcher Partial -->
<div class="relative inline-block text-left font-mono" id="persona-switcher-container">
  <button
    type="button"
    id="persona-switcher-btn"
    class="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-900/80 hover:bg-slate-100 dark:hover:bg-slate-800 transition text-xs font-mono focus:outline-none"
    aria-expanded="false"
    aria-haspopup="true"
    onclick="togglePersonaDropdown()"
  >
    <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse inline-block" id="active-persona-dot" title="Sovereign Key Active"></span>
    <span id="active-persona-display-name" class="truncate max-w-[140px] font-mono text-xs font-medium text-slate-700 dark:text-slate-200">
      {{ user_display_label|default:user.username|truncatechars:18 }}
    </span>
    <span class="text-[10px] px-1 py-0.5 rounded font-bold transition-colors duration-150 {% if active_persona_level == 1 or not active_persona_level %}bg-violet-100 dark:bg-violet-950/80 text-violet-700 dark:text-violet-300{% else %}bg-amber-100 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300{% endif %}" id="active-persona-level">
      L{{ active_persona_level|default:1 }}
    </span>
    <svg class="w-3.5 h-3.5 text-slate-400 transition-transform duration-200" id="persona-chevron" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
    </svg>
  </button>

  <!-- Flyout Menu -->
  <div
    id="persona-switcher-dropdown"
    class="hidden absolute right-0 mt-2 w-72 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl z-50 overflow-hidden"
  >
    <!-- Public Profile Direct Action -->
    <div class="px-2 py-1.5 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50">
      <a href="https://wun.iyou.me/{{ user_display_label|default:user.username }}" target="_blank" class="flex items-center justify-between text-xs text-slate-700 dark:text-slate-200 hover:text-violet-500 dark:hover:text-violet-400 p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/60 transition font-mono">
        <span class="flex items-center gap-1.5">👤 <span>View Public Profile</span></span>
        <span class="text-[10px] text-slate-400">↗</span>
      </a>
    </div>

    <div class="px-2 py-1.5 text-[10px] uppercase font-bold text-slate-400 tracking-wider flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60">
      <span>Active Enclave Personas</span>
      <span id="persona-bridge-status" class="text-emerald-500 font-normal">Bridge Connected</span>
    </div>

    <!-- Persona List Target Container -->
    <div class="py-1 space-y-1" id="persona-list-container">
      <div class="px-2 py-2 text-slate-400 text-center text-[11px] animate-pulse">
        Querying local vault personas...
      </div>
    </div>

    <!-- Enclave Shortcut Footer -->
    <div class="pt-1.5 pb-1 px-2.5 flex items-center justify-between text-[11px] text-slate-400 border-t border-slate-100 dark:border-slate-800/60">
      <span class="truncate">Manage in iyou_home</span>
      <span class="text-violet-500">🔒 Enclave</span>
    </div>
  </div>
</div>
```

### 5.1 Key Features of the Decoupled Flyout
1. **Public Profile Direct Action**: Nesting the public profile anchor (`https://wun.iyou.me/{{ user_display_label|default:user.username }}`) inside the top of the flyout menu eliminates clutter from Layer 1 while giving users one-click access to their public profile.
2. **Bridge Connection State**: `#persona-bridge-status` indicates live WebSocket telemetry from `iyou_home` (or degrades gracefully to "BRIDGE OFFLINE" after 2500ms).
3. **Dynamic Persona Injection**: `#persona-list-container` is populated over the bridge protocol without blocking page load.
4. **Contextual Enclave Management**: Footer links directly to `iyou_home` where keys, derivation indices, and sub-personas are securely managed.

---

## 6. Handle Resolution & Context Processor Pattern

### 6.1 Context Processor Priority (`user_identity(request)`)
Identity display labels in satellite templates are resolved through the canonical context processor according to a strict 4-tier fallback priority:

```python
def user_identity(request):
    if not request.user.is_authenticated:
        return {"user_display_label": "", "current_session_did": ""}

    deck = UserLinkDeck.objects.filter(user=request.user).first()
    handle = f"@{deck.handle.lstrip('@')}" if deck and deck.handle else ""

    persona_name = request.session.get("active_persona_name", "")
    level = request.session.get("active_persona_level", 1)

    # Resolution Priority
    if handle:
        display_label = handle                            # Priority 1: @handle
    elif persona_name:
        display_label = f"{persona_name} (L{level})"     # Priority 2: Persona from session
    elif level == 1:
        display_label = "Primary Identity (L1)"          # Priority 3: Default primary
    else:
        display_label = f"{request.user.username[:16]}... (L{level})" # Priority 4: DID prefix

    return {
        "user_display_label": display_label,
        "current_session_did": request.user.username,
        # ...
    }
```

### 6.2 Client-Side Handle Preservation (`bridge_client.js`)
When the desktop bridge connects via WebSocket, empty or unassigned profile metadata must **never** wipe out a valid server-rendered `@handle`.

In `updateActivePersonaUI(profile)`:
```javascript
var nameStr = "";
if (profile.handle) {
    nameStr = "@" + String(profile.handle).replace(/^@/, "");
} else if (labelEl && labelEl.textContent && labelEl.textContent.trim().startsWith("@")) {
    // Preserve server-rendered @handle if bridge does not supply an explicit handle
    nameStr = labelEl.textContent.trim();
} else if (profile.name || profile.profile_name || profile.label) {
    nameStr = profile.name || profile.profile_name || profile.label;
} else if (profile.npub) {
    nameStr = profile.npub.slice(0, 14) + "...";
} else if (profile.did) {
    nameStr = profile.did.slice(0, 16) + "...";
} else {
    nameStr = "Sovereign";
}
```

This prevents the race condition where `profile.name = "Primary Identity"` overwrote the authenticated user's registered `@handle`.

---

## 7. Integration Checklist for Satellite Templates

To integrate the canonical navigation, mascot footer, and PWA system into any satellite application:

1. **Include Layer 0 Bar**: Immediately following the opening `<body>` tag:
   ```html
   {% include "includes/_ecosystem_bar.html" %}
   ```
2. **Include Layer 1 Header**:
   ```html
   {% include "includes/_standard_header.html" %}
   ```
3. **Persona Enclave Partial**: The standard header already renders it via `{% include "includes/_persona_enclave.html" %}`. Only custom Layout 2 headers outside the standard flow need an explicit opt-in include.
4. **Ensure Client-Side Bridge Assets**:
   Vendor `bridge_client.js` in your static files and initialize `window.bridgeClient = new TauriBridgeClient()`.
5. **Mount Canonical Mascot Footer**: Mounted immediately following `</main>` before closing `</body>`:
   ```html
   {% include "includes/_footer.html" %}
   ```
6. **Inject PWA & Favicon Assets**:
   Include standard favicon links and manifest in `<head>`, and register `sw.js` before `</body>`.

---

## 8. Canonical Mascot Footer ("The Polly Pattern")

The canonical footer architecture, established in `iyou_poly` ("The Polly Pattern"), anchors the bottom of every satellite application with responsive branding, light/dark mascot illustration, and runtime protocol telemetry.

### 8.1 Layout Sticking Contract (`base.html`)
To prevent awkward footer floating on sparse or empty views, satellites must enforce the three-part flex layout contract in `base.html`:

1. **Viewport Coverage (`<body>`)**:
   ```html
   <body class="flex flex-col min-h-screen bg-slate-50 dark:bg-[#080B11] text-slate-900 dark:text-slate-100 antialiased transition-colors duration-200">
   ```
   `<body class="flex flex-col min-h-screen ...">` guarantees that the root layout shell expands to at least 100% of the viewport height.

2. **Main Expansion (`<main>`)**:
   ```html
   <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 w-full">
     {% block content %}{% endblock %}
   </main>
   ```
   `<main class="flex-1 w-full ...">` consumes all unused vertical space, driving the footer down to the baseline.

3. **Mounting Order & Positioning (`_footer.html`)**:
   `{% include "includes/_footer.html" %}` is mounted directly following `</main>` before theme switcher scripts, Service Worker registration, and closing `</body>`:
   ```html
   <!-- Footer -->
   {% include "includes/_footer.html" %}
   ```

### 8.2 Container & Surface Styling (`_footer.html`)
The outer footer container uses the ecosystem's glassmorphic translucent surface design with dark-mode borders and sticky-bottom anchoring:
```html
<footer class="mt-auto border-t border-slate-200 dark:border-gray-800/80 bg-white/50 dark:bg-[#0B0F19]/50 backdrop-blur-sm py-10 transition-colors duration-200">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center justify-center text-center">
    ...
  </div>
</footer>
```
- **Root Wrapper**: `<footer class="mt-auto border-t border-slate-200 dark:border-gray-800/80 bg-white/50 dark:bg-[#0B0F19]/50 backdrop-blur-sm py-10 transition-colors duration-200">`
  - `mt-auto`: Enforces the sticky-footer margin hook.
  - `bg-white/50 dark:bg-[#0B0F19]/50 backdrop-blur-sm`: Glassmorphic translucency blending with ambient background gradients.
  - `py-10`: Provides balanced vertical breathing room across all screen sizes.
- **Inner Container**: `<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center justify-center text-center">` aligns all metadata along the central axis.

### 8.3 Mascot Image Block
Every satellite showcases its companion mascot using dual light and dark PNG assets with smooth hover interactions:
```html
<!-- Prominent Mascot Presentation -->
<div class="relative group mb-4">
  <!-- Light Mode Mascot -->
  <img 
    src="{% static 'img/{slug}_mascot_light.png' %}" 
    alt="{Mascot Name} the {Role/Mascot Title}" 
    class="h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-md border border-slate-200 dark:border-transparent block dark:hidden group-hover:scale-105 transition-transform duration-200" 
  />
  <!-- Dark Mode Mascot -->
  <img 
    src="{% static 'img/{slug}_mascot_dark.png' %}" 
    alt="{Mascot Name} the {Role/Mascot Title}" 
    class="h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-lg border border-transparent dark:border-gray-800 hidden dark:block group-hover:scale-105 transition-transform duration-200" 
  />
</div>
```
- **Wrapper**: `<div class="relative group mb-4">` establishes the hover coordinate context.
- **Light Mode Image**: `{% static 'img/{slug}_mascot_light.png' %}`:
  - Responsive classes: `block dark:hidden`, `h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-md border border-slate-200 dark:border-transparent group-hover:scale-105 transition-transform duration-200`.
- **Dark Mode Image**: `{% static 'img/{slug}_mascot_dark.png' %}`:
  - Responsive classes: `hidden dark:block`, `h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-lg border border-transparent dark:border-gray-800 group-hover:scale-105 transition-transform duration-200`.
- **Accessibility Invariant**: Both light and dark `<img>` tags MUST define descriptive `alt` attributes (e.g. `alt="Polly the Consensus Parrot"`).
- **Placement Invariant**: Mascot assets MUST reside strictly within `<footer>` and are strictly forbidden inside navigation headers (`<nav>`).

### 8.4 Brand Lockup & Subtitle
The brand lockup presents the dual-tone ecosystem app identity alongside version telemetry:
```html
<!-- Brand & Mission Statement -->
<div class="space-y-1 max-w-md">
  <div class="flex items-center justify-center gap-1.5 font-bold tracking-tight">
    <span class="text-slate-400 dark:text-slate-500">iyou</span><span class="text-{color}-600 dark:text-{color}-400 font-bold tracking-tight">_{slug}</span>
    <span class="text-xs font-mono font-normal px-2 py-0.5 rounded-full bg-{color}-100 dark:bg-{color}-950/60 text-{color}-700 dark:text-{color}-300 border border-{color}-200 dark:border-{color}-800/60 ml-1">
      v2.0 Greenfield
    </span>
  </div>
  <p class="text-xs font-mono text-slate-500 dark:text-slate-400">
    {Satellite Mission Statement or Subtitle}
  </p>
</div>
```
- **Brand Lockup**: `iyou` in `text-slate-400 dark:text-slate-500`, `_{slug}` in `text-{color}-600 dark:text-{color}-400 font-bold tracking-tight`.
- **Version Chip**: Monospace badge styled with `text-xs font-mono font-normal px-2 py-0.5 rounded-full bg-{color}-100 dark:bg-{color}-950/60 text-{color}-700 dark:text-{color}-300 border border-{color}-200 dark:border-{color}-800/60 ml-1`.
- **Subtitle**: Explanatory application role in `text-xs font-mono text-slate-500 dark:text-slate-400`.

### 8.5 Telemetry & Protocol Strip
At the base of the footer, runtime protocol coordinates are displayed in a clean monospace strip:
```html
<!-- Protocol & Network Metadata -->
<div class="mt-6 flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400 dark:text-slate-500">
  <span>Relay: <span class="text-slate-600 dark:text-slate-400">ws://127.0.0.1:9003</span></span>
  <span>•</span>
  <span>Enclave Bridge: <span class="text-slate-600 dark:text-slate-400">127.0.0.1:9001</span></span>
  <span>•</span>
  <span>License: <span class="text-slate-600 dark:text-slate-400">AGPL-3.0</span></span>
</div>
```
- Monospace line reporting Relay endpoint, Enclave Bridge (`127.0.0.1:9001`), and license (`AGPL-3.0`) at `text-[11px] font-mono text-slate-400 dark:text-slate-500`.
- Separated by muted bullet dots `<span>•</span>`.

---

## 9. PWA, Web App Manifest & Favicon Routine

To provide native-like standalone desktop and mobile installation with offline resiliency across the ecosystem, each satellite implements standardized Progressive Web App (PWA) artifacts.

### 9.1 Static Assets (`static/`)
Every satellite repository maintains the following standardized assets in its `static/` directory:
```
static/
├── manifest.json              # Web App Manifest
├── js/
│   └── sw.js                  # Minimal offline Service Worker
└── img/
    ├── logo_square_sm.png     # Compact squircle header logo (64x64/96x96)
    ├── logo_square.png        # Default Favicon & Apple Touch Icon (high-res master)
    ├── logo_square_dark.png   # Optional Dark Favicon
    ├── icon-192.png           # 192x192 PWA launcher icon (maskable)
    ├── icon-512.png           # 512x512 PWA splash / install icon (maskable)
    ├── {slug}_mascot_light.png # Light mode companion mascot
    └── {slug}_mascot_dark.png  # Dark mode companion mascot
```

1. **`static/manifest.json`**:
   Web app manifest specifying `name`, `short_name`, `description`, `start_url`, `display: "standalone"`, `theme_color`, and icon array (`icon-192.png`, `icon-512.png` with `purpose: "any maskable"`):
   ```json
   {
     "name": "iYou {AppName}",
     "short_name": "{ShortName}",
     "description": "{App Description}",
     "start_url": "/",
     "scope": "/",
     "display": "standalone",
     "background_color": "#0B0F19",
     "theme_color": "#HEX_COLOR",
     "orientation": "portrait-primary",
     "icons": [
       {
         "src": "/static/img/icon-192.png",
         "sizes": "192x192",
         "type": "image/png",
         "purpose": "any maskable"
       },
       {
         "src": "/static/img/icon-512.png",
         "sizes": "512x512",
         "type": "image/png",
         "purpose": "any maskable"
       }
     ]
   }
   ```
2. **`static/img/logo_square_sm.png` & `static/img/logo_square.png`**: `logo_square_sm.png` (~64-96px) serves as the compact Layer 1 header squircle stamp; `logo_square.png` serves as the high-res master for `_footer.html`, default favicon, and Apple touch icon.
3. **`static/img/icon-192.png` & `static/img/icon-512.png`**: PWA homescreen and launcher icons.
4. **`static/js/sw.js`**: Minimal offline service worker caching core static assets and runtime shell:
   ```javascript
   const CACHE_NAME = 'iyou-{slug}-v1';
   const STATIC_ASSETS = [
     '/',
     '/static/css/{slug}.css',
     '/static/manifest.json',
     '/static/img/logo_square.png',
     '/static/img/icon-192.png',
     '/static/img/icon-512.png'
   ];

   self.addEventListener('install', (event) => {
     event.waitUntil(
       caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
     );
     self.skipWaiting();
   });

   self.addEventListener('activate', (event) => {
     event.waitUntil(
       caches.keys().then((keys) =>
         Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
       )
     );
     self.clients.claim();
   });

   self.addEventListener('fetch', (event) => {
     if (event.request.method !== 'GET') return;
     event.respondWith(
       caches.match(event.request).then((cached) => cached || fetch(event.request))
     );
   });
   ```

### 9.2 Head Injections (`base.html`)
The `<head>` block of `templates/base.html` must include the canonical favicons and PWA meta tags:
```html
<!-- Favicon & App Icons -->
<link rel="icon" type="image/png" href="{% static 'img/logo_square.png' %}">
<link rel="apple-touch-icon" href="{% static 'img/logo_square.png' %}">

<!-- PWA Configuration -->
<meta name="theme-color" content="#HEX_COLOR">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="{App Title}">
<link rel="manifest" href="{% static 'manifest.json' %}">
```

### 9.3 Service Worker Registration
Injected immediately before closing `</body>` to ensure non-blocking page load:
```html
<!-- Offline Service Worker Registration -->
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register("{% static 'js/sw.js' %}")
        .catch((err) => console.debug('SW registration skipped:', err));
    });
  }
</script>
```

