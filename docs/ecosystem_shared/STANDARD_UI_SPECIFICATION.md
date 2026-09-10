# Standard UI Specification: Sovereign Mesh Navigation & Persona Enclave

**Canonical Reference for Layer 0 Ecosystem Bar, Layer 1 Standard Header, and Modular Persona Enclave**  
**Version:** 2.0.0  
**Status:** Authoritative Ecosystem Specification  

---

## 1. Overview & Architectural Hierarchy

The iYou ecosystem presentation tier is structured into strict horizontal layers across all 19 satellite applications:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ Layer 0: Sovereign Ecosystem Bar (Hidden drawer, 4px visible activation)    │
├────────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Application Brand & Sovereign Identity Header                      │
│   ├── Left: App Brand Lockup (iyou_{slug})                                 │
│   └── Right:                                                               │
│       ├── [Optional] Notification Bell (#notification-bell-btn)            │
│       ├── Modular Persona Enclave Partial (_persona_enclave.html)          │
│       │     └── Flyout Menu with Direct Public Profile Action              │
│       ├── Action Links ([ ⚙️ Edit ], Sign Out)                             │
│       ├── Unauthenticated State (Amber dot + "Sovereign Key Required")     │
│       └── Dark/Light Theme Toggle (#theme-toggle)                          │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer 0: Sovereign Ecosystem Bar

The Layer 0 bar provides continuous, non-intrusive navigation across all 19 applications of the sovereign mesh.

### 2.1 Structural & Motion Design
- **Positioning**: Fixed to the viewport top (`fixed top-0 left-0 right-0 z-[9999]`).
- **Initial Resting State**: Hidden above the viewport with only a 4px activation lip visible (`-translate-y-[calc(100%-4px)]`).
- **Desktop Hover Expansion**: Smoothly expands to full height on hover (`sm:hover:translate-y-0`) with hardware-accelerated transitions (`transition-transform duration-300 ease-in-out`).
- **Surface Styling**: Glassmorphic dark surface (`bg-[#0B0F19]/95 backdrop-blur-md border-b border-__COLOR__-500/50 shadow-2xl`).
- **Close Action**: Explicit top-right close button (`#close-ecosystem-bar`) calling `closeEcosystemBar(event)`.
- **Mobile Pull Handle**: Bottom 8px strip (`h-2 w-full bg-__COLOR__-500/80 cursor-pointer`) containing a centered pill (`w-8 h-1 bg-__COLOR__-300 rounded-full opacity-80`) hooked to `toggleEcosystemBar(event)`.

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

### 3.1 Standard Header Components
The canonical `_standard_header.html` provides:
1. **Session DID Binding**:
   ```javascript
   window.CURRENT_SESSION_DID = "{{ current_session_did|escapejs }}";
   ```
2. **Brand Lockup**: `iyou` in neutral slate with `_{app_slug}` styled in the app accent color.
3. **Notification Bell**: Button `#notification-bell-btn` with unread badge ping `#notification-unread-dot`.
4. **Modular Persona Enclave Partial**: Rendered via `{% include "includes/_persona_enclave.html" %}`.
5. **Direct Actions**:
   - `[ ⚙️ Edit ]` linking to `{% url 'dashboard' %}`
   - `Sign Out` linking to `{% url 'oidc_logout' %}` (supporting dual GET and POST)
6. **Canonical Unauthenticated Branch**:
   - Amber static indicator dot (`w-2 h-2 rounded-full bg-amber-400`)
   - Text indicator: `"Sovereign Key Required"`
   - Direct Sign In anchor linking to `{% url 'oidc_authentication_init' %}`
7. **Theme Toggle**: `#theme-toggle` button on far right toggling `#icon-sun` and `#icon-moon`.

### 3.2 Standard vs. Preserved Custom Designs
While most satellites adhere strictly to the generated `_standard_header.html`, specific domain-critical satellites maintain specialized presentation requirements:

```python
PRESERVE_LAYER_1_APPS = {"poly", "name"}
```

- **`iyou_poly`**: Preserves custom governance layout including the "Consensus Engine" badge and specialized chamber navigation while consuming the canonical Layer 0 bar and the modular `_persona_enclave.html` partial.
- **`iyou_name`**: Preserves custom registry styling with teal Sovereign badge and sticky header positioning while consuming the canonical Layer 0 bar and modular `_persona_enclave.html` partial.

Automation scripts (`scripts/generate_templates.py` with `--skip-header` and `scripts/regenerate_all.py`) enforce this guard:
```python
if app_slug in PRESERVE_LAYER_1_APPS:
    print(f"  ↳ SKIPPED _standard_header.html for '{app_slug}' (Preserving Custom Layout)")
```

---

## 4. Modular Persona Enclave Partial (`_persona_enclave.html`)

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

### 4.1 Key Features of the Decoupled Flyout
1. **Public Profile Direct Action**: Nesting the public profile anchor (`https://wun.iyou.me/{{ user_display_label|default:user.username }}`) inside the top of the flyout menu eliminates clutter from Layer 1 while giving users one-click access to their public profile.
2. **Bridge Connection State**: `#persona-bridge-status` indicates live WebSocket telemetry from `iyou_home` (or degrades gracefully to "BRIDGE OFFLINE" after 2500ms).
3. **Dynamic Persona Injection**: `#persona-list-container` is populated over the bridge protocol without blocking page load.
4. **Contextual Enclave Management**: Footer links directly to `iyou_home` where keys, derivation indices, and sub-personas are securely managed.

---

## 5. Handle Resolution & Context Processor Pattern

### 5.1 Context Processor Priority (`user_identity(request)`)
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

### 5.2 Client-Side Handle Preservation (`bridge_client.js`)
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

## 6. Integration Checklist for Satellite Templates

To integrate the canonical navigation system into any satellite application:

1. **Include Layer 0 Bar**: Immediately following the opening `<body>` tag:
   ```html
   {% include "includes/_ecosystem_bar.html" %}
   ```
2. **Include Layer 1 Header**:
   ```html
   {% include "includes/_standard_header.html" %}
   ```
3. **Opt-in Enclave Partial in Custom Layouts** (e.g. `poly`, `name`):
   ```html
   {% include "includes/_persona_enclave.html" %}
   ```
4. **Ensure Client-Side Bridge Assets**:
   Vendor `bridge_client.js` in your static files and initialize `window.bridgeClient = new TauriBridgeClient()`.
