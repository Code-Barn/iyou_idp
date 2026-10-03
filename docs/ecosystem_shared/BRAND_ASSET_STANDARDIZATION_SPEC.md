# Brand Asset Standardization Specification

**Multi-Logo, Dual-Theme & Glyph-Fallback Brand Asset Standard for the Sovereign Mesh**

**Hub:** `omni_social`
**Status:** Living document — canonical brand-asset naming contract and generator blueprint.
**Last updated:** 2026-10-02
**Scope:** `scripts/generate_templates.py`, Layer 1 (`_standard_header.html`), Layer 3 (`_footer.html`), all 20 ecosystem satellites.
**Status of implementation:** Audited and specified. **Not yet implemented** — see §6 Rollout.

---

## 1. Executive Summary

A fleet-wide audit of brand imagery across all 20 ecosystem satellites plus the four supporting enclaves produced six findings that shape this standard.

| # | Finding | Severity |
|:---|:---|:---|
| F-01 | **12 of 20 satellites have zero brand image assets.** No `img/` directory exists outside vendored `.venv` packages. Every one renders a broken `<img alt="talk">` in Layer 1 *and* Layer 3, rescued only by a JS `onerror` that points at a second, equally-missing file. | **Critical** |
| F-02 | **10 of 20 satellites never apply `.dark` to `<html>`.** Their entire `dark:` Tailwind variant surface is inert. Any dual-theme logo markup is a no-op until this is fixed. This is a hard prerequisite, not a nice-to-have. | **Critical** |
| F-03 | **Three competing naming conventions** coexist: generator-hardcoded `logo_square*.png`, app-local `*_mascot_{light,dark}.png` / `*_DM.png` / `hiver_mascot_*`, and freeform names (`M_LOGO.png`, `tinynamelogo_DM.png`, `createdinDeKalb_DM.png`, `Musterd_LOGO_Gemini_Generated_Image_*.png`). | High |
| F-04 | **`iyou_poly`'s Layer 1 lockup is a hand-patch.** It is the only dual-theme header in the fleet and it exists only because someone edited generated output by hand. It is not reproducible by `generate_templates.py` and will be silently reverted on the next regeneration. | High |
| F-05 | **`APP_MASCOTS` emits filenames that do not match `iyou_hive`'s assets.** The generator emits `img/hive_mascot_light.png`; hive ships `img/hiver_mascot_light.png` (and `.jpg`, not `.png` as primary). The footer mascot is broken in hive today. | High |
| F-06 | **Logo fallbacks depend on JavaScript.** Both `generate_standard_header()` and `generate_footer()` use inline `onerror` handlers. This guarantees a visible flash of broken image before the swap and breaks under CSP `script-src` restrictions. | Medium |

The standard below removes all six. Its core principle is **declaration by filename**: an app's brand capability is inferred purely from which canonical files exist in its static directory. No dictionary edit, no generator change, and no JavaScript are required to activate a mode.

---

## 2. Fleet-Wide Asset Inventory

### 2.1 Per-Application Inventory (20-App Roster)

Legend — **L1** = Layer 1 header logo, **L3** = Layer 3 footer brand block. "Broken" means the referenced file does not exist in the repo.

| App | Color | Logo assets on disk | Mascot / glyph | Current L1 mode | Current L3 mode | Defects |
|:---|:---|:---|:---|:---|:---|:---|
| `idp` | — | *(none)* | — | ❌ broken `logo_square_sm.png` | ❌ n/a (no `_footer.html`) | F-01; no footer partial at all |
| `wun` | violet | `logo_square.png` (384²), `logo_square_sm.png` (96²), `logo.png` (**1×1 stub, 70 B**), `iyou_symbol.png`, `icon-192/512.png` | — | ✅ single | ❌ broken `logo_square.png`→`_sm` | F-01 (L3); `logo.png` is a dead pixel |
| `poly` | purple | `logo_square.png` (685²), `logo_square_dark.png` (685²), `logo_square_sm.png` | `poly_mascot_light.png` (281²), `poly_mascot_dark.png` (281²) | ⚠️ **hand-patched dual** | ✅ dual (generator) | F-04 (header not regenerable) |
| `name` | teal | `logo_square.png` (768²), `logo_square_sm.png` (96²), `iyou_name_symbol.png`, `iyou_name_symbol_sm.png`, `namechartharp.png`, `tinynamelogo.png` + `tinynamelogo_DM.png` (351×82 wordmark) | — | ✅ single | ❌ broken `logo_square.png` | F-03 (`_DM` convention); L3 broken |
| `hive` | orange | `logo_square.png` (192²), `logo_square_dark.png` (192²), `logo_square_sm.png` — triplicated in `static/img/`, `static/frontend/img/`, `frontend/public/img/` | `hiver_mascot_light.png/.jpg` (768²), `hiver_mascot_dark.png/.jpg` (768²) — ⚠️ **misspelled slug** | ⚙️ React `StandardHeader.tsx`, JS `onError` | ⚙️ React `MascotFooter.tsx`, JS `onError` | F-05, F-06; no Django partials (React SPA) |
| `ride` | lime | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `dctech` | indigo | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `safe` | rose | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `talk` | cyan | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `clar` | emerald | *(none)* | — | ❌ broken | ❌ broken | F-02 (deep Django layout) |
| `play` | amber | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `blog` | sky | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `help` | red | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `draw` | fuchsia | `logo.png` (1080²), `logo_square.png` (1080²), `logo_square_sm.png`, `favicon.png` | — | ✅ single | ✅ single | Consistent already |
| `life` | sky | *(none)* | — | ❌ broken | ❌ broken | F-02 |
| `walk` | green | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `stay` | yellow | *(none)* | — | ❌ broken | ❌ broken | F-01 |
| `dev` | zinc | *(none)* | — | ❌ broken | ❌ broken | F-01, F-02 |
| `spot` | pink | `apps/core/static/images/M_LOGO.png` (831²), `Musterd_LOGO_Gemini_Generated_Image_*.png`, `SPLAT_*.png` ×5, `splat-mask.svg`, `icon.png`, `mascots/` | — | ❌ broken | ❌ broken | F-03 (freeform names, wrong dir) |
| `baba` | blue | `logo_square.png` (512²), `logo_square_sm.png`, `favicon.ico`, `mesh_avatar_default.svg` | 🏷️ emoji via `APP_GLYPHS` | ✅ **glyph** | ✅ **glyph** | Cleanest implementation in fleet — the reference pattern |

**Supporting projects:** `iyou_home` / `iyou_mobile` (Tauri `icons/Square*Logo.png` — platform packaging, out of scope); `did_rust`, `iyou_name_rust` (no UI).

### 2.2 Naming Convention Drift Catalogue

Five distinct conventions are live today. This standard collapses them to one grammar (§3.2).

| Convention | Example | Repos | Fate |
|:---|:---|:---|:---|
| Generator-hardcoded | `logo_square_sm.png`, `logo_square.png` | all 20 | ✅ canonical |
| Suffix `_dark` | `logo_square_dark.png` | poly, hive | ✅ canonical (`_variant` token) |
| Suffix `_DM` | `tinynamelogo_DM.png`, `createdinDeKalb_DM.png` | name | ⚠️ deprecated → `_dark` |
| Slug-misspelled | `hiver_mascot_*.png` | hive | ⚠️ deprecated → `mascot_*.png` |
| Freeform / generated | `M_LOGO.png`, `Musterd_LOGO_Gemini_Generated_Image_3305ux3305ux3305.png`, `NEW_LOGO.png`, `POLY_LOGO_dark.png` | spot, draw, poly | ⚠️ deprecated |

Repo-root design files (`POLY_LOGO.png`, `DARK_mode_LOGO.png`, `light_mode_LOGO.png`, `NEW_LOGO.png`) are **source masters**, not runtime assets. They MUST move to a `brand/` directory to stop polluting discovery scans.

### 2.3 Theme-Switch Readiness Audit (blocking prerequisite for F-02)

Dual-theme markup requires `darkMode: 'class'` in Tailwind **and** a `.dark` class present on `<html>` before first paint.

| App | `darkMode: 'class'` | `.dark` bootstrap script | Dual-theme logos viable? |
|:---|:---|:---|:---|
| `wun` | ✅ | ✅ `base.html` + `static/js/theme.js` | ✅ |
| `poly` | ✅ | ✅ `base.html` | ✅ (already dual) |
| `baba` | ✅ | ✅ `base.html` + `static/js/theme.js` | ✅ |
| `name` | ✅ | ✅ `base.html` | ✅ |
| `hive` | ✅ (`frontend/`) | ✅ React | ✅ (needs markup change) |
| `stay` | — | ⚠️ `static/js/theme.js` only (not inline) | ⚠️ flash risk |
| `draw` | — | ⚠️ page-level templates, not `base.html` | ⚠️ flash risk |
| `clar` | — | ✅ `apps/core/templates/core/base.html` | ✅ |
| `play` | — | ✅ `templates/base.html` | ✅ |
| `life` | — | ✅ `templates/base.html` | ✅ |
| **`idp`, `ride`, `dctech`, `safe`, `talk`, `blog`, `help`, `walk`, `dev`, `spot`** | ❌ | ❌ **absent** | ❌ **blocked** |

> **Normative gate (G-1):** No satellite MUST be given dual-theme brand markup until its `<html>` `.dark` bootstrap is verified. Shipping `hidden dark:inline-block` into a repo without F-02 fixed produces a permanently hidden logo — a worse failure than the broken image it replaces.

### 2.4 Generator Defect Register

Locations in `scripts/generate_templates.py` (1251 lines, current).

| ID | Line(s) | Defect |
|:---|:---|:---|
| D-01 | 1063–1068 | `generate_standard_header()` hardcodes `img/logo_square_sm.png` + `onerror` → `logo_square.png`. **No `logo_square_dark.png` support at all**, despite poly and hive shipping that exact file. |
| D-02 | 1097, 1103 | `generate_footer()` mascot path is `img/{slug}_mascot_{light,dark}.png`. For `hive` this emits `hive_mascot_*`; disk has `hiver_mascot_*` → **broken in hive**. |
| D-03 | 1057–1061 | Glyph mode is an all-or-nothing `if slug in APP_GLYPHS`. A glyph app that later ships a logo can never graduate without a generator edit. |
| D-04 | 1065, 1121 | Inline `onerror` JS — CSP-hostile, flashes broken-image alt text, and is redundant once detection is filename-based. |
| D-05 | 162–165 | `APP_MASCOTS` conflates *asset identity* (`polly`) with *alt text*. There is no way to express "mascot exists, no dark variant." |
| D-06 | 168–170 | `APP_GLYPHS` has one entry (`baba`) — a manual opt-in list. Every other glyph app requires a generator edit. |
| D-07 | 1135–1143 | `generate()` receives `output_dir` only; it has **no knowledge of the repo root**, so it cannot inspect `static/`. Filename-based detection is impossible without a new parameter. |
| D-08 | 1052, 1085 | `generate_standard_header()` / `generate_footer()` take `(slug, color, descriptor)`; no brand-asset input, no theme capability. |

---

## 3. Canonical Asset Naming Specification

### 3.1 Directory Contract

All runtime brand assets MUST live in a single static root. The standard root is **`static/img/`** (Django flat), resolving to `apps/core/static/img/` or `apps/core/templates/core/static/img/` under the deep-Django layouts — identical to today's dominant convention, so adoption is file *moves*, not re-plumbing.

React satellites (`hive`) place the same filenames under `frontend/public/img/`. `iyou_spot` MUST migrate `apps/core/static/images/` → `apps/core/static/img/`; `static/images/` is retired as a brand root.

| Directory | Purpose |
|:---|:---|
| `static/img/` | **Canonical** runtime brand assets consumed by generated templates |
| `brand/` | Non-runtime source masters (full-resolution, pre-optimisation, `.psd`/`.svg`/`.ai`) |
| `staticfiles/`, `node_modules/`, `.venv/` | Never scanned; excluded from every detection routine |

### 3.2 Canonical Filename Grammar

```
<brand-subject>[_<shape>][_<variant>][_<size>].<ext>
```

| Token | Allowed values | Meaning |
|:---|:---|:---|
| `brand-subject` | `logo` \| `mascot` \| `symbol` \| `avatar` | What the asset is |
| `shape` | `square` \| `wide` | Square (app mark, 1:1) vs. wordmark (wide lockup) |
| `variant` | `light` \| `dark` \| `alt` | Surface it is drawn for, or an alternate/easter-egg mark |
| `size` | `sm` \| `md` \| `lg` | Rendered size class; omit for the default (`md`) |
| `ext` | `png` \| `svg` \| `webp` \| `jpg` | `png`/`svg` normative; `jpg` tolerated for photographic mascots |

**Canonical runtime set (the only files templates ever reference):**

| Filename | Role |
|:---|:---|
| `logo_square.png` | **Universal single logo** — app mark for both themes |
| `logo_square_light.png` | Dual-theme: drawn for light surfaces |
| `logo_square_dark.png` | Dual-theme: drawn for dark surfaces |
| `logo_square_sm.png` | *Deprecated* — retained for import compatibility, emitted nowhere new |
| `mascot.png` | Single mascot |
| `mascot_light.png` / `mascot_dark.png` | Dual-theme mascot |
| `mascot_alt.png` | Alternate / easter-egg mascot (explicit opt-in only) |
| `symbol.png` | Fallback monogram (pre-glyph fallback) |

**Deprecated — MUST NOT be emitted by the generator, MUST be migrated:**

`logo.png` (ambiguous with favicons) · `logo_square_sm.png` (superseded) · `*_DM.png` → `*_dark.png` · `{slug}_mascot_*.png` → `mascot_*.png` · `hiver_mascot_*` → `mascot_*` · `M_LOGO.png`, `*_Gemini_Generated_*.png` → `logo_square.png` · `tinynamelogo*.png` → `logo_wide{,_dark}.png` · `*_square_dark.png` (non-canonical variants such as `logo_square_dark.png` are canonical; `POLY_LOGO_dark.png` at repo root is not)

### 3.3 Brand Capability Enum (`LOGO_MODE`)

```python
LOGO_MODE_SINGLE     = "SINGLE"      # one mark, all themes
LOGO_MODE_DUAL       = "DUAL"        # distinct light/dark marks
LOGO_MODE_MASCOT     = "MASCOT"      # mascot pair drives both layers
LOGO_MODE_GLYPH_ONLY = "GLYPH_ONLY"  # typographic/emoji mark, no raster asset
```

`LOGO_MODE` is **derived, never hand-maintained** (see §3.4). `APP_GLYPHS` remains the *source* of the glyph value for `GLYPH_ONLY` apps and is retired as a *mode selector*.

### 3.4 Detection Algorithm (normative)

Detection is a pure function of the file system. Given a resolved static root `S`:

```
detect_brand(S) -> (mode, header_markup_src, footer_markup_src, glyph)

1. if exists(S/"mascot_light") and exists(S/"mascot_dark")
       and not exists(S/"logo_square_light")      -> MASCOT
2. elif exists(S/"logo_square_light") and exists(S/"logo_square_dark") -> DUAL
3. elif exists(S/"logo_square")                  -> SINGLE
4. elif glyph = APP_GLYPHS.get(slug)              -> GLYPH_ONLY
5. else                                           -> GLYPH_ONLY with a synthesized
                                                      typographic monogram (see §4.1c)
```

Extensions probed in order: `.png`, `.svg`, `.webp`, `.jpg`.

Rules:

1. **R-1 Declaration by filename.** Adding `logo_square_dark.png` next to an existing `logo_square.png` MUST be sufficient to promote that app from `SINGLE` to `DUAL`. No generator edit, no dictionary edit, no JS.
2. **R-2 Partial pairs never emit broken markup.** If only `logo_square_dark.png` exists (no light), the app resolves to `SINGLE` using `logo_square_dark.png` as the universal mark. A lone `dark` file MUST NOT be interpreted as a dual declaration.
3. **R-3 Glyph is the terminal fallback.** `GLYPH_ONLY` is the guaranteed-terminal state, so a satellite with no assets renders a typographic monogram and never a broken image. This alone retires F-01.
4. **R-4 Mascot outranks logo for the footer only.** An app in `MASCOT` mode uses its mascot pair in Layer 3 while Layer 1 falls through to the single-logo branch.
5. **R-5 No JS.** Detection resolves entirely at generation time. Emitted markup MUST NOT contain `onerror`, `onload`, or any inline script for brand assets.
6. **R-6 Deterministic.** Detection MUST be order-independent and idempotent: running the generator twice MUST produce byte-identical output.

---

## 4. Template Markup Contract

### 4.1 Layer 1 — Brand Lockup (`_standard_header.html`)

Replaces the `__BRAND_LOGO__` payload at `generate_templates.py:1052–1082`.

**(a) `SINGLE` / `MASCOT` — universal mark**

```html
        <img src="{% static 'img/logo_square.png' %}"
             alt="poly"
             class="w-11 h-11 sm:w-12 sm:h-12 aspect-square rounded-xl object-contain shadow-sm border border-slate-200 dark:border-slate-800 shrink-0 group-hover:scale-105 transition-transform duration-150" />
```

**(b) `DUAL` — pure-CSS theme switching**

```html
        <img src="{% static 'img/logo_square_light.png' %}"
             alt="poly"
             class="w-11 h-11 sm:w-12 sm:h-12 aspect-square rounded-xl object-contain shadow-sm border border-slate-200 dark:border-slate-800 shrink-0 group-hover:scale-105 transition-transform duration-150 block dark:hidden" />
        <img src="{% static 'img/logo_square_dark.png' %}"
             alt="poly"
             class="w-11 h-11 sm:w-12 sm:h-12 aspect-square rounded-xl object-contain shadow-sm border border-slate-200 dark:border-slate-800 shrink-0 group-hover:scale-105 transition-transform duration-150 hidden dark:block" />
```

**(c) `GLYPH_ONLY` — typographic monogram (terminal fallback)**

```html
        <div class="w-11 h-11 sm:w-12 sm:h-12 rounded-xl bg-__COLOR__-500/10 dark:bg-__COLOR__-500/20 border border-__COLOR__-500/30 dark:border-__COLOR__-500/50 flex items-center justify-center text-__COLOR__-600 dark:text-__COLOR__-400 font-extrabold text-xl sm:text-2xl shadow-sm shrink-0 group-hover:scale-105 transition-transform duration-150 select-none">
          <span>🏷️</span>                              <!-- declared glyph, or synthesized monogram -->
        </div>
```

**(d) Synthesized monogram** (no glyph declared, no asset on disk) — first letter of the descriptor, no raster dependency:

```html
          <span aria-hidden="true">G</span>           <!-- GENEALOGY → "G" -->
```

with `role="img"` and `aria-label` on the wrapping `<a>` (already present via `title=`).

### 4.2 Layer 3 — Footer Brand Block (`_footer.html`)

Replaces the `__MASCOT_BLOCK__` payload at `generate_templates.py:1085–1132`.

**(a) `MASCOT` mode**

```html
    <div class="relative group mb-4">
      <img src="{% static 'img/mascot_light.png' %}"
           alt="Polly the Consensus Parrot"
           class="h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-md border border-slate-200 dark:border-transparent block dark:hidden group-hover:scale-105 transition-transform duration-200" />
      <img src="{% static 'img/mascot_dark.png' %}"
           alt="Polly the Consensus Parrot"
           class="h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-lg border border-transparent dark:border-gray-800 hidden dark:block group-hover:scale-105 transition-transform duration-200" />
    </div>
```

**(b) `SINGLE` / `DUAL`** — 80×80 mark, mirroring the Layer 1 pair:

```html
    <div class="relative group mb-4">
      <img src="{% static 'img/logo_square.png' %}"
           alt="wun"
           class="h-20 w-20 sm:h-24 sm:w-24 rounded-2xl object-cover shadow-md border border-slate-200 dark:border-gray-800 group-hover:scale-105 transition-transform duration-200 select-none" />
    </div>
```

For `DUAL` apps the footer emits the same `block dark:hidden` / `hidden dark:block` pair at footer scale.

**(c) `GLYPH_ONLY`** — unchanged from today's `baba` behaviour (`APP_GLYPHS` span in an accent-tinted tile). This is the reference implementation the fleet should be converging on.

### 4.3 Zero-Flash Guarantee

| Layer | Mechanism | Status |
|:---|:---|:---|
| `.dark` on `<html>` before first paint | Inline `<script>` in `<head>` reading `localStorage['{slug}_theme']` with `prefers-color-scheme` fallback | ✅ `wun`, `poly`, `baba`, `name`, `clar`, `play`, `life`, `hive` |
| Logo swap | Pure CSS `display` toggle on the existing `.dark` class | ✅ no reflow, no reload, no listener |
| Asset preloading | `<link rel="preload" as="image">` for the *inactive* variant only when `DUAL` | 🆕 recommended |
| Colour transition | Existing `transition-colors duration-200` on `<header>` | ✅ |

No JavaScript logo listener is introduced. The swap is a style recalculation triggered by the same class the theme toggle already manages.

### 4.4 Prohibited Patterns

| Prohibited | Reason | Replaced by |
|:---|:---|:---|
| `onerror="this.src=..."` on brand `<img>` | CSP-hostile; flashes broken alt text; JS-dependent | Generation-time detection (R-5) |
| `<picture>` / `<source media="(prefers-color-scheme:dark)">` | Tracks the OS, not the in-app toggle; cannot honour `{slug}_theme` | `dark:` variants keyed to `<html class="dark">` |
| JS `src` swapping on toggle | Reflow + reload; breaks zero-flash | CSS `hidden` / `dark:block` |
| Emoji or monogram used while a logo exists | Inconsistent brand presence | Detection prefers assets over glyphs |

---

## 5. Implementation Plan — `scripts/generate_templates.py`

### 5.1 New module-level structures (insert after line 183, post-`APP_METADATA`)

```python
# ── Brand Asset Resolution (§3) ───────────────────────────────────────

LOGO_MODE_SINGLE     = "SINGLE"
LOGO_MODE_DUAL       = "DUAL"
LOGO_MODE_MASCOT     = "MASCOT"
LOGO_MODE_GLYPH_ONLY = "GLYPH_ONLY"

# Static-root candidates probed relative to a repo root, in priority order.
STATIC_ROOT_CANDIDATES = (
    "static/img",
    "static/frontend/img",
    "apps/core/static/img",
    "apps/core/templates/core/static/img",
    "apps/core/static/images",
    "static/images",
    "frontend/public/img",
    "frontend/public/images",
)

ASSET_EXTENSIONS = (".png", ".svg", ".webp", ".jpg")

# Mascot alt-text only. Asset *identity* is now filename-driven (§3.4);
# this dict no longer determines whether a mascot block is emitted (fixes D-05).
APP_MASCOT_ALT = {
    "poly": "Polly the Consensus Parrot",
    "hive": "Hiver the Legal Vault Keeper",
}

# Optional per-slug override. Empty dict = pure filesystem detection (R-1).
LOGO_MODE_OVERRIDES: dict[str, str] = {}
```

`APP_GLYPHS` (168–170) is **retained unchanged** — it remains the source of truth for glyph values under `GLYPH_ONLY`; it simply stops being a mode selector (fixes D-03/D-06).

### 5.2 New functions (insert before `generate_ecosystem_bar`, line 984)

```python
def resolve_static_root(repo_dir: Path | None) -> Path | None:
    """First existing canonical static root for a repo, or None."""
    if repo_dir is None:
        return None
    for rel in STATIC_ROOT_CANDIDATES:
        candidate = repo_dir / rel
        if candidate.is_dir():
            return candidate
    return None


def _find_asset(static_root: Path | None, stem: str) -> str | None:
    """Return a Django static path ('img/logo_square.png') for <stem>, or None.

    Probes ASSET_EXTENSIONS in order. Never raises.
    """
    if static_root is None:
        return None
    for ext in ASSET_EXTENSIONS:
        if (static_root / f"{stem}{ext}").is_file():
            rel = static_root / f"{stem}{ext}"
            return f"img/{rel.name}" if static_root.name == "img" else f"{rel.relative_to(static_root.parent).as_posix()}"
    return None


def detect_brand_mode(repo_dir: Path | None, slug: str) -> tuple[str, Path | None]:
    """Resolve (mode, static_root) per the normative algorithm in §3.4.

    Honours LOGO_MODE_OVERRIDES before probing the filesystem (R-1).
    """
    static_root = resolve_static_root(repo_dir)
    if slug in LOGO_MODE_OVERRIDES:
        return LOGO_MODE_OVERRIDES[slug], static_root

    logo_light = _find_asset(static_root, "logo_square_light")
    logo_dark  = _find_asset(static_root, "logo_square_dark")
    logo_single = _find_asset(static_root, "logo_square")
    mascot_light = _find_asset(static_root, "mascot_light")
    mascot_dark  = _find_asset(static_root, "mascot_dark")

    # R-2: a lone dark file never declares DUAL; it becomes the universal mark.
    if logo_light and logo_dark:
        return LOGO_MODE_DUAL, static_root
    if logo_light or logo_dark or logo_single:
        return LOGO_MODE_SINGLE, static_root
    if mascot_light and mascot_dark:
        return LOGO_MODE_MASCOT, static_root
    return LOGO_MODE_GLYPH_ONLY, static_root
```

### 5.3 Replace `generate_standard_header()` (1052–1082)

New signature and body — the `logo_markup` branch becomes a three-way switch driven by `logo_mode`:

```python
def generate_standard_header(
    slug: str,
    color: str,
    descriptor: str = "",
    *,
    logo_mode: str = LOGO_MODE_GLYPH_ONLY,
    static_root: Path | None = None,
) -> str:
    """Generate Layer 1 Standard Header partial matching §3.1 & §3.2."""
    if not descriptor:
        descriptor = APP_DESCRIPTORS.get(slug, APP_METADATA.get(slug, {}).get("badge", slug.upper()))

    shell = (
        'w-11 h-11 sm:w-12 sm:h-12 aspect-square rounded-xl object-contain shadow-sm '
        'border border-slate-200 dark:border-slate-800 shrink-0 group-hover:scale-105 '
        'transition-transform duration-150'
    )

    if logo_mode == LOGO_MODE_DUAL:
        light = _find_asset(static_root, "logo_square_light")
        dark  = _find_asset(static_root, "logo_square_dark")
        logo_markup = (
            f'''        <img src="{{% static '{light}' %}}" alt="{slug}" class="{shell} block dark:hidden" />\n'''
            f'''        <img src="{{% static '{dark}' %}}" alt="{slug}" class="{shell} hidden dark:block" />'''
        )
    elif logo_mode == LOGO_MODE_SINGLE:
        src = (_find_asset(static_root, "logo_square_light")
               or _find_asset(static_root, "logo_square_dark")
               or _find_asset(static_root, "logo_square"))
        if src:                                    # R-3: never emit a broken <img>
            logo_markup = f'''        <img src="{{% static '{src}' %}}" alt="{slug}" class="{shell}" />'''
        else:
            logo_markup = _glyph_tile(color, APP_GLYPHS.get(slug, descriptor[:1]))
    else:
        logo_markup = _glyph_tile(color, APP_GLYPHS.get(slug, descriptor[:1]))
    ...
```

with the glyph tile extracted from today's lines 1059–1061 into `_glyph_tile(color, glyph)`.

### 5.4 Replace `generate_footer()` (1085–1132)

```python
def generate_footer(
    slug: str,
    color: str,
    descriptor: str = "",
    mission: str = "",
    *,
    logo_mode: str = LOGO_MODE_GLYPH_ONLY,
    static_root: Path | None = None,
) -> str:
```

The `mascot_block` branch becomes:

| Condition | Emitted block |
|:---|:---|
| `logo_mode == MASCOT` | `mascot_light.png` / `mascot_dark.png` pair, alt text from `APP_MASCOT_ALT` |
| `logo_mode == DUAL` | `logo_square_light.png` / `logo_square_dark.png` pair at footer scale |
| `logo_mode == SINGLE` | single `logo_square.png` at footer scale, **no `onerror`** |
| `logo_mode == GLYPH_ONLY` | `_glyph_tile()` — today's `baba` output |

This removes the `{slug}_mascot_*` interpolation entirely, fixing D-02.

### 5.5 Thread `repo_dir` through `generate()` and `main()` (fixes D-07)

```python
def generate(
    slug: str,
    color: str,
    output_dir: Path,
    skip_header: bool = False,
    badge: str | None = None,
    mission: str | None = None,
    dry_run: bool = False,
    repo_dir: Path | None = None,          # NEW — enables filesystem detection
    logo_mode: str | None = None,          # NEW — explicit override
) -> None:
    if repo_dir is None:                   # best-effort inference from output_dir
        for parent in [output_dir, *output_dir.parents]:
            if (parent / ".git").exists():
                repo_dir = parent
                break
    if logo_mode is None:
        logo_mode, static_root = detect_brand_mode(repo_dir, slug)
    else:
        _, static_root = detect_brand_mode(repo_dir, slug)
```

Then pass `logo_mode=logo_mode, static_root=static_root` into both `generate_standard_header()` and `generate_footer()`. `main()` gains `--repo-dir` and `--logo-mode {single,dual,mascot,glyph}` arguments.

### 5.6 Call-site updates

| File | Line | Change |
|:---|:---|:---|
| `scripts/regenerate_all.py` | 123–160 | `regenerate_app()` already receives `repo_dir` — pass it as `repo_dir=repo_dir` to `generate()`; it already maps `slug → (color, repo_name, layout)` so `hive`'s React SPA can be flagged `skip_header=True` while still receiving a regenerated `_footer.html`. |
| `scripts/ecosystem_integration.py` | 184+ (`step1_register_generate`) | Already takes `--repo-dir`; thread it into the `generate_templates.py` invocation. |
| `scripts/generate_templates.py` | 1204–1247 | `main()`: add `--repo-dir`, `--logo-mode`; add `hive` to a `REACT_SPA_HEADER_SKIP` set so Layer 1 generation is skipped for the SPA. |

### 5.7 Change Summary Table

| File | Function / region | Lines | Action |
|:---|:---|:---|:---|
| `generate_templates.py` | after `APP_METADATA` | new ~183a | Add `LOGO_MODE_*`, `STATIC_ROOT_CANDIDATES`, `ASSET_EXTENSIONS`, `APP_MASCOT_ALT`, `LOGO_MODE_OVERRIDES` |
| `generate_templates.py` | before `generate_ecosystem_bar` | new ~983a | Add `resolve_static_root()`, `_find_asset()`, `detect_brand_mode()`, `_glyph_tile()` |
| `generate_templates.py` | `generate_standard_header()` | 1052–1082 | Rewrite — 4-way mode switch, drop `onerror` |
| `generate_templates.py` | `generate_footer()` | 1085–1132 | Rewrite — 4-way mode switch, drop `{slug}_mascot_*`, drop `onerror` |
| `generate_templates.py` | `generate()` | 1135–1201 | Add `repo_dir`/`logo_mode` params + inference; thread through |
| `generate_templates.py` | `main()` | 1204–1247 | Add `--repo-dir`, `--logo-mode` |
| `regenerate_all.py` | `regenerate_app()` | 123–192 | Pass `repo_dir=` |
| `ecosystem_integration.py` | `step1_register_generate()` | 184–200 | Pass `--repo-dir` |

---

## 6. Rollout Plan

| Phase | Scope | Action | Gate |
|:---|:---|:---|:---|
| **P0 — Unblock** | 10 satellites | Add the F-02 `.dark` bootstrap `<script>` to `base.html`; add `darkMode: 'class'` to `tailwind.config.js` | Verified: `document.documentElement.classList` receives `'dark'` from `localStorage['{slug}_theme']` |
| **P1 — Generator** | `omni_social` | Implement §5 | `--dry-run` across all 20 slugs emits **zero** `onerror` and zero missing-asset paths |
| **P2 — Asset migration** | `poly`, `hive`, `name`, `spot`, `wun`, `baba` | Rename to canonical grammar; move repo-root masters into `brand/`; dedupe hive's triplicated `img/` trees | `detect_brand_mode()` returns the intended mode for each |
| **P3 — Regenerate** | all 20 | `python scripts/regenerate_all.py` | Byte-identical output on a second run (R-6) |
| **P4 — React parity** | `hive` | Port `StandardHeader.tsx` / `MascotFooter.tsx` to `mascot_*.png` + CSS visibility classes; drop `onError` handlers | No JS asset swapping remains |
| **P5 — Spec propagation** | 24 repos | Add this file to `SPEC_FILES` in `sync_ecosystem_specs.py`; run the sync | All satellites carry the naming contract |

**P2 rename map:**

| From | To | Repo |
|:---|:---|:---|
| `poly_mascot_light.png` / `poly_mascot_dark.png` | `mascot_light.png` / `mascot_dark.png` | poly |
| `hiver_mascot_{light,dark}.{png,jpg}` | `mascot_{light,dark}.png` | hive |
| `tinynamelogo{,_DM}.png` | `logo_wide{,_dark}.png` | name |
| `createdinDeKalb{,_DM}.png` | `logo_wide{,_dark}.png` (superseded) | name |
| `M_LOGO.png`, `Musterd_LOGO_Gemini_*.png` | `logo_square.png` | spot |
| `logo.png` (1×1 stub) | *(delete)* | wun |
| `POLY_LOGO{,_dark}.png`, `NEW_LOGO.png`, `*_mode_LOGO.png` | *(move to `brand/`)* | poly, hive, draw |

---

## 7. Conformance Checklist

An implementation claiming brand-asset conformance MUST satisfy:

1. **No broken references** — every emitted `{% static %}` path resolves to a file present in the target repo, for all 20 slugs.
2. **No JS asset handling** — generated templates contain no `onerror`, `onload`, or inline script for brand imagery.
3. **Declaration by filename** — adding `logo_square_dark.png` beside `logo_square.png` promotes `SINGLE → DUAL` with zero generator edits (R-1).
4. **Terminal glyph fallback** — a satellite with no assets and no glyph renders a typographic monogram, never a broken image (R-3).
5. **Idempotence** — two consecutive generator runs produce byte-identical output (R-6).
6. **Pure-CSS swap** — theme toggling switches logos with no listener, no reflow, and no image reload.
7. **G-1 compliance** — no `DUAL` markup ships to a satellite lacking a verified `.dark` bootstrap (§2.3).
8. **Grammatical filenames** — every runtime asset matches `<subject>[_<shape>][_<variant>][_<size>].<ext>` (§3.2).

---

## 8. Risks & Open Questions

| Risk | Impact | Mitigation |
|:---|:---|:---|
| **`glyph` glyph fallback uses the descriptor's first letter** | Renders `G` for GENEALOGY, `A` for ATHLETICS — a visible brand regression vs. a designed mark | Acceptable for the 12 asset-less satellites (today they render *nothing*); commission real glyphs in a follow-up |
| **Regeneration clobbers hand-tuned `iyou_poly` header** | Loss of the F-04 hand-pask | P2 migration preserves `logo_square_dark.png`; P3 output reproduces the hand-patch automatically — verify with `regenerate_all.py --dry-run` first |
| **Tailwind JIT purges unused classes** | `hidden dark:block` dropped from compiled CSS if the app has no dark assets | Detection guarantees both classes appear in emitted markup for `DUAL` apps; verify compiled CSS contains `.dark\\:block` |
| **`static/img` vs `static/images` split in `iyou_spot`** | Detection picks the wrong root | `STATIC_ROOT_CANDIDATES` probes both; P2 consolidates on `img/` |
| **P0 touches 10 satellites' `base.html`** | Broad blast radius, unrelated to branding | Sequence P0 as its own commit per repo; the inline script is ~10 lines and already fleet-standard in `wun`/`poly`/`baba` |
| **`svg` vs `png` mixed roots** | Mixed rasterisation hints | `ASSET_EXTENSIONS` order makes `png` win when both exist; document `svg` as the preferred long-term format |

---

## Appendix A — Detection Matrix (post-migration target state)

| App | `logo_square{,_light,_dark}` | `mascot_{light,dark}` | Glyph | Resolved mode |
|:---|:---|:---|:---|:---|
| `idp` | — | — | — | `GLYPH_ONLY` (synth monogram) |
| `wun` | ✅ | — | — | `SINGLE` |
| `poly` | ✅ light + dark | ✅ | — | `DUAL` (mascot in L3) |
| `name` | ✅ | — | — | `SINGLE` |
| `hive` | ✅ light + dark | ✅ | — | `DUAL` (React) |
| `ride`, `dctech`, `safe`, `talk`, `clar`, `play`, `blog`, `help`, `life`, `walk`, `stay`, `dev` | — | — | — | `GLYPH_ONLY` |
| `draw` | ✅ | — | — | `SINGLE` |
| `spot` | ✅ *(after P2 rename)* | — | — | `SINGLE` |
| `baba` | ✅ | — | 🏷️ | `SINGLE` *(logo now outranks glyph — R-3; glyph demoted to footer)* |

## Appendix B — Per-Repo Migration Actions

| Repo | Actions |
|:---|:---|
| `omni_social` | Implement §5; add spec to `SPEC_FILES`; run sync |
| `iyou_poly` | Rename mascots to `mascot_*`; move `POLY_LOGO*` → `brand/`; delete hand-patch (regenerator now emits it) |
| `iyou_hive` | Rename `hiver_mascot_*` → `mascot_*`; dedupe 3 img trees; port `StandardHeader.tsx` + `MascotFooter.tsx` to CSS visibility, drop `onError`; move `*_mode_LOGO.png` → `brand/` |
| `iyou_name` | `tinynamelogo{,_DM}.png` → `logo_wide{,_dark}.png`; retire `createdinDeKalb*`; add `.dark` verification |
| `iyou_wun` | Delete 1×1 `logo.png` stub |
| `iyou_spot` | Consolidate `static/images/` → `static/img/`; rename `M_LOGO.png` → `logo_square.png`; archive Gemini-generated source |
| `iyou_baba` | None required — reference implementation |
| `iyou_draw` | Move `NEW_LOGO.png` → `brand/` |
| `idp`, `ride`, `dctech`, `safe`, `talk`, `clar`, `play`, `blog`, `help`, `life`, `walk`, `stay`, `dev` | P0 `.dark` bootstrap + `darkMode: 'class'`; accept monogram fallback (optionally commission glyphs) |

## References

- `STANDARD_UI_SPECIFICATION.md` — Layer 0/1/2 anatomy, zero-flash theme engine (§2.4, §3.5)
- `PROJECT_ZERO_SPEC.md` — identity tiers (the brand mark is presentational, never an identity assertion)
- `AGENT.md` — template anatomy, color conventions, regeneration workflow
- `scripts/generate_templates.py` — implementation target
- `scripts/regenerate_all.py` — fleet regeneration driver
- `scripts/ecosystem_integration.py` — 10-step onboarding (Step 1 edits `generate_templates.py`)