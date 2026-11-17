<!-- AUTO-GENERATED FROM scripts/generate_templates.py (ECOSYSTEM_CATALOG) — DO NOT EDIT MANUALLY -->

# Canonical Ecosystem Roster

## §0 Zero-CamelCase Brand Invariant

**The CamelCase brand form — a lowercase `i` immediately followed by an uppercase `Y` (`i` + `You`) — is STRICTLY BANNED across the entire federation.** No UI copy, template, generated artifact, source string, config, spec, or documentation may contain that form. Always use lowercase `iyou`, `iyou_`, or `iyou.me`.

- The federation map title is ALWAYS `iyou_ Federation Map`.
- The ecosystem descriptor is ALWAYS `iyou_ ecosystem`.
- App brands are ALWAYS lowercase snake_case: `iyou_clar`, `iyou_wun`, `iyou_idp`, `iyou_home`, `iyou_mobile`, `iyou_hive`, etc.
- Valid lowercase URLs (`https://iyou.me`, `wss://...`), cryptographic prefixes, and external third-party identifiers are unaffected.

## §1 Governance & Immutable Copy Rule

**This document is the Single Source of Truth (SSOT) for canonical ecosystem copy.** It is generated directly from `ECOSYSTEM_CATALOG` and `ENCLAVE_CATALOG` in `omni_social/scripts/generate_templates.py`.

- `descriptor` is the **canonical uppercase tagline**; `mission` is the **canonical footer/map subtitle**. Both are owned by the user and are immutable copy.
- Agents must **never** rewrite, reword, shorten, capitalize differently, or otherwise 'improve' any `descriptor` or `mission` string without an explicit word-for-word instruction from the user.
- Agents must **never** hand-edit generated template artifacts: `_ecosystem_bar.html`, `_standard_header.html`, `_footer.html`, `_persona_enclave.html`, `_tailwind_safe_init.html`. Read canonical metadata from `docs/ecosystem_shared/ECOSYSTEM_CANONICAL_ROSTER.md` instead.

## §2 Canonical Satellite Roster Table

Protocol order, all 28 registered satellites:

| # | Slug | App Name | URL | Ring / Axis | Status | Color | Canonical Tagline (descriptor) | Canonical Mission (mission) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | idp | iyou_idp | https://iyou.me | gate | ACTIVE | purple | IDENTITY PROVIDER | Root Identity Provider & Sovereign Authentication |
| 2 | wun | iyou_wun | https://wun.iyou.me | nucleus | ACTIVE | violet | SOCIAL HUB | Social Hub & Sovereign Profile Space |
| 3 | chat | iyou_chat | https://chat.iyou.me | nucleus | ACTIVE | cyan | MESSENGER HUB | Sovereign Messenger Hub, MAM Archive & Standalone Dock |
| 4 | meet | iyou_meet | https://meet.iyou.me | nucleus | ACTIVE | teal | VIDEO & RENDEZVOUS | Sovereign Video Conferencing & Physical Meetup Orchestration |
| 5 | poly | iyou_poly | https://poly.iyou.me | ring1 | ACTIVE | purple | CONSENSUS ENGINE | Stateless Consensus Engine & Governance Ledger |
| 6 | name | iyou_name | https://name.iyou.me | ring1 | ACTIVE | teal | GENEALOGY REGISTRY | Kinship Graph & Lineage Provenance Ledger |
| 7 | hive | iyou_hive | https://hive.iyou.me | ring1 | BETA | orange | LEGAL VAULT | Communal Vaults & Legal Proofs |
| 8 | show | iyou_show | https://show.iyou.me | ring2 (N) | ACTIVE | rose | VIDEO INDEX | Zero-Custody Video Channel Indexer & Multi-Source Player |
| 9 | hear | iyou_hear | https://hear.iyou.me | ring2 (E) | ACTIVE | amber | AUDIO & V4V | Sovereign Audio, Podcast & Value-for-Value Stream Router |
| 10 | clar | iyou_clar | https://clar.iyou.me | ring2 (S) | ACTIVE | emerald | DIRECTORY LEDGER | Curated Ledger of Authority & Ranking |
| 11 | muse | iyou_muse | https://muse.iyou.me | ring2 (W) | ACTIVE | indigo | EXHIBITION | Attribution-First Public Exhibition Gallery |
| 12 | ride | iyou_ride | https://ride.iyou.me | ring3 | DEV_WIP | lime | TRANSIT AUCTION | Sovereign Transport & Auction Dispatch |
| 13 | dctech | iyou_dctech | https://dctech.iyou.me | ring3 | DEV_WIP | indigo | CORPORATE SITE | Corporate Portal & Security Hardening |
| 14 | safe | iyou_safe | https://safe.iyou.me | ring3 | DEV_WIP | rose | CRISIS TRIAGE | Key Escrow & Emergency Recovery |
| 15 | talk | iyou_talk | https://talk.iyou.me | ring3 | INCUBATING | cyan | PEER SUPPORT | P2P Encrypted Comms & Peer Support |
| 16 | play | iyou_play | https://play.iyou.me | ring3 | INCUBATING | amber | ATHLETICS MASTER | Athletics Master & Sovereign Events |
| 17 | blog | iyou_blog | https://blog.iyou.me | ring3 | INCUBATING | sky | SOVEREIGN PUBLISHING | Censorship-Resistant Sovereign Publishing |
| 18 | help | iyou_help | https://help.iyou.me | ring3 | INCUBATING | red | HELP & SUPPORT | Help, Documentation & User Guidance |
| 19 | draw | iyou_draw | https://draw.iyou.me | ring3 | BETA | fuchsia | CANVAS | Visual Creation Studio |
| 20 | life | iyou_life | https://life.iyou.me | ring3 | DEV_WIP | sky | LEGACY ARCHIVE | Memorial & Sovereign Legacy Archive |
| 21 | walk | iyou_walk | https://walk.iyou.me | ring3 | INCUBATING | green | PEDESTRIAN MESH | Pedestrian Navigation & Sovereign Mesh |
| 22 | stay | iyou_stay | https://stay.iyou.me | ring3 | DEV_WIP | yellow | HOSPITALITY | Hospitality & Sovereign Spaces |
| 23 | dev | iyou_dev | https://dev.iyou.me | ring3 | INCUBATING | zinc | DEVELOPER PORTAL | Mesh Operations & Developer Portal |
| 24 | spot | iyou_spot | https://spot.iyou.me | ring3 | DEV_WIP | pink | LOCAL DISCOVERY | Local Geolocation & Community Discovery |
| 25 | baba | iyou_baba | https://baba.iyou.me | ring3 | INCUBATING | blue | STICKER VAULT | Sovereign Sticker Vault & Curation Foundry |
| 26 | link | iyou_link | https://link.iyou.me | ring3 | INCUBATING | violet | LINK DECK | Sovereign Link Deck, Profile Projection & Universal Routing |
| 27 | dine | iyou_dine | https://dine.iyou.me | ring3 | INCUBATING | amber | RESTAURANT OS | Sovereign Restaurant Operating System, 0% Take-Rate Settlement & Line-to-Floor Telemetry |
| 28 | peer | iyou_peer | https://peer.iyou.me | ring3 | INCUBATING | emerald | P2P MESH | Autonomous Peer-to-Peer Mesh & Gossip Federation |

## §3 Gatehouse & Native Enclaves Table

| App | Descriptor | Mission | Bridge / Platform Role |
| --- | --- | --- | --- |
| iyou_idp | IDENTITY PROVIDER | Root Identity Provider & Sovereign Authentication | Gatehouse root identity anchor (https://iyou.me) |
| iyou_home | DESKTOP ENCLAVE | Local hardware key vault, SQLite vault & 127.0.0.1:9001 RPC bridge | Desktop enclave — loopback bridge `127.0.0.1:9001` |
| iyou_mobile | POCKET ENCLAVE | Mobile biometric secure enclave, offline key signer & push bridge | Pocket enclave — platforms iOS, Android |

## §4 Central Update Workflow (How to Apply Approved Changes)

All approved copy/metadata changes are applied centrally in `omni_social` only. Never patch a satellite template or a shared doc by hand.

```bash
cd ~/CODE_BASE/omni_social
# 1. Edit ECOSYSTEM_CATALOG in scripts/generate_templates.py (the sole source of truth).
# 2. Regenerate all 25 satellite templates, refresh this roster file, and export the hive registry:
.venv/bin/python scripts/regenerate_all.py
# 3. Propagate this roster into docs/ecosystem_shared/ across all repositories:
.venv/bin/python scripts/sync_ecosystem_specs.py
```

Step 2 regenerates `_ecosystem_bar.html` and `_footer.html` across all 25 active satellites and refreshes `../iyou_hive/frontend/src/data/ecosystemRegistry.generated.ts`. Step 3 pushes this file into every repository's `docs/ecosystem_shared/` so no satellite agent can drift from the canonical copy.
