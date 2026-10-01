# ThreatLens SOC Console — Frontend

Vanilla JS operations console for the ThreatLens CTI platform (Sentinova
Security Systems). No framework, no build step — plain ES modules, IBM Plex
Sans + Mono, dark-first SOC palette with a high-contrast light mode.

## Structure

```
threatlens.html      single-page console
index.html           convenience redirect to the console
src/
  app.js            boot, routing, WebSocket, session glue
  core.js           config, transport, demo fixtures
  views.js          overview, triage, drawer, incidents
  hunt.js           hunt workspace: facets, graph, ATT&CK
  admin.js          feeds, users, audit, health
  heatmap.js        geographic threat density map (FR-20)
  widgets.js        dashboard widget library (FR-22)
  styles.css        all styles (tokens + components + craft revisions)
design/
  tokens.css        design token sheet
  DECISIONS.md      reference dossier + argued decisions
```

## Running

**Same origin (recommended):** the FastAPI backend serves this folder
automatically when it sits next to `threatlens-backend/` (or via `CONSOLE_DIR`).
Start the backend and open `http://127.0.0.1:8000` — no CORS, WebSocket
connects directly.

**Standalone static server:**

```bash
python -m http.server 4173
# open http://localhost:4173/threatlens.html?api=http://127.0.0.1:8000
```

The backend allows CORS from the localhost static-server port (4173), or
use the sign-in ENDPOINT field to point at any reachable backend. Without a
backend the console boots in demo mode with deterministic fixtures.

## Key implementation details

- No framework: vanilla ES modules, flat component structure
- Two render paths: live (real API data) and demo (offline fallback), selected by
  backend health probe at boot
- API base resolution order: `?api=` URL param → `localStorage['tl.api']` →
  `window.ThreatLensConfig.apiBase` → same origin
- WebSocket channels: alerts.stream, indicators.high_severity, incidents.{id},
  system.health — with auto-reconnect, backoff, and polling fallback
- Widget system: show/hide Executive overview sections, persisted per user (FR-22)
- Geographic heatmap: dot-density SVG on equirectangular projection with country
  centroids (FR-20)
- Incident tabs: timeline (append-only), linked indicators, containment checklist
- All API errors surfaced with the uniform envelope: error_code, message, correlation_id
