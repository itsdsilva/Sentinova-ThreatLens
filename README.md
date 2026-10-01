# ThreatLens — Cyber Threat Intelligence Dashboard

ThreatLens, by **Sentinova Security Systems**, is a production-style CTI platform:
it ingests indicators of compromise (IOCs) from public threat feeds, enriches them
against reputation services, correlates them with internal security events, assigns
a confidence-weighted 0–100 severity score, and surfaces everything through four
role-specific SOC dashboards (Executive, Analyst, Incident Response, Threat Hunting).

Standards: STIX 2.1 export, MITRE ATT&CK mapping, Traffic Light Protocol, Kill Chain /
Diamond Model fields, CISA KEV integration.

## Repository layout

```
Sentinova-ThreatLens/
├── threatlens-backend/       FastAPI + SQLAlchemy: REST API, feed pipeline, WebSocket
├── threatlens-frontend/      Vanilla JS SOC console — served by the backend
├── docker-compose.yml        one-command full stack (optional)
└── README.md
```

## What you need

- Python 3.11 or newer — https://www.python.org/downloads/ (tick "Add to PATH" on Windows)
- Git — https://git-scm.com/downloads
- Docker Desktop (optional, for the container run)

## 1. Download the project

```bash
git clone https://github.com/itsdsilva/Sentinova-ThreatLens.git
cd Sentinova-ThreatLens
```

No Git installed? On the GitHub page choose **Code → Download ZIP**, then extract it
and open the extracted folder in a terminal.

## 2. Set up the virtual environment

From the repository root:

```bash
python -m venv .venv
```

| OS | Activate |
|---|---|
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Windows (cmd) | `.venv\Scripts\activate.bat` |
| macOS / Linux | `source .venv/bin/activate` |

> PowerShell refuses scripts by default — run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once if activation fails.

## 3. Run the app

```bash
cd threatlens-backend
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

Open **http://127.0.0.1:8000** — the SOC console, REST API and Swagger UI (`/docs`)
are all served from the same origin, no proxy or CORS involved.

First run creates the SQLite database, seeds demo data (personas, feeds, ATT&CK
techniques, indicators, events, incidents) and starts the feed scheduler. The backend
finds the console automatically in the sibling `threatlens-frontend/` folder
(`CONSOLE_DIR` overrides it if you move things around).

### Seeded demo personas

| Role | Email | Password |
|---|---|---|
| SOC analyst | `analyst@sentinova.io` | `Analyst!Secure2026` |
| Incident responder | `responder@sentinova.io` | `IR!Secure2026x` |
| Threat hunter | `hunter@sentinova.io` | `Hunt!Secure2026` |
| Executive | `exec@sentinova.io` | `Exec!Secure2026` |
| Security engineer | `engineer@sentinova.io` | `Eng!nSecure2026` |
| Administrator | `admin@sentinova.io` | `Admin!Secure2026` |

Click a persona button on the sign-in view to fill the form automatically.

## Running with Docker instead

```bash
docker compose up --build
```

Same URL, data persists in a named volume. API keys can be provided through a `.env`
file next to `docker-compose.yml`.

## Enrichment API keys (all optional, all free tiers)

Without keys the platform runs offline on deterministic reference enrichers. With
keys set, every enricher returns live provider data. The simplest setup is a
`.env` file in `threatlens-backend/` (copy `.env.example` and fill it in) — it is
git-ignored and loaded automatically at startup. You can also export them before
starting the server:

```bash
# Windows (PowerShell)
$env:ABUSEIPDB_KEY = "..." ; $env:VIRUSTOTAL_KEY = "..." ; uvicorn app.main:app --port 8000

# macOS / Linux
export ABUSEIPDB_KEY="..." VIRUSTOTAL_KEY="..." && uvicorn app.main:app --port 8000
```

| Key variable | Provider | Used for | Register at |
|---|---|---|---|
| `ABUSEIPDB_KEY` | AbuseIPDB | IP abuse confidence + reports | abuseipdb.com |
| `VIRUSTOTAL_KEY` | VirusTotal | Hash verdict ratios, domain analysis | virustotal.com |
| `OTX_KEY` | AlienVault OTX | Pulse counts, threat context (also the OTX feed) | otx.alienvault.com |
| `SHODAN_KEY` | Shodan | Open ports / exposure for IP indicators | shodan.io |
| `GREYNOISE_KEY` | GreyNoise | Scanner-noise vs. targeted-actor classification | greynoise.io |
| `PHISHTANK_KEY` | PhishTank | Known-phishing URL checks | phishtank.org |
| `MALWAREBAZAAR_KEY` | MalwareBazaar | Sample lookups for hashes (optional) | bazaar.abuse.ch |

No key needed: URLhaus, Feodo Tracker, ThreatFox, MalwareBazaar (feed), Spamhaus
DROP, CISA KEV, ip-api.com (geo/ASN) and the TAXII 2.1 client.

Keys are read from the environment only — nothing is ever stored in the source tree.

## Tests

```bash
cd threatlens-backend
pytest tests -q        # with the venv active
```

Covers scoring, deduplication/normalisation, feed source parsing, RBAC, alert
lifecycle and exports.

## Deployment notes

- Single web service: Render (native Python, persistent disk for SQLite) — see
  `threatlens-backend/render.yaml`; set the service root directory to
  `threatlens-backend`.
- Docker: build from the repository root (`docker-compose.yml` handles it); the
  console ships inside the image.
- PostgreSQL for scale: set `DATABASE_URL`; Elasticsearch search activates with
  `ES_URL` (the document shape, mapping and query builder are already implemented).
