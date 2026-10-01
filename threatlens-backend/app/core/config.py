import secrets
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Populate os.environ from an untracked .env so provider keys (see .env.example)
# are picked up no matter which folder the server is launched from. Real
# environment variables always win; both files stay out of git via .gitignore.
_here = Path(__file__).resolve()
load_dotenv(_here.parent.parent / ".env", override=False)          # threatlens-backend/.env
load_dotenv(_here.parent.parent.parent / ".env", override=False)   # repo root/.env


class Settings(BaseSettings):
    APP_NAME: str = "ThreatLens"
    APP_VERSION: str = "1.0.0"
    ENV: str = "local"

    # System of record. Postgres in production (e.g. postgresql+psycopg://user:pass@host/db),
    # SQLite for zero-dependency local runs.
    DATABASE_URL: str = "sqlite:///./threatlens.db"

    # Auth
    SECRET_KEY: str = ""
    ACCESS_TOKEN_MINUTES: int = 30
    REFRESH_TOKEN_DAYS: int = 7
    MFA_REQUIRED_FOR: list[str] = ["administrator"]  # roles where TOTP may be enforced when enrolled

    # Login hardening
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 15

    # Rate limiting (per principal)
    RATE_LIMIT_PER_MINUTE: int = 240

    # Elasticsearch (optional; when set, search routes to ES)
    ES_URL: str = ''

    # Feed polling defaults (seconds); each feed can override its own schedule
    FEED_POLL_INTERVAL_DEFAULT: int = 900

    # Scoring model weights (documented in services/scoring.py)
    SCORE_W_SOURCE: float = 0.30
    SCORE_W_CONFIDENCE: float = 0.25
    SCORE_W_RECENCY: float = 0.20
    SCORE_W_SIGHTINGS: float = 0.15
    SCORE_W_TYPE: float = 0.10

    # Correlation window for matching indicators to internal events (days)
    CORRELATION_WINDOW_DAYS: int = 7

    # Enrichment / feed provider keys (PRD §21.4). Empty string = provider not
    # configured; the deterministic reference enrichers keep the pipeline
    # functional offline. Values live in .env or real environment variables
    # only — never commit real keys.
    ABUSEIPDB_KEY: str = ""
    VIRUSTOTAL_KEY: str = ""
    OTX_KEY: str = ""
    SHODAN_KEY: str = ""
    GREYNOISE_KEY: str = ""
    PHISHTANK_KEY: str = ""
    MALWAREBAZAAR_KEY: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


_DEV_SECRET = "threatlens-dev-secret-change-me-in-production"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if not s.SECRET_KEY:
        if s.ENV.lower() in ("production", "prod"):
            raise RuntimeError(
                "SECRET_KEY must be set in production (generate one with "
                "`python -c \"import secrets; print(secrets.token_hex(32))\"`)."
            )
        # Local/dev default: random per process so tokens never survive restarts.
        s.SECRET_KEY = secrets.token_hex(32)
    elif s.SECRET_KEY == _DEV_SECRET:
        raise RuntimeError(
            f"SECRET_KEY is still the placeholder {_DEV_SECRET!r}; set a real secret before running."
        )
    return s


settings = get_settings()
