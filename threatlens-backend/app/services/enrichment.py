"""Enrichment service (FR-10..FR-14): IP reputation, malicious-domain analysis,
malware-hash verdicts, geo/ASN. Results are cached (DB-backed with TTL) and
cold lookups are bounded so interactive latency stays in budget.

Providers (PRD §21.4): AbuseIPDB, VirusTotal, ip-api.com, CISA KEV, AlienVault
OTX, Shodan, GreyNoise, URLhaus, MalwareBazaar and PhishTank. Real providers
are used when keys/network allow; deterministic reference enrichers keep the
demo fully functional offline (values are derived from a stable hash of the
indicator so they never contradict themselves between calls)."""
import hashlib
import os
import json
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Enrichment, Indicator, aware
from app.services.scoring import severity_for_score

CACHE_TTL_MINUTES = 60

# Enrichment row (kind, provider) -> key used in the merged full_enrichment payload.
# The indicator detail endpoint reuses this to serve cached provider data cheaply.
PROVIDER_KEYS = {
    ("reputation", "ip_reputation"): "reputation",
    ("reputation", "greynoise"): "noise",
    ("reputation", "otx"): "otx",
    ("reputation", "cisa_kev"): "kev",
    ("geo", "geo_asn"): "geo",
    ("verdicts", "detection_engines"): "verdicts",
    ("verdicts", "malwarebazaar"): "sample",
    ("scan_context", "domain_analysis"): "domain_analysis",
    ("scan_context", "shodan"): "exposure",
    ("scan_context", "urlhaus"): "urlhaus",
    ("scan_context", "phishtank"): "phishtank",
}


def _get_env_key(name: str) -> str:
    """Read an API key from the environment (or the untracked .env loaded by
    app.core.config). Empty string = not configured; the deterministic
    reference enrichers take over so the demo stays offline-friendly."""
    return os.environ.get(name, "")


def _try_abuseipdb(ip: str) -> dict | None:
    """Real AbuseIPDB API call for IP reputation (free: 1000/day)."""
    key = _get_env_key("ABUSEIPDB_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if resp.status_code == 200:
            j = resp.json().get("data", {})
            return {
                "abuse_confidence_score": j.get("abuseConfidenceScore", 0),
                "total_reports": j.get("totalReports", 0),
                "distinct_reporters": j.get("numDistinctUsers", 0),
                "verdict": "malicious" if j.get("abuseConfidenceScore", 0) >= 50 else ("suspicious" if j.get("abuseConfidenceScore", 0) >= 25 else "clean"),
                "isp": j.get("isp", ""),
                "usage_type": j.get("usageType", ""),
                "country_code": j.get("countryCode", ""),
                "is_whitelisted": j.get("isWhitelisted", False),
                "last_reported": j.get("lastReportedAt", ""),
            }
    except Exception:
        pass
    return None


def _try_virustotal_hash(sha256: str) -> dict | None:
    """Real VirusTotal API call for hash verdicts (free: 4/min, 500/day)."""
    key = _get_env_key("VIRUSTOTAL_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + undetected + stats.get("harmless", 0) + stats.get("timeout", 0)
            families = []
            pop = attrs.get("popular_threat_classification", {})
            if pop.get("suggested_threat_label"):
                families.append(pop["suggested_threat_label"].split("/")[0].split(".")[0])
            for _, v in results.items():
                if v.get("result") and v["result"] not in ("clean", "unrated", "timeout"):
                    fam = v["result"].split("/")[0].split(".")[0]
                    if fam and fam not in families:
                        families.append(fam)
            return {
                "engine_total": total or 70,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "ratio": round(malicious / max(1, total), 2),
                "families": families[:3],
            }
    except Exception:
        pass
    return None


def _try_virustotal_domain(domain: str) -> dict | None:
    """Real VirusTotal API call for domain analysis."""
    key = _get_env_key("VIRUSTOTAL_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
            timeout=15,
        )
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            cats = attrs.get("categories", {})
            return {
                "newly_registered": attrs.get("creation_date", 0) > (datetime.now(timezone.utc).timestamp() - 86400 * 90),
                "known_phishing": any("phish" in str(c).lower() for c in cats.values()),
                "dga_like": False,
                "registrar_age_days": max(1, int((datetime.now(timezone.utc).timestamp() - attrs.get("creation_date", 0)) / 86400)) if attrs.get("creation_date") else 0,
                "resolves": True,
                "vt_malicious": stats.get("malicious", 0),
                "vt_suspicious": stats.get("suspicious", 0),
                "vt_harmless": stats.get("harmless", 0),
                "categories": list(cats.values())[:3],
            }
    except Exception:
        pass
    return None


def _try_ipapi_geo(ip: str) -> dict | None:
    """Real geolocation via ip-api.com (free, no key, 45 req/min)."""
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,as,asName,org,lat,lon"},
            timeout=8,
        )
        if resp.status_code == 200:
            j = resp.json()
            if j.get("status") == "success":
                return {
                    "country": j.get("countryCode", ""),
                    "asn": j.get("as", "").split(" ")[0] if j.get("as") else "",
                    "asn_owner": j.get("asName", "") or j.get("org", ""),
                    "latitude": j.get("lat", 0),
                    "longitude": j.get("lon", 0),
                }
    except Exception:
        pass
    return None


OTX_SECTIONS = {
    "ip": "IPv4", "domain": "domain", "url": "URL",
    "hash_md5": "FileHash-MD5", "hash_sha1": "FileHash-SHA1", "hash_sha256": "FileHash-SHA256",
    "email": "email", "cve": "CVE",
}


def _try_otx(indicator: Indicator) -> dict | None:
    """AlienVault OTX indicator context (free key, see otx.alienvault.com)."""
    key = _get_env_key("OTX_KEY")
    section = OTX_SECTIONS.get(indicator.type)
    if not key or not section:
        return None
    try:
        resp = httpx.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator.value}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=20,
        )
        if resp.status_code == 200:
            j = resp.json()
            pulse_info = j.get("pulse_info", {})
            pulses = pulse_info.get("count", 0) if isinstance(pulse_info, dict) else 0
            names = [p.get("name", "") for p in (pulse_info.get("pulses") or []) if isinstance(p, dict)][:3]
            malware = [m.get("family") or m.get("name", "") for m in j.get("malware", {}).get("malware", []) if isinstance(m, dict)]
            return {
                "pulse_count": pulses,
                "pulse_names": names,
                "malware_families": [m for m in malware if m][:3] or None,
                "validation": [
                    {"source": v.get("name"), "detection": v.get("detection")}
                    for v in (j.get("validation") or [])[:2] if isinstance(v, dict)
                ],
            }
    except Exception:
        pass
    return None


def _try_shodan(ip: str) -> dict | None:
    """Shodan host/exposure lookup for IP indicators (free tier, shodan.io)."""
    key = _get_env_key("SHODAN_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}, timeout=8)
        if resp.status_code == 200:
            j = resp.json()
            return {
                "org": j.get("org") or j.get("asn"),
                "asn": (j.get("asn") or "").replace("AS", ""),
                "ports": sorted(j.get("ports") or [])[:8],
                "hostnames": (j.get("hostnames") or [])[:3],
                "country": j.get("country_code"),
                "last_update": j.get("last_update"),
            }
    except Exception:
        pass
    return None


def _try_greynoise(ip: str) -> dict | None:
    """GreyNoise community context: separates internet-wide scanner noise from
    real targeting (free community key, greynoise.io)."""
    key = _get_env_key("GREYNOISE_KEY")
    if not key:
        return None
    try:
        resp = httpx.get(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": key}, timeout=8)
        if resp.status_code == 200:
            j = resp.json()
            return {
                "classification": j.get("classification"),
                "actor": j.get("name"),
                "noise": j.get("noise"),
                "tags": (j.get("tags") or [])[:5],
                "last_seen": j.get("last_seen"),
            }
    except Exception:
        pass
    return None


def _try_urlhaus_host(host: str) -> dict | None:
    """URLhaus host lookup: has this host served malicious payloads? No key."""
    try:
        resp = httpx.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, timeout=8)
        if resp.status_code == 200:
            j = resp.json()
            if j.get("query_status") == "ok" and j.get("host"):
                urls = j.get("urls") or []
                return {
                    "urlhaus_listed": True,
                    "url_count": j.get("url_count", len(urls)),
                    "latest_urls": [
                        {"url": u.get("url"), "status": u.get("url_status"), "tag": u.get("tags", [""])[0] if u.get("tags") else None}
                        for u in urls[:3]
                    ],
                }
            if j.get("query_status") == "no_results":
                return {"urlhaus_listed": False}
    except Exception:
        pass
    return None


def _try_malwarebazaar_hash(sha256: str) -> dict | None:
    """MalwareBazaar hash lookup (abuse.ch API v1, get_info)."""
    headers = {"Auth-Key": _get_env_key("MALWAREBAZAAR_KEY")} if _get_env_key("MALWAREBAZAAR_KEY") else {}
    try:
        resp = httpx.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": sha256}, headers=headers, timeout=10)
        if resp.status_code == 200:
            j = resp.json()
            if j.get("query_status") == "ok" and j.get("data"):
                sample = j["data"][0]
                intel = sample.get("intelligence", {}) or {}
                downloads = sample.get("file_data", {}) or {}
                return {
                    "mb_listed": True,
                    "signature": sample.get("signature"),
                    "file_type": sample.get("file_type"),
                    "file_name": sample.get("file_name"),
                    "imphash": sample.get("imphash"),
                    "delivery_method": sample.get("delivery_method"),
                    "tags": (sample.get("tags") or [])[:4],
                    "reporter": sample.get("reporter"),
                    "first_seen": sample.get("first_seen"),
                    "intel_clamav": (intel.get("clamav") or [None])[0],
                    "downloads": downloads.get("downloads", 0) if isinstance(downloads, dict) else 0,
                }
            if j.get("query_status") in ("hash_not_found", "no_hash_provided"):
                return {"mb_listed": False}
    except Exception:
        pass
    return None


def _try_phishtank(host_value: str, is_url: bool) -> dict | None:
    """PhishTank URL check (free key, phishtank.org)."""
    key = _get_env_key("PHISHTANK_KEY")
    if not key:
        return None
    try:
        resp = httpx.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": host_value, "format": "json", "request_key": key},
            timeout=10,
        )
        if resp.status_code == 200:
            j = resp.json()
            results = j.get("results", {})
            entry = results.get("url")
            if entry:
                listed = entry.get("in_database")
                return {
                    "phishtank_listed": bool(listed),
                    "verified": entry.get("verified"),
                    "valid": entry.get("valid"),
                    "phish_detail": entry.get("phish_detail_page") if listed else None,
                }
    except Exception:
        pass
    return None

COUNTRY_POOL = ["RU", "CN", "US", "BR", "IN", "NL", "DE", "UA", "VN", "IR", "RO", "GB", "FR", "TR", "ID", "KR"]
ASN_POOL = [
    ("AS14061", "DigitalOcean, LLC"), ("AS9009", "M247 Europe SRL"),
    ("AS16509", "Amazon.com, Inc."), ("AS45102", "Alibaba Cloud"),
    ("AS49981", "WorldStream B.V."), ("AS208323", "Comfortel Ltd."),
]
FAMILIES = ["Emotet", "Qakbot", "Dridex", "AsyncRAT", "Cobalt Strike", "IcedID", "AgentTesla"]
VERDICT_POOL = [(58, 2), (44, 0), (67, 4), (39, 1), (72, 6), (31, 0)]


def _stable_bucket(value: str, mod: int) -> int:
    return int(hashlib.sha256(value.encode()).hexdigest(), 16) % mod


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _get_cached(db: Session, indicator: Indicator, kind: str, provider: str) -> Enrichment | None:
    row = (
        db.execute(
            select(Enrichment).where(
                Enrichment.indicator_id == indicator.id,
                Enrichment.kind == kind,
                Enrichment.provider == provider,
            )
        )
        .scalars()
        .first()
    )
    if row and row.expires_at and aware(row.expires_at) > _now():
        return row
    return None


def _store(db: Session, indicator: Indicator, kind: str, provider: str, data: dict) -> Enrichment:
    row = (
        db.execute(
            select(Enrichment).where(
                Enrichment.indicator_id == indicator.id,
                Enrichment.kind == kind,
                Enrichment.provider == provider,
            )
        )
        .scalars()
        .first()
    )
    expires = _now() + timedelta(minutes=CACHE_TTL_MINUTES)
    if row:
        row.data = data
        row.fetched_at = _now()
        row.expires_at = expires
    else:
        row = Enrichment(indicator_id=indicator.id, kind=kind, provider=provider, data=data, expires_at=expires)
        db.add(row)
        db.flush()
    return row


def _try_http_json(url: str, timeout: float = 4.0):
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def enrich_reputation_ip(db: Session, indicator: Indicator) -> dict:
    cached = _get_cached(db, indicator, "reputation", "ip_reputation")
    if cached:
        return cached.data
    # real AbuseIPDB API when key is configured
    real = _try_abuseipdb(indicator.value) if indicator.type == "ip" else None
    if real:
        abuse_conf = real["abuse_confidence_score"]
        reports = real["total_reports"]
        data = {**real, "verdict": real["verdict"], "last_reported": real.get("last_reported", "")}
        _store(db, indicator, "reputation", "ip_reputation", data)
        return data
    bucket = _stable_bucket(indicator.value, 100)
    abuse_conf = max(10, min(100, bucket + 15))
    reports = 3 + _stable_bucket(indicator.value, 300)
    data = {
        "abuse_confidence_score": abuse_conf,
        "total_reports": reports,
        "distinct_reporters": max(1, reports // 4),
        "verdict": "malicious" if abuse_conf >= 50 else ("suspicious" if abuse_conf >= 25 else "benign"),
        "last_reported": (indicator.last_seen.isoformat() if indicator.last_seen else None),
    }
    _store(db, indicator, "reputation", "ip_reputation", data)
    return data


def enrich_geo(db: Session, indicator: Indicator) -> dict:
    if indicator.type not in ("ip", "domain", "url"):
        return {}
    cached = _get_cached(db, indicator, "geo", "geo_asn")
    if cached:
        return cached.data
    host = indicator.value
    if indicator.type in ("domain", "url"):
        host = indicator.value.split("://", 1)[-1].split("/", 1)[0]
    # real ip-api.com geolocation for IP indicators (free, no key)
    if indicator.type == "ip":
        real = _try_ipapi_geo(indicator.value)
        if real:
            data = real
            _store(db, indicator, "geo", "geo_asn", data)
            return data
    country = COUNTRY_POOL[_stable_bucket(host, len(COUNTRY_POOL))]
    asn_id, asn_name = ASN_POOL[_stable_bucket(host + "|asn", len(ASN_POOL))]
    data = {
        "country": country,
        "asn": asn_id,
        "asn_owner": asn_name,
        "latitude": round(-60 + _stable_bucket(host + "|lat", 150), 4),
        "longitude": round(-120 + _stable_bucket(host + "|lon", 240), 4),
    }
    _store(db, indicator, "geo", "geo_asn", data)
    return data


def enrich_verdicts(db: Session, indicator: Indicator) -> dict:
    if indicator.type not in ("hash_md5", "hash_sha1", "hash_sha256", "domain", "url"):
        return {}
    cached = _get_cached(db, indicator, "verdicts", "detection_engines")
    if cached:
        return cached.data
    # real VirusTotal API for hash indicators
    if indicator.type in ("hash_sha256", "hash_sha1", "hash_md5"):
        real = _try_virustotal_hash(indicator.value)
        if real:
            data = real
            _store(db, indicator, "verdicts", "detection_engines", data)
            return data
    malicious = VERDICT_POOL[_stable_bucket(indicator.value, len(VERDICT_POOL))][0]
    suspicious = _stable_bucket(indicator.value + "|s", 5)
    total = 72
    data = {
        "engine_total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": total - malicious - suspicious,
        "ratio": round(malicious / total, 2),
        "families": [FAMILIES[_stable_bucket(indicator.value, len(FAMILIES))]] if malicious > 20 else [],
    }
    _store(db, indicator, "verdicts", "detection_engines", data)
    return data


def enrich_domain_analysis(db: Session, indicator: Indicator) -> dict:
    if indicator.type not in ("domain", "url", "ip"):
        return {}
    cached = _get_cached(db, indicator, "scan_context", "domain_analysis")
    if cached:
        return cached.data
    bucket = _stable_bucket(indicator.value, 100)
    # real VirusTotal domain analysis when key is configured
    if indicator.type in ("domain", "url"):
        host = indicator.value.split("://", 1)[-1].split("/", 1)[0] if indicator.type == "url" else indicator.value
        real = _try_virustotal_domain(host)
        if real:
            data = real
            _store(db, indicator, "scan_context", "domain_analysis", data)
            return data
    newly_registered = bucket % 7 == 0
    phishing = indicator.malware_family in ("PhishKit",) or bucket % 9 == 0
    data = {
        "newly_registered": newly_registered,
        "known_phishing": phishing,
        "dga_like": bucket % 11 == 0,
        "registrar_age_days": 3 + _stable_bucket(indicator.value + "|age", 3000),
        "resolves": True,
    }
    _store(db, indicator, "scan_context", "domain_analysis", data)
    return data


def enrich_cve_kev(db: Session, indicator: Indicator) -> dict:
    """CVE indicators are checked against the CISA KEV catalog (real, no key)."""
    if indicator.type != "cve":
        return {}
    cached = _get_cached(db, indicator, "reputation", "cisa_kev")
    if cached:
        return cached.data
    data: dict = {"kev_listed": False, "known_exploited": False}
    payload = _try_http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if payload and isinstance(payload.get("vulnerabilities"), list):
        match = next((v for v in payload["vulnerabilities"] if v.get("cveID", "").upper() == indicator.value.upper()), None)
        if match:
            data = {
                "kev_listed": True,
                "known_exploited": True,
                "kev_date_added": match.get("dateAdded"),
                "kev_description": (match.get("shortDescription") or "")[:400],
            }
    else:
        bucket = _stable_bucket(indicator.value, 10)
        data = {"kev_listed": bucket >= 6, "known_exploited": bucket >= 6}
    _store(db, indicator, "reputation", "cisa_kev", data)
    return data


def enrich_noise_context(db: Session, indicator: Indicator) -> dict:
    """GreyNoise community context for IP indicators — is this host just
    internet-wide scanning noise or a targeted actor?"""
    if indicator.type != "ip":
        return {}
    cached = _get_cached(db, indicator, "reputation", "greynoise")
    if cached:
        return cached.data
    data = _try_greynoise(indicator.value) or {}
    if data:
        _store(db, indicator, "reputation", "greynoise", data)
    return data


def enrich_exposure(db: Session, indicator: Indicator) -> dict:
    """Shodan host/exposure lookup for IP indicators (open ports, org, ASN)."""
    if indicator.type != "ip":
        return {}
    cached = _get_cached(db, indicator, "scan_context", "shodan")
    if cached:
        return cached.data
    data = _try_shodan(indicator.value) or {}
    if data:
        _store(db, indicator, "scan_context", "shodan", data)
    return data


def enrich_otx_context(db: Session, indicator: Indicator) -> dict:
    """AlienVault OTX pulse context — works for every IOC type."""
    if indicator.type not in OTX_SECTIONS:
        return {}
    cached = _get_cached(db, indicator, "reputation", "otx")
    if cached:
        return cached.data
    data = _try_otx(indicator) or {}
    if data:
        _store(db, indicator, "reputation", "otx", data)
    return data


def enrich_sample_lookup(db: Session, indicator: Indicator) -> dict:
    """MalwareBazaar sample lookup for hash indicators."""
    if indicator.type not in ("hash_md5", "hash_sha1", "hash_sha256"):
        return {}
    cached = _get_cached(db, indicator, "verdicts", "malwarebazaar")
    if cached:
        return cached.data
    data = _try_malwarebazaar_hash(indicator.value) or {}
    if data:
        _store(db, indicator, "verdicts", "malwarebazaar", data)
    return data


def enrich_urlhaus_context(db: Session, indicator: Indicator) -> dict:
    """URLhaus host lookup for domain/URL indicators — payload-serving history."""
    if indicator.type not in ("domain", "url"):
        return {}
    cached = _get_cached(db, indicator, "scan_context", "urlhaus")
    if cached:
        return cached.data
    host = indicator.value.split("://", 1)[-1].split("/", 1)[0]
    data = _try_urlhaus_host(host) or {}
    if data:
        _store(db, indicator, "scan_context", "urlhaus", data)
    return data


def enrich_phishtank_context(db: Session, indicator: Indicator) -> dict:
    """PhishTank lookup for domain/URL indicators (free key)."""
    if indicator.type not in ("domain", "url"):
        return {}
    cached = _get_cached(db, indicator, "scan_context", "phishtank")
    if cached:
        return cached.data
    data = _try_phishtank(indicator.value, indicator.type == "url") or {}
    if data:
        _store(db, indicator, "scan_context", "phishtank", data)
    return data


def cached_enrichment(db: Session, indicator: Indicator) -> dict:
    """Serve previously stored enrichment rows without re-calling providers.
    Used by the indicator detail endpoint so the drawer shows provider context
    without triggering network traffic; Enrich refreshes through full_enrichment."""
    rows = (
        db.execute(select(Enrichment).where(Enrichment.indicator_id == indicator.id))
        .scalars()
        .all()
    )
    out: dict = {}
    for row in rows:
        key = PROVIDER_KEYS.get((row.kind, row.provider))
        if key and isinstance(row.data, dict):
            out[key] = row.data
    return out


def full_enrichment(db: Session, indicator: Indicator) -> dict:
    result: dict = {}
    if indicator.type == "ip":
        result["reputation"] = enrich_reputation_ip(db, indicator)
        noise = enrich_noise_context(db, indicator)
        if noise:
            result["noise"] = noise
        exposure = enrich_exposure(db, indicator)
        if exposure:
            result["exposure"] = exposure
    if indicator.type == "cve":
        result["kev"] = enrich_cve_kev(db, indicator)
    otx = enrich_otx_context(db, indicator)
    if otx:
        result["otx"] = otx
    geo = enrich_geo(db, indicator)
    if geo:
        result["geo"] = geo
    verdicts = enrich_verdicts(db, indicator)
    if verdicts:
        result["verdicts"] = verdicts
    sample = enrich_sample_lookup(db, indicator)
    if sample:
        result["sample"] = sample
    domain = enrich_domain_analysis(db, indicator)
    if domain:
        result["domain_analysis"] = domain
    urlhaus_ctx = enrich_urlhaus_context(db, indicator)
    if urlhaus_ctx:
        result["urlhaus"] = urlhaus_ctx
    phish = enrich_phishtank_context(db, indicator)
    if phish:
        result["phishtank"] = phish
    result["scoring"] = {
        "severity_score": indicator.severity_score,
        "severity": severity_for_score(indicator.severity_score),
        "confidence": indicator.confidence,
        "internal_sightings": indicator.internal_sightings,
    }
    return result
