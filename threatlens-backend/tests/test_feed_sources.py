"""Feed source and enrichment provider tests.

The parsers are exercised offline with representative sample payloads so
pipeline behaviour is verified without network access. Provider functions
are checked for their no-key behaviour (deterministic fallback, no calls).
"""
from types import SimpleNamespace

from app.feeds.adapters import (ADAPTERS, _parse_malwarebazaar_csv,
                                _parse_spamhaus_drop, run_adapter)

MALWAREBAZAAR_CSV = """# header
# first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_mime, file_size, file_type, signature, imphash, ssdeep, tlsh
# update at 2026-09-28 12:00:00 UTC
# MalwareBazaar - abuse.ch
2026-09-28 11:30:00, 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, abcdef, abc, analyst1, invoice-loader.exe, application/x-dosexec, 245760, PE32, Qakbot, , , ,
2026-09-27 09:15:00, fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210, def, def, analyst2, payload.bin, application/octet-stream, 10240, , , , , ,
"""

SPAMHAUS_DROP = """; DROP/EDROP lists, see http://www.spamhaus.org/drop/
; (C) The Spamhaus Project
1.4.102.0/24 ; SBL368657 ; included on the SBL as part of the netblock
5.188.206.0/24 ; SBL99063
"""


def test_malwarebazaar_csv_parsed():
    records = _parse_malwarebazaar_csv(MALWAREBAZAAR_CSV)
    assert len(records) == 2
    first = records[0]
    assert first["type"] == "hash_sha256"
    assert first["value"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert first["malware_family"] == "Qakbot"
    assert "malwarebazaar" in first["tags"]
    assert first["seen_at"] is not None


def test_malwarebazaar_csv_headerless_fallback():
    body = "\n".join(MALWAREBAZAAR_CSV.splitlines()[3:])
    records = _parse_malwarebazaar_csv(body)
    assert records and records[0]["type"] == "hash_sha256"


def test_spamhaus_drop_parsed():
    records = _parse_spamhaus_drop(SPAMHAUS_DROP)
    assert [r["value"] for r in records] == ["1.4.102.0", "5.188.206.0"]
    assert all(r["type"] == "ip" for r in records)
    assert records[0]["tags"][0] == "spamhaus"
    assert "sbl368657" in records[0]["tags"]


def test_all_prd_sources_have_adapters():
    registered = set(ADAPTERS)
    expected = {"urlhaus", "malwarebazaar", "feodo", "threatfox",
                "spamhaus_drop", "cisa_kev", "otx", "taxii21", "reference"}
    assert expected <= registered


def test_run_adapter_unknown_slug():
    records, error = run_adapter("nonexistent", None)
    assert records == []
    assert "no adapter" in error


def test_enrichment_providers_inactive_without_keys(monkeypatch):
    """Without env keys the provider helpers must short-circuit (no network)."""
    from app.services import enrichment

    for name in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "OTX_KEY", "SHODAN_KEY",
                 "GREYNOISE_KEY", "PHISHTANK_KEY", "MALWAREBAZAAR_KEY"):
        monkeypatch.delenv(name, raising=False)

    assert enrichment._try_abuseipdb("1.2.3.4") is None
    assert enrichment._try_virustotal_hash("44d88612fea8a8f36de82e1278abb02f") is None
    assert enrichment._try_virustotal_domain("example.com") is None
    assert enrichment._try_otx(SimpleNamespace(value="1.2.3.4", type="ip")) is None
    assert enrichment._try_shodan("1.2.3.4") is None
    assert enrichment._try_greynoise("1.2.3.4") is None
    assert enrichment._try_malwarebazaar_hash("0" * 64) is None
    assert enrichment._try_phishtank("example.com", False) is None


def test_offline_fallbacks_still_enrich(monkeypatch):
    """Enrichers keep producing data without network or keys (deterministic fallback)."""
    from app.db import SessionLocal
    from app.services import enrichment
    from app.services.enrichment import full_enrichment
    from app.services.ingest import ingest_indicator

    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_KEY", raising=False)
    monkeypatch.setattr(enrichment, "_try_ipapi_geo", lambda ip: None)
    monkeypatch.setattr(enrichment, "_try_abuseipdb", lambda ip: None)
    monkeypatch.setattr(enrichment, "_try_otx", lambda ind: None)
    monkeypatch.setattr(enrichment, "_try_greynoise", lambda ip: None)
    monkeypatch.setattr(enrichment, "_try_shodan", lambda ip: None)

    db = SessionLocal()
    try:
        ind = ingest_indicator(db, value="203.0.113.250", source_name="unit test",
                               source_confidence=50, tlp="amber")
        db.commit()
        data = full_enrichment(db, ind)
        assert data["reputation"]["abuse_confidence_score"] > 0
        assert data["geo"]["country"]
        assert data["scoring"]["severity_score"] == ind.severity_score
    finally:
        db.rollback()
        db.close()
