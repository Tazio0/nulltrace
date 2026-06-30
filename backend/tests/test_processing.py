"""Tests severity scoring, threat enrichment, and threat deduplication."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.processing.scorer import SeverityScorer
from backend.app.processing.enricher import ThreatEnricher
from backend.app.processing.deduplicator import ThreatDeduplicator
from backend.app.database import Base
from backend.app.models import Threat

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _make_threat_dict(
    indicator="1.2.3.4",
    type_="ip",
    source="AbuseIPDB",
    severity="high",
    country="ZA",
):
    return {
        "indicator": indicator,
        "type": type_,
        "source": source,
        "severity": severity,
        "country": country,
    }


@pytest.fixture
def sqlite_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

class TestSeverityScorer:

    def test_abuseipdb_score_0_is_low(self):
        scorer = SeverityScorer()
        assert scorer.normalize(0, "AbuseIPDB") == "low"

    def test_abuseipdb_score_25_is_low(self):
        scorer = SeverityScorer()
        assert scorer.normalize(25, "AbuseIPDB") == "low"

    def test_abuseipdb_score_26_is_medium(self):
        scorer = SeverityScorer()
        assert scorer.normalize(26, "AbuseIPDB") == "medium"

    def test_abuseipdb_score_50_is_medium(self):
        scorer = SeverityScorer()
        assert scorer.normalize(50, "AbuseIPDB") == "medium"

    def test_abuseipdb_score_51_is_high(self):
        scorer = SeverityScorer()
        assert scorer.normalize(51, "AbuseIPDB") == "high"

    def test_abuseipdb_score_75_is_high(self):
        scorer = SeverityScorer()
        assert scorer.normalize(75, "AbuseIPDB") == "high"

    def test_abuseipdb_score_76_is_critical(self):
        scorer = SeverityScorer()
        assert scorer.normalize(76, "AbuseIPDB") == "critical"

    def test_abuseipdb_score_100_is_critical(self):
        scorer = SeverityScorer()
        assert scorer.normalize(100, "AbuseIPDB") == "critical"

    def test_urlhaus_malware_download(self):
        scorer = SeverityScorer()
        result = scorer.normalize("malware_download", "URLhaus")
        assert result in VALID_SEVERITIES, (
            f"Expected one of {VALID_SEVERITIES}, got '{result}'"
        )

    @pytest.mark.parametrize(
        ("raw_severity", "expected"),
        [
            ("malware_download", "critical"),
            ("phishing", "high"),
            ("unknown_threat", "medium"),
        ],
    )
    def test_urlhaus_categories_are_normalized(self, raw_severity, expected):
        scorer = SeverityScorer()
        assert scorer.normalize(raw_severity, "URLhaus") == expected

    @pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
    def test_alienvault_canonical_text_is_preserved(self, severity):
        scorer = SeverityScorer()
        assert scorer.normalize(severity.upper(), "AlienVault OTX") == severity

    def test_phishtank_default_is_high(self):
        scorer = SeverityScorer()
        assert scorer.normalize(None, "PhishTank") == "high"

    def test_blocklist_de_default_is_medium(self):
        scorer = SeverityScorer()
        assert scorer.normalize(None, "Blocklist.de") == "medium"

    def test_unknown_source_defaults_to_medium(self):
        scorer = SeverityScorer()
        assert scorer.normalize(None, "UnknownFeed") == "medium"

    def test_none_severity_does_not_crash(self):
        scorer = SeverityScorer()
        result = scorer.normalize(None, "AbuseIPDB")
        assert isinstance(result, str), "normalize() must return a string even for None input"

    def test_return_type_is_always_string(self):
        scorer = SeverityScorer()

        test_cases = [
            (0, "AbuseIPDB"),
            (100, "AbuseIPDB"),
            ("malware_download", "URLhaus"),
            (None, "PhishTank"),
            (None, "Blocklist.de"),
            (None, "UnknownFeed"),
            (42, "AbuseIPDB"),
        ]

        for raw, source in test_cases:
            result = scorer.normalize(raw, source)
            assert isinstance(result, str), (
                f"normalize({raw!r}, {source!r}) returned {type(result).__name__}, "
                f"expected str"
            )

class TestThreatEnricher:

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_adds_country_code(self, mock_geo):
        mock_geo.return_value = {"country_code": "US", "isp": "Cloudflare"}

        enricher = ThreatEnricher()
        threat = _make_threat_dict(indicator="8.8.8.8", type_="ip")
        result = enricher.enrich(threat)

        assert "country_code" in result, "Enriched dict must contain 'country_code'"
        assert result["country_code"] == "US"

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_adds_isp(self, mock_geo):
        mock_geo.return_value = {"country_code": "US", "isp": "Google LLC"}

        enricher = ThreatEnricher()
        threat = _make_threat_dict(indicator="8.8.4.4", type_="ip")
        result = enricher.enrich(threat)

        assert "isp" in result, "Enriched dict must contain 'isp'"
        assert result["isp"] == "Google LLC"

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_preserves_original_fields(self, mock_geo):
        mock_geo.return_value = {"country_code": "DE", "isp": "Hetzner"}

        enricher = ThreatEnricher()
        threat = _make_threat_dict()
        result = enricher.enrich(threat)

        for key in ("indicator", "type", "source", "severity", "country"):
            assert key in result, f"Original key '{key}' missing after enrichment"

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_url_indicator_handled_gracefully(self, mock_geo):
        mock_geo.return_value = {}

        enricher = ThreatEnricher()
        threat = _make_threat_dict(
            indicator="http://evil.example.com/payload",
            type_="url",
            source="URLhaus",
        )
        result = enricher.enrich(threat)
        assert isinstance(result, dict)

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_failed_lookup_returns_dict_unchanged(self, mock_geo):
        mock_geo.side_effect = Exception("Geo service unavailable")

        enricher = ThreatEnricher()
        original = _make_threat_dict()
        result = enricher.enrich(original)

        assert isinstance(result, dict), "enrich() must still return a dict on failure"
        assert result["indicator"] == original["indicator"]

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_returns_dict(self, mock_geo):
        mock_geo.return_value = {"country_code": "JP", "isp": "NTT"}

        enricher = ThreatEnricher()
        threat = _make_threat_dict()
        result = enricher.enrich(threat)

        assert isinstance(result, dict), (
            f"enrich() returned {type(result).__name__}, expected dict"
        )

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_domain_indicator_handled(self, mock_geo):
        mock_geo.return_value = {}

        enricher = ThreatEnricher()
        threat = _make_threat_dict(
            indicator="malware-c2.example.com",
            type_="domain",
            source="AlienVault OTX",
        )
        result = enricher.enrich(threat)
        assert isinstance(result, dict)

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_skips_geo_lookup_for_non_ip_indicators(self, mock_geo):
        enricher = ThreatEnricher()
        threat = _make_threat_dict(
            indicator="http://evil.example.com/payload",
            type_="url",
            source="URLhaus",
        )

        result = enricher.enrich(threat)

        mock_geo.assert_not_called()
        assert result == threat
        assert result is not threat

    @patch("backend.app.processing.enricher.geo_lookup")
    def test_enrich_does_not_mutate_original_threat(self, mock_geo):
        mock_geo.return_value = {"country_code": "US", "isp": "Google LLC"}
        enricher = ThreatEnricher()
        threat = _make_threat_dict(indicator="8.8.8.8", country=None)

        result = enricher.enrich(threat)

        assert result is not threat
        assert "country_code" not in threat
        assert result["country_code"] == "US"

class TestThreatDeduplicator:

    @staticmethod
    def _build_mock_session(threats=None):
        if threats is None:
            threats = []

        session = MagicMock()

        query_mock = MagicMock()
        session.query.return_value = query_mock
        query_mock.filter.return_value = query_mock

        query_mock.first.return_value = None

        return session, query_mock

    def test_new_indicator_is_not_duplicate(self):
        dedup = ThreatDeduplicator()
        session, query_mock = self._build_mock_session()
        query_mock.first.return_value = None

        result = dedup.is_duplicate("1.2.3.4", session)
        assert result is False

    def test_existing_indicator_today_is_duplicate(self):
        dedup = ThreatDeduplicator()
        session, query_mock = self._build_mock_session()

        existing = Threat(
            indicator="1.2.3.4",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        existing.created_at = datetime.now()
        query_mock.first.return_value = existing

        result = dedup.is_duplicate("1.2.3.4", session)
        assert result is True

    def test_existing_indicator_yesterday_is_not_duplicate(self):
        dedup = ThreatDeduplicator()
        session, query_mock = self._build_mock_session()

        query_mock.first.return_value = None

        result = dedup.is_duplicate("1.2.3.4", session)
        assert result is False

    def test_different_indicator_is_not_duplicate(self):
        dedup = ThreatDeduplicator()
        session, query_mock = self._build_mock_session()
        query_mock.first.return_value = None

        result = dedup.is_duplicate("5.6.7.8", session)
        assert result is False

    def test_case_insensitive_url_check(self):
        dedup = ThreatDeduplicator()
        session, query_mock = self._build_mock_session()

        existing = Threat(
            indicator="http://Evil.COM",
            type="url",
            source="URLhaus",
            severity="critical",
        )
        existing.created_at = datetime.now()
        query_mock.first.return_value = existing

        result = dedup.is_duplicate("http://evil.com", session)
        assert result is True

    def test_empty_database_returns_false(self):
        dedup = ThreatDeduplicator()
        session, query_mock = self._build_mock_session()
        query_mock.first.return_value = None

        result = dedup.is_duplicate("anything-at-all", session)
        assert result is False

    def test_real_session_detects_indicator_seen_today(self, sqlite_session):
        sqlite_session.add(
            Threat(
                indicator="198.51.100.10",
                type="ip",
                source="AbuseIPDB",
                severity="high",
                created_at=datetime.now(),
            )
        )
        sqlite_session.commit()

        dedup = ThreatDeduplicator()

        assert dedup.is_duplicate("198.51.100.10", sqlite_session) is True

    def test_real_session_allows_indicator_only_seen_before_today(self, sqlite_session):
        sqlite_session.add(
            Threat(
                indicator="203.0.113.77",
                type="ip",
                source="Blocklist.de",
                severity="medium",
                created_at=datetime.now() - timedelta(days=1),
            )
        )
        sqlite_session.commit()

        dedup = ThreatDeduplicator()

        assert dedup.is_duplicate("203.0.113.77", sqlite_session) is False

    def test_real_session_matches_url_case_insensitively(self, sqlite_session):
        sqlite_session.add(
            Threat(
                indicator="HTTP://EVIL.EXAMPLE/LOGIN",
                type="url",
                source="PhishTank",
                severity="high",
                created_at=datetime.now(),
            )
        )
        sqlite_session.commit()

        dedup = ThreatDeduplicator()

        assert dedup.is_duplicate("http://evil.example/login", sqlite_session) is True
