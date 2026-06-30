"""Tests ingestor interfaces, feed initialization, parsing, auth patterns, and edge cases."""

import pytest
from unittest.mock import MagicMock, patch

from backend.app.core.ingestors import (
    BaseIngestor,
    AbuseIPIngestor,
    AlienVaultIngestor,
    URLhausIngestor,
    PhishTankIngestor,
    BlocklistDeIngestor,
)

EXPECTED_FIELDS = {"indicator", "type", "source", "severity", "country"}


def assert_valid_threat_list(result):
    assert isinstance(result, list), "parse() must return a list"
    assert len(result) > 0, "parse() must return at least one item"
    for item in result:
        assert isinstance(item, dict), "Each threat must be a dict"
        for field in EXPECTED_FIELDS:
            assert field in item, f"Missing required field: '{field}'"

class TestBaseIngestor:

    def test_base_ingestor_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            BaseIngestor(api_key="test")

    def test_base_ingestor_enforces_parse_method(self):
        class IncompleteIngestor(BaseIngestor):
            pass

        with pytest.raises(TypeError):
            IncompleteIngestor(api_key="key")

    def test_base_ingestor_enforces_fetch_method(self):
        class IncompleteIngestor(BaseIngestor):
            def parse(self, raw_data):
                return []

        with pytest.raises(TypeError):
            IncompleteIngestor(api_key="key")

    def test_concrete_subclass_is_valid_without_instantiation_error(self):
        class FullIngestor(BaseIngestor):
            def fetch(self):
                return {}

            def parse(self, raw_data):
                return []

        ingestor = FullIngestor(feed_name="Mock", base_url="http://mock.com",api_key="key")
        assert ingestor is not None

class TestAbuseIPIngestor:

    def test_initialization(self):
        ingestor = AbuseIPIngestor(api_key="SECRET_KEY")
        assert ingestor.api_key == "SECRET_KEY"
        assert ingestor.feed_name == "AbuseIPDB"
        assert "abuseipdb.com" in ingestor.base_url

    def test_requires_api_key(self):
        with pytest.raises(TypeError):
            AbuseIPIngestor()

    def test_parse_returns_normalized_list(self):
        ingestor = AbuseIPIngestor(api_key="SECRET_KEY")

        raw = {
            "data": [
                {
                    "ipAddress": "192.168.1.1",
                    "abuseConfidenceScore": 90,
                    "countryCode": "ZA",
                    "totalReports": 15,
                }
            ]
        }

        result = ingestor.parse(raw)
        assert_valid_threat_list(result)
        assert result[0]["indicator"] == "192.168.1.1"
        assert result[0]["type"] == "ip"
        assert result[0]["source"] == "AbuseIPDB"
        assert result[0]["country"] == "ZA"

    def test_parse_empty_data_returns_empty_list(self):
        ingestor = AbuseIPIngestor(api_key="SECRET_KEY")
        result = ingestor.parse({"data": []})
        assert result == []

    def test_parse_missing_country_code_does_not_crash(self):
        ingestor = AbuseIPIngestor(api_key="SECRET_KEY")

        raw = {
            "data": [
                {
                    "ipAddress": "10.0.0.1",
                    "abuseConfidenceScore": 75,
                    "totalReports": 5,
                }
            ]
        }

        result = ingestor.parse(raw)
        assert isinstance(result, list)
        assert result[0]["country"] is None or isinstance(result[0]["country"], str)

    def test_fetch_does_not_hit_real_network(self):
        ingestor = AbuseIPIngestor(api_key="SECRET_KEY")

        with patch.object(ingestor, "fetch", return_value={"data": []}) as mock_fetch:
            result = ingestor.fetch()
            mock_fetch.assert_called_once()
            assert result == {"data": []}

class TestAlienVaultIngestor:

    def test_initialization(self):
        ingestor = AlienVaultIngestor(api_key="OTX_KEY")
        assert ingestor.api_key == "OTX_KEY"
        assert ingestor.feed_name == "AlienVault OTX"
        assert "otx.alienvault.com" in ingestor.base_url

    def test_requires_api_key(self):
        with pytest.raises(TypeError):
            AlienVaultIngestor()

    def test_parse_returns_normalized_list(self):
        ingestor = AlienVaultIngestor(api_key="OTX_KEY")

        raw = {
            "results": [
                {
                    "indicators": [
                        {
                            "indicator": "malicious-domain.com",
                            "type": "domain",
                            "country": "RU",
                        }
                    ]
                }
            ]
        }

        result = ingestor.parse(raw)
        assert_valid_threat_list(result)
        assert result[0]["indicator"] == "malicious-domain.com"
        assert result[0]["type"] == "domain"
        assert result[0]["source"] == "AlienVault OTX"

    def test_parse_empty_results_returns_empty_list(self):
        ingestor = AlienVaultIngestor(api_key="OTX_KEY")
        result = ingestor.parse({"results": []})
        assert result == []

    def test_parse_pulse_with_no_indicators_returns_empty_list(self):
        ingestor = AlienVaultIngestor(api_key="OTX_KEY")
        raw = {"results": [{"indicators": []}]}
        result = ingestor.parse(raw)
        assert result == []

    def test_parse_normalises_otx_type_strings(self):
        ingestor = AlienVaultIngestor(api_key="OTX_KEY")

        otx_types = [
            ("IPv4", "ip"),
            ("IPv6", "ip"),
            ("URL", "url"),
            ("domain", "domain"),
            ("hostname", "domain"),
            ("FQDN", "domain"),
        ]

        for raw_type, expected_type in otx_types:
            raw = {
                "results": [
                    {
                        "indicators": [
                            {
                                "indicator": "test-indicator",
                                "type": raw_type,
                            }
                        ]
                    }
                ]
            }
            result = ingestor.parse(raw)
            assert result[0]["type"] == expected_type, (
                f"OTX type '{raw_type}' should normalise to '{expected_type}', "
                f"got '{result[0]['type']}'"
            )

class TestURLhausIngestor:

    def test_initialization(self):
        ingestor = URLhausIngestor()
        assert ingestor.api_key is None
        assert ingestor.feed_name == "URLhaus"
        assert "urlhaus" in ingestor.base_url

    def test_parse_returns_normalized_list(self):
        ingestor = URLhausIngestor()

        raw = {
            "urls": [
                {
                    "url": "http://evil.example.com/payload",
                    "url_status": "online",
                    "country": "CN",
                    "threat": "malware_download",
                }
            ]
        }

        result = ingestor.parse(raw)
        assert_valid_threat_list(result)
        assert result[0]["indicator"] == "http://evil.example.com/payload"
        assert result[0]["type"] == "url"
        assert result[0]["source"] == "URLhaus"

    def test_parse_filters_offline_urls(self):
        ingestor = URLhausIngestor()

        raw = {
            "urls": [
                {
                    "url": "http://dead.example.com/old",
                    "url_status": "offline",
                    "country": "US",
                    "threat": "malware_download",
                }
            ]
        }

        result = ingestor.parse(raw)
        assert result == []

    def test_parse_empty_urls_returns_empty_list(self):
        ingestor = URLhausIngestor()
        result = ingestor.parse({"urls": []})
        assert result == []

class TestPhishTankIngestor:

    def test_initialization(self):
        ingestor = PhishTankIngestor()
        assert ingestor.api_key is None
        assert ingestor.feed_name == "PhishTank"

    def test_parse_returns_normalized_list(self):
        ingestor = PhishTankIngestor()

        raw = [
            {
                "url": "http://phish.example.com/login",
                "verified": "yes",
                "country": "NG",
            }
        ]

        result = ingestor.parse(raw)
        assert_valid_threat_list(result)
        assert result[0]["indicator"] == "http://phish.example.com/login"
        assert result[0]["type"] == "url"
        assert result[0]["source"] == "PhishTank"

    def test_parse_excludes_unverified_entries(self):
        ingestor = PhishTankIngestor()

        raw = [
            {
                "url": "http://suspicious.example.com",
                "verified": "no",
                "country": "US",
            }
        ]

        result = ingestor.parse(raw)
        assert result == []

    def test_parse_empty_list_returns_empty_list(self):
        ingestor = PhishTankIngestor()
        result = ingestor.parse([])
        assert result == []

class TestBlocklistDeIngestor:

    def test_initialization(self):
        ingestor = BlocklistDeIngestor()
        assert ingestor.api_key is None
        assert ingestor.feed_name == "Blocklist.de"
        assert "blocklist.de" in ingestor.base_url

    def test_parse_returns_normalized_list(self):
        ingestor = BlocklistDeIngestor()

        raw = "185.220.101.1\n185.220.101.2\n185.220.101.3\n"

        result = ingestor.parse(raw)
        assert_valid_threat_list(result)
        assert result[0]["indicator"] == "185.220.101.1"
        assert result[0]["type"] == "ip"
        assert result[0]["source"] == "Blocklist.de"

    def test_parse_ignores_comment_lines(self):
        ingestor = BlocklistDeIngestor()

        raw = "# This is a comment\n185.220.101.1\n# Another comment\n185.220.101.2\n"

        result = ingestor.parse(raw)
        assert len(result) == 2
        for item in result:
            assert not item["indicator"].startswith("#")

    def test_parse_empty_string_returns_empty_list(self):
        ingestor = BlocklistDeIngestor()
        result = ingestor.parse("")
        assert result == []

    def test_parse_strips_whitespace_from_ips(self):
        ingestor = BlocklistDeIngestor()
        raw = "  185.220.101.1  \n  185.220.101.2  \n"
        result = ingestor.parse(raw)
        assert result[0]["indicator"] == "185.220.101.1"
        assert result[1]["indicator"] == "185.220.101.2"

class TestCrossFeedConsistency:

    def test_all_ingestors_share_common_interface(self):
        ingestors = [
            AbuseIPIngestor(api_key="k"),
            AlienVaultIngestor(api_key="k"),
            URLhausIngestor(),
            PhishTankIngestor(),
            BlocklistDeIngestor(),
        ]

        for ingestor in ingestors:
            assert hasattr(ingestor, "feed_name"), f"{type(ingestor).__name__} missing feed_name"
            assert hasattr(ingestor, "base_url"), f"{type(ingestor).__name__} missing base_url"
            assert hasattr(ingestor, "api_key"), f"{type(ingestor).__name__} missing api_key"
            assert hasattr(ingestor, "fetch"), f"{type(ingestor).__name__} missing fetch()"
            assert hasattr(ingestor, "parse"), f"{type(ingestor).__name__} missing parse()"

    def test_all_ingestors_are_subclasses_of_base(self):
        for cls in [AbuseIPIngestor, AlienVaultIngestor, URLhausIngestor,
                    PhishTankIngestor, BlocklistDeIngestor]:
            assert issubclass(cls, BaseIngestor), f"{cls.__name__} must extend BaseIngestor"

    def test_public_feeds_have_none_api_key(self):
        public_feeds = [URLhausIngestor(), PhishTankIngestor(), BlocklistDeIngestor()]
        for ingestor in public_feeds:
            assert ingestor.api_key is None, f"{ingestor.feed_name} should have api_key=None"

    def test_authenticated_feeds_store_api_key(self):
        authenticated_feeds = [
            AbuseIPIngestor(api_key="key_a"),
            AlienVaultIngestor(api_key="key_b"),
        ]
        assert authenticated_feeds[0].api_key == "key_a"
        assert authenticated_feeds[1].api_key == "key_b"
