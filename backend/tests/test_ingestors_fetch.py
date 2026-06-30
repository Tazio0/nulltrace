from unittest.mock import patch, MagicMock
import pytest
from backend.app.core.ingestors import (
    AbuseIPIngestor,
    AlienVaultIngestor,
    URLhausIngestor,
    PhishTankIngestor,
    BlocklistDeIngestor
)

@patch("backend.app.core.ingestors.requests.get")
def test_abuseipdb_fetch(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": [{"ipAddress": "1.2.3.4"}]}
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    ingestor = AbuseIPIngestor(api_key="TEST_API_KEY")
    result = ingestor.fetch()

    mock_get.assert_called_once_with(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={
            "Key": "TEST_API_KEY",
            "Accept": "application/json"
        }
    )
    assert result == {"data": [{"ipAddress": "1.2.3.4"}]}


@patch("backend.app.core.ingestors.requests.get")
def test_alienvault_fetch(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"results": []}
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    ingestor = AlienVaultIngestor(api_key="TEST_OTX_KEY")
    result = ingestor.fetch()

    mock_get.assert_called_once_with(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={
            "X-OTX-API-KEY": "TEST_OTX_KEY"
        }
    )
    assert result == {"results": []}


@patch("backend.app.core.ingestors.requests.get")
def test_urlhaus_fetch(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"urls": []}
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    ingestor = URLhausIngestor()
    result = ingestor.fetch()

    mock_get.assert_called_once_with("https://urlhaus.abuse.ch/downloads/json_recent/")
    assert result == {"urls": []}


@patch("backend.app.core.ingestors.requests.get")
def test_phishtank_fetch(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = []
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    ingestor = PhishTankIngestor()
    result = ingestor.fetch()

    mock_get.assert_called_once()
    headers = mock_get.call_args[1].get("headers", {})
    assert "User-Agent" in headers
    assert "threatwatch" in headers["User-Agent"].lower()
    assert result == []


@patch("backend.app.core.ingestors.requests.get")
def test_blocklistde_fetch(mock_get):
    mock_response = MagicMock()
    mock_response.text = "1.2.3.4\n5.6.7.8\n"
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    ingestor = BlocklistDeIngestor()
    result = ingestor.fetch()

    mock_get.assert_called_once_with("https://lists.blocklist.de/lists/all.txt")
    assert result == "1.2.3.4\n5.6.7.8\n"
