"""Tests SpiderwebHoneypot configuration, socket handling, and alert formatting."""

import pytest
from unittest.mock import patch, MagicMock, call

from backend.app.core.deception import SpiderwebHoneypot

class TestSpiderwebHoneypotInit:

    def test_default_initialization(self):
        honeypot = SpiderwebHoneypot(port=2222)
        assert honeypot.port == 2222

    def test_default_host_is_all_interfaces(self):
        honeypot = SpiderwebHoneypot(port=2222)
        assert honeypot.host == "0.0.0.0"

    def test_custom_host(self):
        honeypot = SpiderwebHoneypot(port=2222, host="127.0.0.1")
        assert honeypot.host == "127.0.0.1"

    def test_has_service_name(self):
        honeypot = SpiderwebHoneypot(port=22)
        assert hasattr(honeypot, "service_name")
        assert isinstance(honeypot.service_name, str)
        assert len(honeypot.service_name) > 0

    def test_custom_service_name(self):
        honeypot = SpiderwebHoneypot(port=23, service_name="Telnet")
        assert honeypot.service_name == "Telnet"


class TestStartListening:

    @patch("backend.app.core.deception.socket")
    def test_creates_tcp_socket(self, mock_socket_module):
        mock_server = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1

        mock_server.accept.side_effect = OSError("Mocked shutdown")

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_socket_module.socket.assert_called_once_with(
            mock_socket_module.AF_INET,
            mock_socket_module.SOCK_STREAM,
        )

    @patch("backend.app.core.deception.socket")
    def test_binds_to_configured_host_and_port(self, mock_socket_module):
        mock_server = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1
        mock_server.accept.side_effect = OSError("Mocked shutdown")

        honeypot = SpiderwebHoneypot(port=9999, host="127.0.0.1")
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_server.bind.assert_called_once_with(("127.0.0.1", 9999))

    @patch("backend.app.core.deception.socket")
    def test_calls_listen(self, mock_socket_module):
        mock_server = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1
        mock_server.accept.side_effect = OSError("Mocked shutdown")

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_server.listen.assert_called_once()

class TestConnectionHandling:

    @patch("backend.app.core.deception.socket")
    def test_extracts_attacker_ip_from_connection(self, mock_socket_module):
        mock_server = MagicMock()
        mock_conn = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1

        mock_server.accept.side_effect = [
            (mock_conn, ("45.33.32.156", 54321)),
            OSError("Mocked shutdown"),
        ]

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        assert mock_conn.close.called or mock_conn.recv.called

    @patch("backend.app.core.deception.socket")
    def test_closes_client_connection_after_handling(self, mock_socket_module):
        mock_server = MagicMock()
        mock_conn = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1

        mock_server.accept.side_effect = [
            (mock_conn, ("185.220.101.1", 12345)),
            OSError("Mocked shutdown"),
        ]

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_conn.close.assert_called()

class TestFormatAlert:

    def test_format_alert_returns_dict(self):
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="192.168.1.100", port=2222)
        assert isinstance(alert, dict)

    def test_format_alert_contains_required_keys(self):
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="10.0.0.5", port=2222)

        required_keys = {"attacker_ip", "port", "service_name", "timestamp"}
        for key in required_keys:
            assert key in alert, f"format_alert() missing required key: '{key}'"

    def test_format_alert_attacker_ip_matches_input(self):
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="203.0.113.50", port=2222)
        assert alert["attacker_ip"] == "203.0.113.50"

    def test_format_alert_port_matches_input(self):
        honeypot = SpiderwebHoneypot(port=8080)
        alert = honeypot.format_alert(attacker_ip="1.2.3.4", port=8080)
        assert alert["port"] == 8080

    def test_format_alert_includes_service_name(self):
        honeypot = SpiderwebHoneypot(port=22, service_name="SSH")
        alert = honeypot.format_alert(attacker_ip="1.2.3.4", port=22)
        assert alert["service_name"] == "SSH"

    def test_format_alert_timestamp_is_string(self):
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="1.2.3.4", port=2222)
        assert isinstance(alert["timestamp"], str)
        assert len(alert["timestamp"]) > 0

    def test_format_alert_with_credentials(self):
        honeypot = SpiderwebHoneypot(port=22)
        alert = honeypot.format_alert(
            attacker_ip="1.2.3.4",
            port=22,
            username="root",
            password="toor",
        )
        assert alert.get("username") == "root"
        assert alert.get("password") == "toor"
