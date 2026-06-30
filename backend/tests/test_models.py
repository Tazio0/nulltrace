"""Tests SQLAlchemy ORM model construction, defaults, constraints, and persistence."""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from backend.app.models import Threat, HoneypotLog, FirewallRule

class TestThreat:

    def test_instantiation_with_required_fields(self):
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        assert threat.indicator == "192.168.1.1"
        assert threat.type == "ip"
        assert threat.source == "AbuseIPDB"
        assert threat.severity == "high"

    def test_country_field_assignment(self):
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
            country="ZA",
        )
        assert threat.country == "ZA"

    def test_country_defaults_to_none(self):
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
        )
        assert threat.country is None

    def test_timestamp_field_exists(self):
        threat = Threat(
            indicator="evil.example.com",
            type="domain",
            source="AlienVault OTX",
            severity="critical",
        )
        assert hasattr(threat, "created_at")

    def test_indicator_stores_domain(self):
        threat = Threat(
            indicator="malware-c2.example.com",
            type="domain",
            source="AlienVault OTX",
            severity="high",
        )
        assert threat.indicator == "malware-c2.example.com"
        assert threat.type == "domain"

    def test_indicator_stores_url(self):
        threat = Threat(
            indicator="http://evil.example.com/payload.exe",
            type="url",
            source="URLhaus",
            severity="critical",
        )
        assert threat.indicator == "http://evil.example.com/payload.exe"
        assert threat.type == "url"

    def test_severity_accepts_all_levels(self):
        for level in ("low", "medium", "high", "critical"):
            threat = Threat(
                indicator="1.2.3.4",
                type="ip",
                source="TestFeed",
                severity=level,
            )
            assert threat.severity == level

    def test_repr_or_str_contains_indicator(self):
        threat = Threat(
            indicator="203.0.113.50",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        text = repr(threat)
        assert "203.0.113.50" in text

class TestHoneypotLog:

    def test_instantiation_with_required_fields(self):
        log = HoneypotLog(
            attacker_ip="45.33.32.156",
            port=22,
        )
        assert log.attacker_ip == "45.33.32.156"
        assert log.port == 22

    def test_credentials_captured(self):
        log = HoneypotLog(
            attacker_ip="185.220.101.1",
            port=23,
            username="admin",
            password="password123",
        )
        assert log.username == "admin"
        assert log.password == "password123"

    def test_credentials_default_to_none(self):
        log = HoneypotLog(
            attacker_ip="185.220.101.1",
            port=22,
        )
        assert log.username is None
        assert log.password is None

    def test_timestamp_field_exists(self):
        log = HoneypotLog(
            attacker_ip="10.0.0.1",
            port=8080,
        )
        assert hasattr(log, "created_at")

    def test_protocol_field(self):
        log = HoneypotLog(
            attacker_ip="10.0.0.1",
            port=53,
            protocol="udp",
        )
        assert log.protocol == "udp"

    def test_protocol_defaults_to_tcp(self):
        log = HoneypotLog(
            attacker_ip="10.0.0.1",
            port=22,
        )
        assert log.protocol == "tcp"

    def test_repr_contains_attacker_ip(self):
        log = HoneypotLog(
            attacker_ip="203.0.113.99",
            port=22,
        )
        text = repr(log)
        assert "203.0.113.99" in text

class TestFirewallRule:

    def test_instantiation_with_required_fields(self):
        rule = FirewallRule(
            target_ip="185.220.101.1",
            rule_command="ufw deny from 185.220.101.1",
        )
        assert rule.target_ip == "185.220.101.1"
        assert rule.rule_command == "ufw deny from 185.220.101.1"

    def test_rule_type_field(self):
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="iptables -A INPUT -s 10.0.0.1 -j DROP",
            rule_type="iptables",
        )
        assert rule.rule_type == "iptables"

    def test_is_active_defaults_to_true(self):
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        assert rule.is_active is True

    def test_is_active_can_be_set_false(self):
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
            is_active=False,
        )
        assert rule.is_active is False

    def test_timestamp_field_exists(self):
        rule = FirewallRule(
            target_ip="1.2.3.4",
            rule_command="ufw deny from 1.2.3.4",
        )
        assert hasattr(rule, "created_at")

    def test_source_threat_reference(self):
        rule = FirewallRule(
            target_ip="45.33.32.156",
            rule_command="ufw deny from 45.33.32.156",
            source="AbuseIPDB",
        )
        assert rule.source == "AbuseIPDB"

    def test_repr_contains_target_ip(self):
        rule = FirewallRule(
            target_ip="203.0.113.10",
            rule_command="ufw deny from 203.0.113.10",
        )
        text = repr(rule)
        assert "203.0.113.10" in text

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.app.database import Base


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()

class TestThreatORM:

    def test_tablename_is_threats(self):
        assert Threat.__tablename__ == "threats"

    def test_threat_has_id_column(self):
        assert hasattr(Threat, "id")

    def test_can_add_threat_to_session(self, db_session):
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        db_session.flush()
        assert threat.id is not None

    def test_indicator_not_nullable(self, db_session):
        threat = Threat(
            indicator=None,
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_type_not_nullable(self, db_session):
        threat = Threat(
            indicator="192.168.1.1",
            type=None,
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_source_not_nullable(self, db_session):
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source=None,
            severity="high",
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_severity_not_nullable(self, db_session):
        threat = Threat(
            indicator="192.168.1.1",
            type="ip",
            source="AbuseIPDB",
            severity=None,
        )
        db_session.add(threat)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_country_nullable(self, db_session):
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
        )
        db_session.add(threat)
        db_session.flush()
        assert threat.country is None

    def test_created_at_auto_set(self, db_session):
        threat = Threat(
            indicator="10.0.0.1",
            type="ip",
            source="Blocklist.de",
            severity="medium",
        )
        db_session.add(threat)
        db_session.flush()
        assert threat.created_at is not None

    def test_repr_still_works_after_orm(self, db_session):
        threat = Threat(
            indicator="203.0.113.50",
            type="ip",
            source="AbuseIPDB",
            severity="high",
        )
        db_session.add(threat)
        db_session.flush()
        assert "203.0.113.50" in repr(threat)

class TestHoneypotLogORM:

    def test_tablename_is_honeypot_logs(self):
        assert HoneypotLog.__tablename__ == "honeypot_logs"

    def test_has_id_column(self):
        assert hasattr(HoneypotLog, "id")

    def test_can_add_to_session(self, db_session):
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.id is not None

    def test_attacker_ip_not_nullable(self, db_session):
        log = HoneypotLog(attacker_ip=None, port=22)
        db_session.add(log)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_port_not_nullable(self, db_session):
        log = HoneypotLog(attacker_ip="45.33.32.156", port=None)
        db_session.add(log)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_username_nullable(self, db_session):
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.username is None

    def test_password_nullable(self, db_session):
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.password is None

    def test_protocol_defaults_to_tcp(self, db_session):
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.protocol == "tcp"

    def test_created_at_auto_set(self, db_session):
        log = HoneypotLog(attacker_ip="45.33.32.156", port=22)
        db_session.add(log)
        db_session.flush()
        assert log.created_at is not None

class TestFirewallRuleORM:

    def test_tablename_is_firewall_rules(self):
        assert FirewallRule.__tablename__ == "firewall_rules"

    def test_has_id_column(self):
        assert hasattr(FirewallRule, "id")

    def test_can_add_to_session(self, db_session):
        rule = FirewallRule(
            target_ip="185.220.101.1",
            rule_command="ufw deny from 185.220.101.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.id is not None

    def test_target_ip_not_nullable(self, db_session):
        rule = FirewallRule(
            target_ip=None,
            rule_command="ufw deny from 185.220.101.1",
        )
        db_session.add(rule)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_rule_command_not_nullable(self, db_session):
        rule = FirewallRule(
            target_ip="185.220.101.1",
            rule_command=None,
        )
        db_session.add(rule)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_is_active_defaults_to_true(self, db_session):
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.is_active is True

    def test_source_nullable(self, db_session):
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.source is None

    def test_created_at_auto_set(self, db_session):
        rule = FirewallRule(
            target_ip="10.0.0.1",
            rule_command="ufw deny from 10.0.0.1",
        )
        db_session.add(rule)
        db_session.flush()
        assert rule.created_at is not None
