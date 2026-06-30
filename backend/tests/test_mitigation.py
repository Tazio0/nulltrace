"""Tests IronCurtainEngine rule generation for UFW, iptables, MikroTik, and edge cases."""

import pytest

from backend.app.core.mitigation import IronCurtainEngine

class TestIronCurtainEngineInit:

    def test_default_initialization(self):
        engine = IronCurtainEngine()
        assert engine is not None

    def test_has_required_methods(self):
        engine = IronCurtainEngine()
        assert hasattr(engine, "generate_ufw_rule")
        assert hasattr(engine, "generate_iptables_rule")
        assert hasattr(engine, "generate_mikrotik_rule")

class TestGenerateUfwRule:

    def test_basic_ufw_deny_rule(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("185.220.101.1")
        assert rule == "ufw deny from 185.220.101.1"

    def test_ufw_rule_contains_ip(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("10.0.0.1")
        assert "10.0.0.1" in rule

    def test_ufw_rule_starts_with_ufw(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("1.2.3.4")
        assert rule.startswith("ufw")

    def test_ufw_rule_contains_deny(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("1.2.3.4")
        assert "deny" in rule

    def test_ufw_rule_with_cidr_range(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("192.168.0.0/24")
        assert "192.168.0.0/24" in rule
        assert rule == "ufw deny from 192.168.0.0/24"

    def test_ufw_rule_returns_string(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("1.2.3.4")
        assert isinstance(rule, str)

class TestGenerateIptablesRule:

    def test_basic_iptables_drop_rule(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("185.220.101.1")
        assert rule == "iptables -A INPUT -s 185.220.101.1 -j DROP"

    def test_iptables_rule_contains_ip(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("10.0.0.1")
        assert "10.0.0.1" in rule

    def test_iptables_rule_uses_input_chain(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert "-A INPUT" in rule

    def test_iptables_rule_uses_drop_target(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert "-j DROP" in rule

    def test_iptables_rule_uses_source_flag(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert "-s 1.2.3.4" in rule

    def test_iptables_rule_with_cidr_range(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("10.0.0.0/8")
        assert rule == "iptables -A INPUT -s 10.0.0.0/8 -j DROP"

    def test_iptables_rule_returns_string(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("1.2.3.4")
        assert isinstance(rule, str)

class TestGenerateMikrotikRule:

    def test_basic_mikrotik_drop_rule(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("185.220.101.1")
        assert rule == "/ip firewall filter add chain=input src-address=185.220.101.1 action=drop"

    def test_mikrotik_rule_contains_ip(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("10.0.0.1")
        assert "10.0.0.1" in rule

    def test_mikrotik_rule_uses_input_chain(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert "chain=input" in rule

    def test_mikrotik_rule_uses_drop_action(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert "action=drop" in rule

    def test_mikrotik_rule_uses_src_address(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert "src-address=1.2.3.4" in rule

    def test_mikrotik_rule_starts_with_ip_firewall(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert rule.startswith("/ip firewall")

    def test_mikrotik_rule_with_cidr_range(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("172.16.0.0/12")
        assert "src-address=172.16.0.0/12" in rule

    def test_mikrotik_rule_returns_string(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("1.2.3.4")
        assert isinstance(rule, str)

class TestEdgeCases:

    def test_ufw_rule_strips_whitespace_from_ip(self):
        engine = IronCurtainEngine()
        rule = engine.generate_ufw_rule("  185.220.101.1  ")
        assert rule == "ufw deny from 185.220.101.1"

    def test_iptables_rule_strips_whitespace_from_ip(self):
        engine = IronCurtainEngine()
        rule = engine.generate_iptables_rule("  10.0.0.1  ")
        assert rule == "iptables -A INPUT -s 10.0.0.1 -j DROP"

    def test_mikrotik_rule_strips_whitespace_from_ip(self):
        engine = IronCurtainEngine()
        rule = engine.generate_mikrotik_rule("  10.0.0.1  ")
        assert "src-address=10.0.0.1" in rule

    def test_generate_ufw_rule_empty_ip_raises_error(self):
        engine = IronCurtainEngine()
        with pytest.raises(ValueError):
            engine.generate_ufw_rule("")

    def test_generate_iptables_rule_empty_ip_raises_error(self):
        engine = IronCurtainEngine()
        with pytest.raises(ValueError):
            engine.generate_iptables_rule("")

    def test_generate_mikrotik_rule_empty_ip_raises_error(self):
        engine = IronCurtainEngine()
        with pytest.raises(ValueError):
            engine.generate_mikrotik_rule("")

class TestBatchGeneration:

    def test_generate_rules_for_multiple_ips(self):
        engine = IronCurtainEngine()
        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        rules = [engine.generate_ufw_rule(ip) for ip in ips]
        assert len(rules) == 3
        assert rules[0] == "ufw deny from 1.1.1.1"
        assert rules[1] == "ufw deny from 2.2.2.2"
        assert rules[2] == "ufw deny from 3.3.3.3"
