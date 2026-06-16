from datetime import datetime
from backend.app.database import Base
from sqlalchemy import Integer, String, DateTime, Boolean, Column

class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True)
    indicator = Column(String(50), unique=True, nullable=False)
    type = Column(String(120), nullable=False)
    source = Column(String(120), nullable=False)
    severity = Column(String(120), nullable=False)
    country = Column(String(120))
    created_at = Column( DateTime(timezone=True), default=datetime.now)

    def __repr__(self):
        return f"Threat(indicator={self.indicator})"

class HoneypotLog(Base):
    __tablename__ = "honeypot_logs"
    id = Column(Integer, primary_key=True)
    attacker_ip = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    username = Column(String(120), nullable=True)
    password = Column(String(120), nullable=True)
    protocol = Column(String(120), nullable=True, default="tcp")
    created_at = Column(DateTime(timezone=True), default=datetime.now)

    def __init__(self, attacker_ip, port, username=None, password=None, protocol="tcp", **kwargs):
        super().__init__(attacker_ip=attacker_ip, port=port, username=username, password=password, protocol=protocol, **kwargs)

    def __repr__(self):
        return f"HoneypotLog(attacker_ip={self.attacker_ip})"

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True)
    target_ip = Column(String, nullable=False)
    rule_command = Column(String, unique=True, nullable=False)
    rule_type = Column(String(120), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    source = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now)

    def __init__(self, target_ip, rule_command, rule_type=None, is_active=True, source=None, **kwargs):
        super().__init__(target_ip=target_ip, rule_command=rule_command, rule_type=rule_type, is_active=is_active, source=source, **kwargs)

    def __repr__(self):
        return f"FirewallRule(target_ip={self.target_ip})"




