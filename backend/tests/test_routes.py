import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from backend.app.main import app
from backend.app.database import Base, get_db
from backend.app.models import Threat, HoneypotLog

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(name="db_session")
def fixture_db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(name="client")
def fixture_client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_live_threats_endpoint(client, db_session):
    threat1 = Threat(indicator="192.168.1.1", type="ip", source="AbuseIPDB", severity="critical", country="ZA")
    threat2 = Threat(indicator="192.168.1.2", type="ip", source="URLhaus", severity="high", country="RU")
    db_session.add_all([threat1, threat2])
    db_session.commit()

    response = client.get("/api/threats/live")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2
    assert any(t["indicator"] == "192.168.1.1" for t in data)

def test_live_threats_filtering(client, db_session):
    threat1 = Threat(indicator="192.168.1.1", type="ip", source="AbuseIPDB", severity="critical", country="ZA")
    threat2 = Threat(indicator="192.168.1.2", type="ip", source="URLhaus", severity="high", country="RU")
    db_session.add_all([threat1, threat2])
    db_session.commit()

    response = client.get("/api/threats/live?countries=ZA")
    assert response.status_code == 200
    data = response.json()
    assert all(t["country"] == "ZA" for t in data)

def test_threats_stats_endpoint(client, db_session):
    threat1 = Threat(indicator="192.168.1.1", type="ip", source="AbuseIPDB", severity="critical", country="ZA")
    threat2 = Threat(indicator="http://evil.com", type="url", source="URLhaus", severity="high", country="RU")
    db_session.add_all([threat1, threat2])
    db_session.commit()

    response = client.get("/api/threats/stats")
    assert response.status_code == 200
    data = response.json()
    assert "by_type" in data
    assert "by_severity" in data
    assert data["by_type"].get("ip") == 1
    assert data["by_type"].get("url") == 1
    assert data["by_severity"].get("critical") == 1

def test_heatmap_data_endpoint(client, db_session):
    threat1 = Threat(indicator="1.1.1.1", type="ip", source="AbuseIPDB", severity="high", country="ZA")
    threat2 = Threat(indicator="2.2.2.2", type="ip", source="AbuseIPDB", severity="high", country="ZA")
    threat3 = Threat(indicator="3.3.3.3", type="ip", source="URLhaus", severity="low", country="US")
    db_session.add_all([threat1, threat2, threat3])
    db_session.commit()

    response = client.get("/api/map/heatmap-data")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    za_item = next((item for item in data if item["country"] == "ZA"), None)
    assert za_item is not None
    assert za_item["count"] == 2

def test_search_endpoint(client, db_session):
    threat = Threat(indicator="203.0.113.88", type="ip", source="AbuseIPDB", severity="high", country="ZA")
    db_session.add(threat)
    db_session.commit()

    response = client.get("/api/search?q=203.0.113.88")
    assert response.status_code == 200
    data = response.json()
    assert data["indicator"] == "203.0.113.88"
    assert data["source"] == "AbuseIPDB"

    not_found = client.get("/api/search?q=8.8.8.8")
    assert not_found.status_code == 404

def test_sa_context_endpoints(client, db_session):
    threat = Threat(indicator="196.25.1.5", type="ip", source="Blocklist.de", severity="high", country="ZA")
    db_session.add(threat)
    
    log = HoneypotLog(attacker_ip="185.220.101.5", port=22, username="root", password="password", protocol="tcp")
    db_session.add(log)
    db_session.commit()

    threats_resp = client.get("/api/sa/threats")
    assert threats_resp.status_code == 200
    assert isinstance(threats_resp.json(), list)

    stats_resp = client.get("/api/sa/stats")
    assert stats_resp.status_code == 200
    data = stats_resp.json()
    assert "top_countries" in data
    assert "top_ports" in data
