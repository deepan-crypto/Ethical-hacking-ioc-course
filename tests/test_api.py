"""
Integration Test: FastAPI REST Endpoints

Tests all dashboard, hashes, IOCs, authentication telemetry, timeline,
and report export API endpoints using FastAPI's TestClient.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_db
from app.main import app
from app.services.hash_analyzer import HashAnalyzer
from app.services.ioc_detector import IOCDetector
from data.generate_datasets import (
    generate_hashes_dataset,
    generate_authentication_logs_dataset
)

TEST_DB_URL = "sqlite:///:memory:"

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="module", autouse=True)
def setup_test_database():
    """Initializes in-memory database and loads sample data once for the API test module."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    h_path = generate_hashes_dataset()
    a_path = generate_authentication_logs_dataset()
    HashAnalyzer.ingest_csv_content(h_path, db)
    IOCDetector.ingest_authentication_logs(a_path, db)
    IOCDetector.run_full_detection_pipeline(db)

    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


def test_api_dashboard_endpoint(client):
    """GET /api/dashboard returns metrics, distributions, and recent timeline activity."""
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()

    assert "summary" in data
    assert data["summary"]["total_hashes"] >= 20
    assert data["summary"]["total_iocs"] >= 4
    assert "severity_distribution" in data
    assert "mitre_tactics" in data
    assert "recent_activity" in data


def test_api_mitre_matrix_endpoint(client):
    """GET /api/mitre-matrix returns technique mappings with active detection counts."""
    response = client.get("/api/mitre-matrix")
    assert response.status_code == 200
    data = response.json()

    assert data["total_techniques_monitored"] >= 6
    assert data["active_techniques_detected"] >= 1
    assert len(data["techniques"]) >= 6


def test_api_hashes_endpoints(client):
    """GET /api/hashes and GET /api/hashes/reuse return validated records and clusters."""
    # List hashes
    res = client.get("/api/hashes?limit=50")
    assert res.status_code == 200
    hashes_data = res.json()
    assert hashes_data["total"] >= 20
    assert len(hashes_data["records"]) >= 20

    # Filter by risk level
    res_crit = client.get("/api/hashes?risk_level=CRITICAL")
    assert res_crit.status_code == 200
    assert res_crit.json()["total"] >= 1

    # Reuse matrix
    res_reuse = client.get("/api/hashes/reuse")
    assert res_reuse.status_code == 200
    reuse_data = res_reuse.json()
    assert reuse_data["total_clusters"] >= 2
    assert reuse_data["total_accounts_affected"] >= 4


def test_api_iocs_endpoints(client):
    """GET /api/iocs, details, and status updates."""
    res = client.get("/api/iocs")
    assert res.status_code == 200
    iocs_data = res.json()
    assert iocs_data["total"] >= 4

    first_ioc = iocs_data["iocs"][0]
    ioc_id = first_ioc["ioc_id"]

    # Single IOC detail
    detail_res = client.get(f"/api/iocs/{ioc_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["ioc"]["ioc_id"] == ioc_id
    assert "mitre_details" in detail_data

    # Update status
    patch_res = client.patch(f"/api/iocs/{ioc_id}/status", json={"status": "INVESTIGATING"})
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "INVESTIGATING"


def test_api_authentication_and_timeline_endpoints(client):
    """GET /api/authentication-events and GET /api/timeline."""
    res_auth = client.get("/api/authentication-events")
    assert res_auth.status_code == 200
    auth_data = res_auth.json()
    assert auth_data["total"] >= 30

    res_timeline = client.get("/api/timeline")
    assert res_timeline.status_code == 200
    timeline_data = res_timeline.json()
    assert timeline_data["total_timeline_entries"] >= 30


def test_api_reports_endpoints(client):
    """GET /api/report (JSON) and GET /api/report/markdown (Plain Text)."""
    res_json = client.get("/api/report")
    assert res_json.status_code == 200
    rep_data = res_json.json()
    assert "executive_summary" in rep_data
    assert "hash_analysis" in rep_data
    assert "recommendations" in rep_data

    res_md = client.get("/api/report/markdown")
    assert res_md.status_code == 200
    assert "# Windows Password Hash Security Analysis" in res_md.text
