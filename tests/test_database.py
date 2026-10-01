"""
Unit Test: Core Database Initialization & ORM Models

Tests table creation, session handling, model persistence,
and data dictionary serialization for SQLite storage.
"""

import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.database import Base
from app.models.hash_record import HashRecord
from app.models.authentication import AuthenticationEvent
from app.models.ioc import IOCRecord, AnalysisResult

# Use an in-memory SQLite database for fast, isolated unit testing
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def db_session():
    """Creates a fresh in-memory database and session for each test function."""
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_hash_record_crud(db_session):
    """Verifies HashRecord creation, persistence, and serialization."""
    record = HashRecord(
        username="administrator",
        hash_type="NTLM",
        hash_value="31d6cfe0d16ae931b73c59d7e0c089c0",
        hash_fingerprint="7a86f9b819f390ff5d666d9c67a3a2e5cae1c0738d8f07011d67417537b92ec1",
        machine="LAB-DC-01",
        source="LAB_EXPORT",
        timestamp=datetime(2026, 9, 1, 10, 30, 0),
        is_reused=True,
        reuse_count=2,
        risk_score=50,
        risk_level="HIGH",
        notes="Educational test weak blank password hash."
    )
    db_session.add(record)
    db_session.commit()

    retrieved = db_session.query(HashRecord).filter_by(username="administrator").first()
    assert retrieved is not None
    assert retrieved.hash_type == "NTLM"
    assert retrieved.risk_level == "HIGH"
    assert retrieved.is_reused is True

    serialized = retrieved.to_dict()
    assert serialized["username"] == "administrator"
    assert serialized["hash_fingerprint"].startswith("7a86f9")
    assert serialized["risk_score"] == 50


def test_authentication_event_crud(db_session):
    """Verifies AuthenticationEvent creation and querying."""
    event = AuthenticationEvent(
        timestamp=datetime(2026, 9, 1, 10, 15, 0),
        username="sarah_finance",
        source_machine="LAB-PC-02",
        destination_machine="LAB-SRV-01",
        event_type="4625",
        status="FAILURE",
        ip_address="192.168.1.45",
        is_suspicious=True,
        anomaly_reason="Multiple logon failures detected"
    )
    db_session.add(event)
    db_session.commit()

    retrieved = db_session.query(AuthenticationEvent).filter_by(username="sarah_finance").first()
    assert retrieved is not None
    assert retrieved.status == "FAILURE"
    assert retrieved.is_suspicious is True
    assert "failures" in retrieved.anomaly_reason


def test_ioc_and_analysis_result_crud(db_session):
    """Verifies IOCRecord and AnalysisResult creation with MITRE ATT&CK metadata."""
    ioc = IOCRecord(
        ioc_id="IOC-2026-001",
        ioc_type="HASH_REUSE",
        severity="CRITICAL",
        mitre_technique_id="T1078.002",
        mitre_tactic="Lateral Movement",
        username="administrator",
        machine="LAB-DC-01",
        timestamp=datetime.now(),
        description="Password hash reused across privileged accounts",
        evidence="Hash fingerprint shared between administrator and backup_admin",
        defensive_action="Force immediate credential rotation and enforce MFA",
        status="ACTIVE"
    )
    analysis = AnalysisResult(
        total_hashes=50,
        unique_hashes=42,
        duplicate_hashes=8,
        weak_synthetic_hashes=3,
        high_risk_accounts=5,
        total_iocs=4,
        critical_iocs=1,
        summary_json='{"status": "completed"}'
    )
    db_session.add(ioc)
    db_session.add(analysis)
    db_session.commit()

    saved_ioc = db_session.query(IOCRecord).filter_by(ioc_id="IOC-2026-001").first()
    assert saved_ioc is not None
    assert saved_ioc.mitre_technique_id == "T1078.002"
    assert saved_ioc.severity == "CRITICAL"

    saved_analysis = db_session.query(AnalysisResult).first()
    assert saved_analysis.total_hashes == 50
    assert saved_analysis.critical_iocs == 1
