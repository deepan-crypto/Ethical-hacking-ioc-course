"""
Unit Test: IOC Detection Engine & Security Report Generator

Tests multi-telemetry correlation, MITRE technique assignment,
attack scenario identification, timeline sequencing, and report generation.
"""

import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.ioc import IOCRecord
from app.services.hash_analyzer import HashAnalyzer
from app.services.ioc_detector import IOCDetector
from app.services.report_generator import ReportGenerator
from data.generate_datasets import (
    generate_hashes_dataset,
    generate_authentication_logs_dataset
)

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh in-memory database with populated lab data."""
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()

    # Seed both datasets
    h_csv = generate_hashes_dataset()
    a_csv = generate_authentication_logs_dataset()
    HashAnalyzer.ingest_csv_content(h_csv, session)
    IOCDetector.ingest_authentication_logs(a_csv, session)

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_authentication_log_ingestion(db_session):
    """Verifies parsing and persistence of Windows 4624/4625 event logs."""
    from app.models.authentication import AuthenticationEvent
    events = db_session.query(AuthenticationEvent).all()
    assert len(events) >= 30

    failures = [e for e in events if e.status == "FAILURE"]
    assert len(failures) >= 10, "Should have failure events from simulated attacks"

    suspicious = [e for e in events if e.is_suspicious]
    assert len(suspicious) >= 5, "Should flag off-hours and unknown machines"


def test_ioc_detection_pipeline_and_mitre_mapping(db_session):
    """Verifies that all simulated threat vectors are detected and mapped to MITRE ATT&CK."""
    iocs = IOCDetector.run_full_detection_pipeline(db_session)
    assert len(iocs) >= 4, "Should detect multiple IOCs across hashes and logs"

    types = {ioc.ioc_type for ioc in iocs}
    assert "HASH_REUSE" in types
    assert "AUTH_FAILURE_SPIKE" in types
    assert "UNUSUAL_LOGIN_TIME" in types

    # Check MITRE techniques
    mitre_ids = {ioc.mitre_technique_id for ioc in iocs}
    assert "T1078.002" in mitre_ids, "Should detect Domain Account Hash Reuse"
    assert "T1110.003" in mitre_ids, "Should detect Password Spraying"
    assert "T1098" in mitre_ids, "Should detect Off-hours Privileged Activity"

    # Check that at least one CRITICAL IOC exists
    critical_iocs = [i for i in iocs if i.severity == "CRITICAL"]
    assert len(critical_iocs) >= 1
    for i in critical_iocs:
        assert i.defensive_action != "", "All IOCs must have actionable defensive playbooks"


def test_chronological_timeline_generation(db_session):
    """Verifies merged chronological incident timeline."""
    IOCDetector.run_full_detection_pipeline(db_session)
    timeline = IOCDetector.get_chronological_timeline(db_session)

    assert len(timeline) >= 30
    # Must be sorted in ascending order
    for idx in range(len(timeline) - 1):
        assert timeline[idx]["timestamp"] <= timeline[idx + 1]["timestamp"]

    # Contains both auth events and IOC alerts
    types = {item["type"] for item in timeline}
    assert "AUTH_EVENT" in types
    assert "IOC_ALERT" in types


def test_report_generator_json_and_markdown(db_session):
    """Verifies executive report generation in JSON and Markdown formats."""
    IOCDetector.run_full_detection_pipeline(db_session)

    # Test JSON data
    report_data = ReportGenerator.generate_full_report_data(db_session)
    assert "executive_summary" in report_data
    assert report_data["executive_summary"]["total_hashes_analyzed"] >= 20
    assert report_data["executive_summary"]["total_iocs_detected"] >= 4
    assert len(report_data["recommendations"]) >= 5

    # Test Markdown document
    md_report = ReportGenerator.generate_markdown_report(db_session)
    assert "# Windows Password Hash Security Analysis" in md_report
    assert "## 1. Executive Summary" in md_report
    assert "## 4. Indicators of Compromise (IOC) Findings" in md_report
    assert "T1078.002" in md_report
