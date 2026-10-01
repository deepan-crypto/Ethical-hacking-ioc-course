"""
Unit Test: Hash Analysis Engine (hash_analyzer.py)

Validates format checking, SHA-256 fingerprinting, collision & reuse clustering,
weak synthetic hash detection, and SQLite database ingestion.
"""

import hashlib
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.hash_record import HashRecord
from app.services.hash_analyzer import HashAnalyzer
from data.generate_datasets import (
    generate_hashes_dataset,
    LAB_REUSED_ADMIN_HASH,
    LAB_REUSED_ENG_HASH,
    LAB_WEAK_HASH_BLANK
)

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh in-memory database session."""
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_validate_hash_format():
    """Checks format validation and algorithm bit-length identification."""
    # Valid NTLM (32 hex)
    valid, htype, _ = HashAnalyzer.validate_hash_format("b45cffe0e4c5b3671234a4918732168a")
    assert valid is True
    assert htype == "NTLM"

    # Uppercase NTLM
    valid, htype, _ = HashAnalyzer.validate_hash_format("B45CFFE0E4C5B3671234A4918732168A")
    assert valid is True
    assert htype == "NTLM"

    # Invalid non-hex characters
    valid, htype, msg = HashAnalyzer.validate_hash_format("zzzzffe0e4c5b3671234a4918732168a")
    assert valid is False
    assert htype == "INVALID"

    # Wrong length
    valid, htype, msg = HashAnalyzer.validate_hash_format("1234567890abcdef")
    assert valid is False
    assert htype == "UNKNOWN"

    # Empty / None
    valid, htype, msg = HashAnalyzer.validate_hash_format("")
    assert valid is False


def test_calculate_sha256_fingerprint():
    """Verifies SHA-256 fingerprint generation and case-normalization."""
    test_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
    expected = hashlib.sha256(test_hash.encode("utf-8")).hexdigest()

    fp1 = HashAnalyzer.calculate_sha256_fingerprint(test_hash)
    fp2 = HashAnalyzer.calculate_sha256_fingerprint(test_hash.upper())

    assert fp1 == expected
    assert fp1 == fp2, "Fingerprinting must normalize casing"


def test_check_known_weak_hash():
    """Verifies detection of known educational weak synthetic hashes."""
    weak_desc = HashAnalyzer.check_known_weak_hash(LAB_WEAK_HASH_BLANK)
    assert weak_desc is not None
    assert "Blank" in weak_desc or "Empty" in weak_desc

    random_hash = "e10adc3949ba59abbe56e057f20f883e"
    assert HashAnalyzer.check_known_weak_hash(random_hash) is None


def test_detect_reuse_clusters():
    """Tests identification of multi-account credential sharing clusters."""
    sample_records = [
        {"username": "user1", "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "machine": "PC-01"},
        {"username": "user2", "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "machine": "PC-02"},
        {"username": "admin", "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "machine": "DC-01"},
        {"username": "backup", "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "machine": "SRV-01"},
        {"username": "user3", "hash": "cccccccccccccccccccccccccccccccc", "machine": "PC-03"},
    ]

    clusters = HashAnalyzer.detect_reuse_clusters(sample_records)
    assert len(clusters) == 2, "Should find exactly 2 reuse clusters"

    # Cluster with 'admin' should be marked CRITICAL
    admin_cluster = next((c for c in clusters if "admin" in c["affected_accounts"]), None)
    assert admin_cluster is not None
    assert admin_cluster["has_privileged_account"] is True
    assert admin_cluster["risk_level"] == "CRITICAL"
    assert admin_cluster["affected_count"] == 2

    # Cluster without privileged users
    user_cluster = next((c for c in clusters if "user1" in c["affected_accounts"]), None)
    assert user_cluster is not None
    assert user_cluster["has_privileged_account"] is False
    assert user_cluster["affected_count"] == 2


def test_csv_ingestion_and_db_persistence(db_session):
    """Verifies end-to-end CSV ingestion, analysis, and SQLite persistence."""
    csv_path = generate_hashes_dataset()
    result = HashAnalyzer.ingest_csv_content(csv_path, db_session)

    assert result["total_records_processed"] >= 20
    assert result["reused_clusters_detected"] >= 2
    assert result["weak_hashes_detected"] >= 3

    # Query database records
    records = db_session.query(HashRecord).all()
    assert len(records) == result["total_imported"]

    # Verify admin record has high/critical risk score and reuse flag
    admin_rec = db_session.query(HashRecord).filter_by(username="administrator").first()
    assert admin_rec is not None
    assert admin_rec.is_reused is True
    assert admin_rec.risk_score >= 40
    assert admin_rec.risk_level in ["HIGH", "CRITICAL"]
    assert len(admin_rec.hash_fingerprint) == 64
