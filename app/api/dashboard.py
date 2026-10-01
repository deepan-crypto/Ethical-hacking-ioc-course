"""
Dashboard API Endpoints Module

Provides summarized metrics, severity distributions, MITRE ATT&CK counts,
analysis triggers, and one-click lab dataset seeding.
"""

from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Any, Dict

from app.core.config import DISCLAIMER
from app.core.database import get_db
from app.models.authentication import AuthenticationEvent
from app.models.hash_record import HashRecord
from app.models.ioc import IOCRecord, AnalysisResult
from app.services.hash_analyzer import HashAnalyzer
from app.services.ioc_detector import IOCDetector
from app.services.mitre_mapper import MitreMapper
from data.generate_datasets import (
    generate_hashes_dataset,
    generate_authentication_logs_dataset
)

router = APIRouter(prefix="/api", tags=["Dashboard"])


@router.get("/dashboard")
def get_dashboard_summary(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns executive SOC overview metrics, severity counts, and recent alert activity.
    """
    hash_records = db.query(HashRecord).all()
    auth_events = db.query(AuthenticationEvent).all()
    iocs = db.query(IOCRecord).all()

    total_hashes = len(hash_records)
    unique_hashes = len({r.hash_value for r in hash_records})
    duplicate_hashes = total_hashes - unique_hashes
    weak_hashes = sum(1 for r in hash_records if "Weak" in (r.notes or ""))
    high_risk_accounts = sum(1 for r in hash_records if r.risk_level in ["HIGH", "CRITICAL"])

    total_auth = len(auth_events)
    suspicious_auth = sum(1 for e in auth_events if e.is_suspicious)
    failed_auth = sum(1 for e in auth_events if e.status == "FAILURE")

    total_iocs = len(iocs)
    critical_iocs = sum(1 for i in iocs if i.severity == "CRITICAL")
    high_iocs = sum(1 for i in iocs if i.severity == "HIGH")
    medium_iocs = sum(1 for i in iocs if i.severity == "MEDIUM")
    low_iocs = sum(1 for i in iocs if i.severity == "LOW")

    # Severity distribution
    severity_dist = {
        "LOW": low_iocs,
        "MEDIUM": medium_iocs,
        "HIGH": high_iocs,
        "CRITICAL": critical_iocs
    }

    # Hash risk distribution
    hash_risk_dist = {
        "LOW": sum(1 for r in hash_records if r.risk_level == "LOW"),
        "MEDIUM": sum(1 for r in hash_records if r.risk_level == "MEDIUM"),
        "HIGH": sum(1 for r in hash_records if r.risk_level == "HIGH"),
        "CRITICAL": sum(1 for r in hash_records if r.risk_level == "CRITICAL")
    }

    # IOCs by category
    iocs_by_type: Dict[str, int] = {}
    for i in iocs:
        iocs_by_type[i.ioc_type] = iocs_by_type.get(i.ioc_type, 0) + 1

    # MITRE Tactics breakdown
    mitre_tactics: Dict[str, int] = {}
    for i in iocs:
        mitre_tactics[i.mitre_tactic] = mitre_tactics.get(i.mitre_tactic, 0) + 1

    # Recent timeline activity (last 10 items)
    timeline = IOCDetector.get_chronological_timeline(db)
    recent_activity = timeline[-10:] if len(timeline) >= 10 else timeline
    recent_activity.reverse()

    return {
        "summary": {
            "total_hashes": total_hashes,
            "unique_hashes": unique_hashes,
            "duplicate_hashes": duplicate_hashes,
            "weak_hashes": weak_hashes,
            "high_risk_accounts": high_risk_accounts,
            "total_iocs": total_iocs,
            "critical_iocs": critical_iocs,
            "high_iocs": high_iocs,
            "total_auth_events": total_auth,
            "failed_auth_events": failed_auth,
            "suspicious_auth_events": suspicious_auth
        },
        "severity_distribution": severity_dist,
        "hash_risk_distribution": hash_risk_dist,
        "iocs_by_type": iocs_by_type,
        "mitre_tactics": mitre_tactics,
        "recent_activity": recent_activity,
        "disclaimer": DISCLAIMER
    }


@router.get("/mitre-matrix")
def get_mitre_matrix_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns full MITRE ATT&CK technique matrix populated with active IOC detection counts.
    """
    all_techniques = MitreMapper.get_all_matrix_techniques()
    iocs = db.query(IOCRecord).all()

    # Count detections per technique
    technique_counts: Dict[str, int] = {}
    for i in iocs:
        technique_counts[i.mitre_technique_id] = technique_counts.get(i.mitre_technique_id, 0) + 1

    matrix_view = []
    for tech in all_techniques:
        tid = tech["technique_id"]
        count = technique_counts.get(tid, 0)
        matrix_view.append({
            **tech,
            "detection_count": count,
            "is_active": count > 0,
            "status_label": f"{count} Active Alert(s)" if count > 0 else "Baseline (No Alerts)"
        })

    return {
        "total_techniques_monitored": len(all_techniques),
        "active_techniques_detected": sum(1 for m in matrix_view if m["is_active"]),
        "techniques": matrix_view
    }


@router.post("/analyze")
def trigger_analysis(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Manually triggers full correlation pipeline across hashes and authentication logs.
    """
    detected_iocs = IOCDetector.run_full_detection_pipeline(db)

    # Save analysis result snapshot
    hash_records = db.query(HashRecord).all()
    unique_hashes = len({r.hash_value for r in hash_records})
    critical_count = sum(1 for i in detected_iocs if i.severity == "CRITICAL")
    high_risk_accs = sum(1 for r in hash_records if r.risk_level in ["HIGH", "CRITICAL"])

    snapshot = AnalysisResult(
        scan_timestamp=datetime.now(),
        total_hashes=len(hash_records),
        unique_hashes=unique_hashes,
        duplicate_hashes=len(hash_records) - unique_hashes,
        weak_synthetic_hashes=sum(1 for r in hash_records if "Weak" in (r.notes or "")),
        high_risk_accounts=high_risk_accs,
        total_iocs=len(detected_iocs),
        critical_iocs=critical_count,
        summary_json=f'{{"status": "completed", "iocs_detected": {len(detected_iocs)}}}'
    )
    db.add(snapshot)
    db.commit()

    return {
        "status": "success",
        "message": f"Security analysis complete. {len(detected_iocs)} IOCs identified ({critical_count} CRITICAL).",
        "iocs_detected_count": len(detected_iocs),
        "critical_iocs_count": critical_count
    }


@router.post("/seed-lab-data")
def seed_sample_lab_data(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    One-click helper for demonstration: generates sample lab CSVs,
    ingests hashes, ingests auth logs, and executes the detection pipeline.
    """
    h_path = generate_hashes_dataset()
    a_path = generate_authentication_logs_dataset()

    hash_res = HashAnalyzer.ingest_csv_content(h_path, db)
    auth_res = IOCDetector.ingest_authentication_logs(a_path, db)
    iocs = IOCDetector.run_full_detection_pipeline(db)

    return {
        "status": "success",
        "message": "Sample lab data generated, ingested, and analyzed successfully!",
        "hashes_imported": hash_res.get("total_imported", 0),
        "auth_events_imported": auth_res.get("total_events_imported", 0),
        "iocs_detected": len(iocs)
    }
