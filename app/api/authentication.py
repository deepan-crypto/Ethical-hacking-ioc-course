"""
Authentication Telemetry & Timeline API Endpoints

Provides querying of Windows Event 4624/4625 logs, CSV uploading, and chronological timeline.
"""

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional

from app.core.database import get_db
from app.models.authentication import AuthenticationEvent
from app.services.ioc_detector import IOCDetector

router = APIRouter(prefix="/api", tags=["Authentication & Timeline"])


@router.get("/authentication-events")
def list_authentication_events(
    status: Optional[str] = Query(None, description="SUCCESS or FAILURE"),
    suspicious_only: bool = Query(False, description="Filter for suspicious events only"),
    username: Optional[str] = Query(None, description="Filter by username"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Returns list of Windows authentication telemetry events with anomaly annotations.
    """
    query = db.query(AuthenticationEvent)

    if status:
        query = query.filter(AuthenticationEvent.status == status.upper())
    if suspicious_only:
        query = query.filter(AuthenticationEvent.is_suspicious.is_(True))
    if username:
        query = query.filter(AuthenticationEvent.username.ilike(f"%{username.strip()}%"))

    total_count = query.count()
    events = query.order_by(AuthenticationEvent.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": [e.to_dict() for e in events]
    }


@router.get("/timeline")
def get_incident_timeline(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns the unified chronological incident timeline combining
    authentication telemetry with detected IOC milestones.
    """
    timeline = IOCDetector.get_chronological_timeline(db)
    return {
        "total_timeline_entries": len(timeline),
        "timeline": timeline
    }


@router.post("/authentication/upload")
async def upload_authentication_logs(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Uploads and processes a Windows Security Event log CSV from an authorized lab.
    Columns expected: timestamp, username, source_machine, destination_machine, event_type, status, ip_address
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only CSV files are supported.")

    content = await file.read()
    csv_text = content.decode("utf-8", errors="replace")

    result = IOCDetector.ingest_authentication_logs(csv_text, db)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    # Re-run IOC detection pipeline
    detected = IOCDetector.run_full_detection_pipeline(db)

    return {
        "status": "success",
        "message": f"Successfully ingested {result.get('total_events_imported', 0)} authentication events.",
        "details": result,
        "iocs_triggered": len(detected)
    }
