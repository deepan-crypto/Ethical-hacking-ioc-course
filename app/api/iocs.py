"""
IOC Management & Triage API Endpoints

Provides querying, filtering, and status triage updates for detected Indicators of Compromise.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional

from app.core.database import get_db
from app.models.ioc import IOCRecord
from app.services.mitre_mapper import MitreMapper

router = APIRouter(prefix="/api/iocs", tags=["IOCs"])


class IOCStatusUpdate(BaseModel):
    status: str  # ACTIVE, INVESTIGATING, RESOLVED


@router.get("")
def list_iocs(
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    ioc_type: Optional[str] = Query(None, description="Filter by type (HASH_REUSE, AUTH_FAILURE_SPIKE, etc.)"),
    status: Optional[str] = Query(None, description="Filter by status (ACTIVE, INVESTIGATING, RESOLVED)"),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Returns list of detected Indicators of Compromise with MITRE ATT&CK tags.
    """
    query = db.query(IOCRecord)

    if severity:
        query = query.filter(IOCRecord.severity == severity.upper())
    if ioc_type:
        query = query.filter(IOCRecord.ioc_type == ioc_type.upper())
    if status:
        query = query.filter(IOCRecord.status == status.upper())

    # Order CRITICAL first, then newest
    iocs = query.order_by(IOCRecord.severity.desc(), IOCRecord.timestamp.desc()).all()

    return {
        "total": len(iocs),
        "iocs": [i.to_dict() for i in iocs]
    }


@router.get("/{ioc_id}")
def get_ioc_detail(ioc_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns comprehensive details for an individual IOC including MITRE playbook recommendations.
    """
    ioc = db.query(IOCRecord).filter(IOCRecord.ioc_id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    mitre_info = MitreMapper.get_technique(ioc.mitre_technique_id)

    return {
        "ioc": ioc.to_dict(),
        "mitre_details": mitre_info
    }


@router.patch("/{ioc_id}/status")
def update_ioc_status(
    ioc_id: str,
    payload: IOCStatusUpdate,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Updates the operational triage status of an IOC (e.g. ACTIVE -> INVESTIGATING -> RESOLVED).
    """
    ioc = db.query(IOCRecord).filter(IOCRecord.ioc_id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")

    valid_statuses = {"ACTIVE", "INVESTIGATING", "RESOLVED"}
    new_status = payload.status.strip().upper()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}")

    ioc.status = new_status
    db.commit()

    return {
        "status": "success",
        "ioc_id": ioc.ioc_id,
        "new_status": ioc.status
    }
