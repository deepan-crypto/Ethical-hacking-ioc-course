"""
Hash Management & Reuse API Endpoints

Handles hash record querying, CSV dataset uploading, and credential reuse analysis.
"""

from fastapi import APIRouter, Depends, File, Query, UploadFile, HTTPException
from sqlalchemy.orm import Session
from typing import Any, Dict, List, Optional

from app.core.database import get_db
from app.models.hash_record import HashRecord
from app.services.hash_analyzer import HashAnalyzer
from app.services.ioc_detector import IOCDetector

router = APIRouter(prefix="/api/hashes", tags=["Hashes"])


@router.get("")
def list_hash_records(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (LOW, MEDIUM, HIGH, CRITICAL)"),
    search: Optional[str] = Query(None, description="Search by username, machine, or hash"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Returns list of analyzed hash records with optional filtering and pagination.
    """
    query = db.query(HashRecord)

    if risk_level:
        query = query.filter(HashRecord.risk_level == risk_level.upper())

    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            (HashRecord.username.ilike(term)) |
            (HashRecord.machine.ilike(term)) |
            (HashRecord.hash_value.ilike(term)) |
            (HashRecord.hash_fingerprint.ilike(term))
        )

    total_count = query.count()
    records = query.order_by(HashRecord.risk_score.desc()).offset(offset).limit(limit).all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "records": [r.to_dict() for r in records]
    }


@router.get("/reuse")
def get_hash_reuse_matrix(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns all detected cross-account hash reuse clusters, affected hosts,
    and associated privilege escalation risks.
    """
    clusters = HashAnalyzer.get_reuse_matrix(db)
    return {
        "total_clusters": len(clusters),
        "total_accounts_affected": sum(c["affected_count"] for c in clusters),
        "clusters": clusters
    }


@router.post("/upload")
async def upload_hash_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    Uploads and processes a Windows hash CSV file from an authorized lab environment.
    Columns expected: username, hash_type, hash, machine, source, timestamp
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only CSV files are supported.")

    content = await file.read()
    csv_text = content.decode("utf-8", errors="replace")

    result = HashAnalyzer.ingest_csv_content(csv_text, db)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    # Re-run IOC detection pipeline
    IOCDetector.run_full_detection_pipeline(db)

    return {
        "status": "success",
        "message": f"Successfully imported {result.get('total_imported', 0)} hash records.",
        "details": result
    }
