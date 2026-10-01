"""
Security Reports API Endpoints

Provides endpoints to download structured executive and technical reports in JSON and Markdown.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from typing import Any, Dict

from app.core.database import get_db
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/report", tags=["Reports"])


@router.get("")
def get_report_json(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns full executive and technical security report in structured JSON format.
    """
    return ReportGenerator.generate_full_report_data(db)


@router.get("/markdown", response_class=PlainTextResponse)
def get_report_markdown(db: Session = Depends(get_db)) -> str:
    """
    Returns formatted GitHub-flavored Markdown document of the complete security assessment report.
    """
    return ReportGenerator.generate_markdown_report(db)
