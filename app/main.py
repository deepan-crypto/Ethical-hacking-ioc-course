"""
Main FastAPI Application Entrypoint

1. What it does:
   Initializes the FastAPI application, mounts API route controllers,
   configures CORS for modern frontend communication, initializes database
   tables upon startup, and seeds sample lab data if empty.

2. Why it is required:
   Serves as the central server runtime exposing REST endpoints to the
   React Blue Team SOC frontend and handling lab data ingestion.

3. Cybersecurity concept demonstrated:
   Secure API Architecture & SOC Backend Orchestration.
   Validates incoming telemetry, prevents CORS misconfigurations, and
   serves threat intelligence snapshots across defensive tooling.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core import config
from app.core.database import init_db, SessionLocal
from app.api import dashboard, hashes, iocs, authentication, reports
from app.models.hash_record import HashRecord
from app.services.hash_analyzer import HashAnalyzer
from app.services.ioc_detector import IOCDetector
from data.generate_datasets import (
    generate_hashes_dataset,
    generate_authentication_logs_dataset
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager:
    Initializes database tables and automatically loads baseline lab datasets
    if the database is currently empty.
    """
    init_db()

    # Auto-seed sample lab datasets on startup if database has no records
    db = SessionLocal()
    try:
        count = db.query(HashRecord).count()
        if count == 0:
            h_csv = generate_hashes_dataset()
            a_csv = generate_authentication_logs_dataset()
            HashAnalyzer.ingest_csv_content(h_csv, db)
            IOCDetector.ingest_authentication_logs(a_csv, db)
            IOCDetector.run_full_detection_pipeline(db)
    finally:
        db.close()

    yield


app = FastAPI(
    title=config.APP_TITLE,
    description=config.APP_DESCRIPTION,
    version=config.APP_VERSION,
    lifespan=lifespan
)

# Enable CORS for React development server and local clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(dashboard.router)
app.include_router(hashes.router)
app.include_router(iocs.router)
app.include_router(authentication.router)
app.include_router(reports.router)

# Static & Frontend Serving Setup
STATIC_DIR = Path(__file__).resolve().parent / "static"
REACT_DIST_DIR = STATIC_DIR / "dist"

# If built React frontend exists in app/static/dist, mount and serve it
if REACT_DIST_DIR.exists():
    app.mount("/assets", StaticFiles(directory=REACT_DIST_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_react_app(full_path: str):
        # Allow API endpoints to take precedence
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            return None
        index_file = REACT_DIST_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "SOC Dashboard API is running. Build frontend to view UI."}
else:
    @app.get("/", include_in_schema=False)
    async def root_status():
        return {
            "name": config.APP_TITLE,
            "version": config.APP_VERSION,
            "status": "ONLINE",
            "docs_url": "/docs",
            "api_endpoints": {
                "dashboard": "/api/dashboard",
                "mitre_matrix": "/api/mitre-matrix",
                "hashes": "/api/hashes",
                "hash_reuse": "/api/hashes/reuse",
                "iocs": "/api/iocs",
                "authentication_events": "/api/authentication-events",
                "timeline": "/api/timeline",
                "report": "/api/report",
                "report_markdown": "/api/report/markdown"
            },
            "disclaimer": config.DISCLAIMER
        }
