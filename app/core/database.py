"""
Database Engine & Session Management Module

1. What it does:
   Configures the SQLite engine, session maker, declarative Base class,
   and dependency injection generator for FastAPI endpoints.

2. Why it is required:
   Provides persistent storage for hash records, authentication event logs,
   detected IOCs, and security analysis scan snapshots.

3. Cybersecurity concept demonstrated:
   Forensic data integrity and evidence preservation. Storing security telemetry
   in an auditable local SQLite store ensures records can be queried, filtered,
   and correlated without modifying source evidence.

4. Example input / output:
   `db = next(get_db())` -> provides active SQLAlchemy Session
   `init_db()` -> initializes SQLite database tables if not already present
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from typing import Generator
from app.core.config import DATABASE_URL

# SQLite engine with check_same_thread=False for FastAPI concurrency
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a database session per request,
    ensuring cleanup and session closure upon response completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Creates all database tables defined in SQLAlchemy ORM models.
    Safe to call multiple times (idempotent).
    """
    # Import models here so Base knows about all registered tables
    import app.models.hash_record
    import app.models.authentication
    import app.models.ioc

    Base.metadata.create_all(bind=engine)
