"""
IOC & Analysis Snapshot ORM Models

1. What it does:
   Defines the database schema for Indicators of Compromise (IOCs) detected by
   the correlation engine, including MITRE ATT&CK mapping, defensive actions,
   and aggregated historical analysis scan summaries.

2. Why it is required:
   Stores structured threat intelligence artifacts that blue team SOC analysts
   use to triage incidents, assign investigation statuses, and review MITRE tactics.

3. Cybersecurity concept demonstrated:
   Indicator of Compromise (IOC) Management & MITRE ATT&CK Framework Mapping.
   Modern SOCs categorize detections using standardized frameworks (MITRE ATT&CK)
   and assign explicit, actionable defensive playbooks (e.g., credential resets,
   MFA enforcement, host isolation).

4. Example input:
   ioc_id="IOC-2026-001", ioc_type="HASH_REUSE", severity="CRITICAL",
   mitre_technique_id="T1078.002", mitre_tactic="Lateral Movement",
   username="administrator", machine="LAB-PC-01", description="Hash shared with 4 users"

5. Example output:
   Structured IOC record stored in DB, queryable by SOC dashboard with status="ACTIVE"
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.core.database import Base


class IOCRecord(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ioc_id = Column(String(50), unique=True, index=True, nullable=False)
    ioc_type = Column(String(50), index=True, nullable=False)
    # Types: HASH_REUSE, ACCOUNT_ANOMALY, AUTH_FAILURE_SPIKE,
    #        UNUSUAL_LOGIN_TIME, SUSPICIOUS_MACHINE, PRIVILEGED_ACCOUNT_ACTIVITY

    severity = Column(String(20), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL

    # MITRE ATT&CK Mapping
    mitre_technique_id = Column(String(30), index=True, nullable=False)  # e.g., T1078.002, T1110.001
    mitre_tactic = Column(String(50), nullable=False)  # Credential Access, Lateral Movement, etc.

    username = Column(String(100), index=True, nullable=True)
    machine = Column(String(100), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    defensive_action = Column(Text, nullable=False)
    status = Column(String(20), default="ACTIVE", index=True)  # ACTIVE, INVESTIGATING, RESOLVED

    def to_dict(self) -> dict:
        """Serializes the IOC record for API/JSON responses."""
        return {
            "id": self.id,
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "severity": self.severity,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_tactic": self.mitre_tactic,
            "username": self.username,
            "machine": self.machine,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else None,
            "description": self.description,
            "evidence": self.evidence,
            "defensive_action": self.defensive_action,
            "status": self.status
        }


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    total_hashes = Column(Integer, default=0)
    unique_hashes = Column(Integer, default=0)
    duplicate_hashes = Column(Integer, default=0)
    weak_synthetic_hashes = Column(Integer, default=0)
    high_risk_accounts = Column(Integer, default=0)
    total_iocs = Column(Integer, default=0)
    critical_iocs = Column(Integer, default=0)
    summary_json = Column(Text, nullable=True)

    def to_dict(self) -> dict:
        """Serializes the analysis snapshot for dashboard history."""
        return {
            "id": self.id,
            "scan_timestamp": self.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.scan_timestamp else None,
            "total_hashes": self.total_hashes,
            "unique_hashes": self.unique_hashes,
            "duplicate_hashes": self.duplicate_hashes,
            "weak_synthetic_hashes": self.weak_synthetic_hashes,
            "high_risk_accounts": self.high_risk_accounts,
            "total_iocs": self.total_iocs,
            "critical_iocs": self.critical_iocs,
            "summary_json": self.summary_json
        }
