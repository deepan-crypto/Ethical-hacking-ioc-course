"""
IOC Detection & Authentication Log Correlation Engine Module

1. What it does:
   - Ingests and parses Windows Security Event logs (Event IDs 4624 Logon Success and 4625 Logon Failure).
   - Detects brute-force logon failure bursts against single accounts (MITRE T1110.001).
   - Detects password spraying attacks across multiple accounts from single IP sources (MITRE T1110.003).
   - Detects out-of-hours authentications, particularly for privileged accounts (MITRE T1098).
   - Detects authentication attempts originating from unapproved lab hosts (MITRE T1021.002).
   - Correlates hash reuse findings with active authentication telemetry.
   - Generates standardized, structured Indicators of Compromise (IOCs) with MITRE ATT&CK mappings.

2. Why it is required:
   Isolated credential hashes or individual failed logons do not tell the whole story.
   Blue teams require a correlation engine that connects multiple data points
   (e.g., shared hash + logon failure burst + off-hours access) into verified incidents.

3. Cybersecurity concept demonstrated:
   SIEM / EDR Multi-Source Telemetry Correlation.
   In modern SOC architectures, detection engines combine identity hygiene data
   with real-time host authentication telemetry to identify adversary TTPs.

4. Example input:
   Auth logs showing 5 failed 4625 logons for 'sarah_finance' in 3 minutes,
   followed by successful 4624 logon from IP 192.168.1.45.

5. Example output:
   Structured IOC record:
   ioc_id="IOC-2026-003", ioc_type="AUTH_FAILURE_SPIKE", severity="HIGH",
   mitre_technique_id="T1110.001", defensive_action="Lock account, enforce MFA"
"""

import csv
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from sqlalchemy.orm import Session

from app.core import config
from app.models.authentication import AuthenticationEvent
from app.models.hash_record import HashRecord
from app.models.ioc import IOCRecord
from app.services.hash_analyzer import HashAnalyzer
from app.services.mitre_mapper import MitreMapper


class IOCDetector:
    """
    Core correlation and detection engine for Windows security telemetry.
    """

    @classmethod
    def ingest_authentication_logs(
        cls,
        csv_text_or_path: Union[str, Path, io.StringIO],
        db: Session
    ) -> Dict[str, Any]:
        """
        Parses Windows authentication event log CSV and persists records to SQLite.
        Expected columns: timestamp, username, source_machine, destination_machine, event_type, status, ip_address
        """
        if isinstance(csv_text_or_path, (str, Path)) and Path(str(csv_text_or_path)).is_file():
            with open(csv_text_or_path, mode="r", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
        elif isinstance(csv_text_or_path, io.StringIO):
            reader = list(csv.DictReader(csv_text_or_path))
        elif isinstance(csv_text_or_path, str):
            reader = list(csv.DictReader(io.StringIO(csv_text_or_path)))
        else:
            raise ValueError("Unsupported input format for authentication log ingestion.")

        if not reader:
            return {"error": "Authentication log CSV is empty or missing headers."}

        db.query(AuthenticationEvent).delete()
        imported_events = []

        for row in reader:
            ts_str = row.get("timestamp", "").strip()
            username = row.get("username", "").strip()
            src_machine = row.get("source_machine", "").strip()
            dst_machine = row.get("destination_machine", "").strip()
            event_type = row.get("event_type", "4624").strip()
            status = row.get("status", "SUCCESS").strip().upper()
            ip_address = row.get("ip_address", "192.168.1.1").strip()

            if ts_str:
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    ts = datetime.now()
            else:
                ts = datetime.now()

            # Baseline flags
            is_suspicious = False
            reasons = []

            # Check off-hours
            hour = ts.hour
            if hour >= config.UNUSUAL_HOUR_START or hour < config.UNUSUAL_HOUR_END:
                is_suspicious = True
                reasons.append(f"Off-hours authentication ({ts.strftime('%H:%M')})")

            # Check unknown source host
            if src_machine.upper() not in config.KNOWN_LAB_MACHINES:
                is_suspicious = True
                reasons.append(f"Unapproved source host: {src_machine}")

            if status == "FAILURE":
                reasons.append("Logon Failure (Event 4625)")

            event_obj = AuthenticationEvent(
                timestamp=ts,
                username=username,
                source_machine=src_machine,
                destination_machine=dst_machine,
                event_type=event_type,
                status=status,
                ip_address=ip_address,
                is_suspicious=is_suspicious,
                anomaly_reason="; ".join(reasons) if reasons else "Normal logon event"
            )
            imported_events.append(event_obj)

        db.add_all(imported_events)
        db.commit()

        return {
            "total_events_imported": len(imported_events),
            "suspicious_events_count": sum(1 for e in imported_events if e.is_suspicious),
            "failure_events_count": sum(1 for e in imported_events if e.status == "FAILURE")
        }

    @classmethod
    def run_full_detection_pipeline(cls, db: Session) -> List[IOCRecord]:
        """
        Executes the end-to-end IOC detection pipeline across both
        stored HashRecords and AuthenticationEvents.
        """
        # Clear existing IOCs before new analysis run
        db.query(IOCRecord).delete()

        iocs: List[IOCRecord] = []
        ioc_counter = 1

        def next_ioc_id() -> str:
            nonlocal ioc_counter
            curr_year = datetime.now().year
            res = f"IOC-{curr_year}-{ioc_counter:03d}"
            ioc_counter += 1
            return res

        # -------------------------------------------------------------
        # Phase 1: Hash-Based IOCs (Credential Reuse, Weak Hashes, Suspicious Machines)
        # -------------------------------------------------------------
        hash_records = db.query(HashRecord).all()
        reuse_clusters = HashAnalyzer.get_reuse_matrix(db)

        # 1A. Hash Reuse IOCs
        for cluster in reuse_clusters:
            accounts = cluster["affected_accounts"]
            has_priv = cluster["has_privileged_account"]
            severity = "CRITICAL" if has_priv or len(accounts) >= 3 else "HIGH"

            mitre = MitreMapper.map_ioc("HASH_REUSE")
            ioc = IOCRecord(
                ioc_id=next_ioc_id(),
                ioc_type="HASH_REUSE",
                severity=severity,
                mitre_technique_id=mitre["technique_id"],
                mitre_tactic=mitre["tactic"],
                username=", ".join(accounts),
                machine=", ".join(cluster["machines"]),
                timestamp=datetime.strptime(cluster["last_seen"], "%Y-%m-%d %H:%M:%S") if isinstance(cluster["last_seen"], str) else datetime.now(),
                description=f"Identical password hash shared across {len(accounts)} accounts ({', '.join(accounts)}).",
                evidence=(
                    f"SHA-256 Fingerprint: {cluster['hash_fingerprint'][:16]}... "
                    f"Shared between accounts: {', '.join(accounts)} across hosts: {', '.join(cluster['machines'])}. "
                    f"Privileged account involved: {has_priv}."
                ),
                defensive_action=mitre["defensive_recommendation"],
                status="ACTIVE"
            )
            iocs.append(ioc)

        # 1B. Known Weak Synthetic Hash IOCs
        for rec in hash_records:
            weak_desc = HashAnalyzer.check_known_weak_hash(rec.hash_value)
            if weak_desc:
                mitre = MitreMapper.map_ioc("ACCOUNT_ANOMALY", is_known_weak=True)
                ioc = IOCRecord(
                    ioc_id=next_ioc_id(),
                    ioc_type="ACCOUNT_ANOMALY",
                    severity="HIGH",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_tactic=mitre["tactic"],
                    username=rec.username,
                    machine=rec.machine,
                    timestamp=rec.timestamp,
                    description=f"Account '{rec.username}' configured with known weak test hash ({weak_desc}).",
                    evidence=f"Hash matches synthetic signature '{weak_desc}'. Host: {rec.machine}, Source: {rec.source}.",
                    defensive_action=mitre["defensive_recommendation"],
                    status="ACTIVE"
                )
                iocs.append(ioc)

        # 1C. Suspicious Machine / Unauthorized SAM Export
        for rec in hash_records:
            if HashAnalyzer.is_suspicious_source(rec.machine, rec.source):
                mitre = MitreMapper.map_ioc("SUSPICIOUS_MACHINE", is_suspicious_host=True)
                ioc = IOCRecord(
                    ioc_id=next_ioc_id(),
                    ioc_type="SUSPICIOUS_MACHINE",
                    severity="MEDIUM",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_tactic=mitre["tactic"],
                    username=rec.username,
                    machine=rec.machine,
                    timestamp=rec.timestamp,
                    description=f"Hash record for '{rec.username}' collected from unauthorized or unapproved host '{rec.machine}'.",
                    evidence=f"Host '{rec.machine}' is outside approved lab baselines. Source: '{rec.source}'.",
                    defensive_action=mitre["defensive_recommendation"],
                    status="ACTIVE"
                )
                iocs.append(ioc)

        # -------------------------------------------------------------
        # Phase 2: Authentication Telemetry IOCs
        # -------------------------------------------------------------
        auth_events = db.query(AuthenticationEvent).order_by(AuthenticationEvent.timestamp.asc()).all()

        # 2A. Password Spraying Detection (Multiple accounts failed from same IP)
        ip_failures: Dict[str, List[AuthenticationEvent]] = {}
        for ev in auth_events:
            if ev.status == "FAILURE":
                ip_failures.setdefault(ev.ip_address, []).append(ev)

        for ip, failures in ip_failures.items():
            targeted_users = {f.username for f in failures}
            if len(targeted_users) >= 4:
                # Password spraying signature detected
                mitre = MitreMapper.map_ioc("AUTH_FAILURE_SPIKE", is_spraying=True)
                earliest = min(f.timestamp for f in failures)
                latest = max(f.timestamp for f in failures)
                ioc = IOCRecord(
                    ioc_id=next_ioc_id(),
                    ioc_type="AUTH_FAILURE_SPIKE",
                    severity="CRITICAL",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_tactic=mitre["tactic"],
                    username=", ".join(sorted(list(targeted_users))),
                    machine=failures[0].source_machine,
                    timestamp=latest,
                    description=f"Password Spraying Attack detected from IP {ip} targeting {len(targeted_users)} accounts.",
                    evidence=(
                        f"Source IP {ip} generated {len(failures)} failed logons across accounts: "
                        f"{', '.join(sorted(list(targeted_users)))} between {earliest.strftime('%H:%M:%S')} and {latest.strftime('%H:%M:%S')}."
                    ),
                    defensive_action=mitre["defensive_recommendation"],
                    status="ACTIVE"
                )
                iocs.append(ioc)

        # 2B. Single Account Brute Force Failure Spike Detection
        # Group failures by username
        user_failures: Dict[str, List[AuthenticationEvent]] = {}
        for ev in auth_events:
            if ev.status == "FAILURE":
                user_failures.setdefault(ev.username, []).append(ev)

        for user, fails in user_failures.items():
            if len(fails) >= config.AUTH_FAILURE_SPIKE_THRESHOLD:
                # Verify if clustered in short window (e.g., within 10 minutes)
                fails_sorted = sorted(fails, key=lambda x: x.timestamp)
                span_minutes = (fails_sorted[-1].timestamp - fails_sorted[0].timestamp).total_seconds() / 60.0
                if span_minutes <= 15.0:
                    mitre = MitreMapper.map_ioc("AUTH_FAILURE_SPIKE", is_spraying=False)
                    ioc = IOCRecord(
                        ioc_id=next_ioc_id(),
                        ioc_type="AUTH_FAILURE_SPIKE",
                        severity="HIGH",
                        mitre_technique_id=mitre["technique_id"],
                        mitre_tactic=mitre["tactic"],
                        username=user,
                        machine=fails_sorted[0].source_machine,
                        timestamp=fails_sorted[-1].timestamp,
                        description=f"Logon failure burst ({len(fails)} failures in {span_minutes:.1f} mins) on account '{user}'.",
                        evidence=(
                            f"{len(fails)} consecutive Event 4625 logons against {fails_sorted[0].destination_machine} "
                            f"from IP {fails_sorted[0].ip_address}."
                        ),
                        defensive_action=mitre["defensive_recommendation"],
                        status="ACTIVE"
                    )
                    iocs.append(ioc)

        # 2C. Out-of-Hours Privileged Account Activity
        for ev in auth_events:
            hour = ev.timestamp.hour
            is_off_hour = hour >= config.UNUSUAL_HOUR_START or hour < config.UNUSUAL_HOUR_END
            is_priv = ev.username.lower() in config.PRIVILEGED_ACCOUNTS
            if is_off_hour and is_priv and ev.status == "SUCCESS":
                mitre = MitreMapper.map_ioc("UNUSUAL_LOGIN_TIME", is_off_hours=True)
                ioc = IOCRecord(
                    ioc_id=next_ioc_id(),
                    ioc_type="UNUSUAL_LOGIN_TIME",
                    severity="HIGH",
                    mitre_technique_id=mitre["technique_id"],
                    mitre_tactic=mitre["tactic"],
                    username=ev.username,
                    machine=ev.source_machine,
                    timestamp=ev.timestamp,
                    description=f"Privileged logon for '{ev.username}' outside baseline business hours ({ev.timestamp.strftime('%H:%M:%S')}).",
                    evidence=(
                        f"Successful Event 4624 logon to {ev.destination_machine} from {ev.source_machine} "
                        f"({ev.ip_address}) during off-hours window."
                    ),
                    defensive_action=mitre["defensive_recommendation"],
                    status="ACTIVE"
                )
                iocs.append(ioc)

        # 2D. Lateral Movement Burst
        # Detect single user accessing >= 4 distinct destination machines in a short window
        user_logons: Dict[str, List[AuthenticationEvent]] = {}
        for ev in auth_events:
            if ev.status == "SUCCESS":
                user_logons.setdefault(ev.username, []).append(ev)

        for user, successes in user_logons.items():
            destinations = {s.destination_machine for s in successes}
            if len(destinations) >= 4:
                mitre = MitreMapper.map_ioc("SUSPICIOUS_MACHINE", is_suspicious_host=True)
                ioc = IOCRecord(
                    ioc_id=next_ioc_id(),
                    ioc_type="SUSPICIOUS_MACHINE",
                    severity="HIGH",
                    mitre_technique_id="T1021.002",
                    mitre_tactic="Lateral Movement",
                    username=user,
                    machine=successes[0].source_machine,
                    timestamp=successes[-1].timestamp,
                    description=f"Potential Lateral Movement: Account '{user}' accessed {len(destinations)} distinct hosts rapidly.",
                    evidence=f"Hosts accessed: {', '.join(sorted(list(destinations)))} originating from {successes[0].source_machine}.",
                    defensive_action=mitre["defensive_recommendation"],
                    status="ACTIVE"
                )
                iocs.append(ioc)

        # Persist all detected IOCs
        db.add_all(iocs)
        db.commit()

        return iocs

    @classmethod
    def get_chronological_timeline(cls, db: Session) -> List[Dict[str, Any]]:
        """
        Builds a unified chronological timeline combining authentication events
        and detected IOC milestones for incident triage.
        """
        timeline = []

        # 1. Add authentication events
        auth_events = db.query(AuthenticationEvent).order_by(AuthenticationEvent.timestamp.asc()).all()
        for ev in auth_events:
            timeline.append({
                "type": "AUTH_EVENT",
                "id": ev.id,
                "timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "time_display": ev.timestamp.strftime("%H:%M:%S"),
                "title": f"Logon {ev.status}: {ev.username}",
                "severity": "MEDIUM" if ev.is_suspicious else "LOW",
                "details": f"{ev.event_type} from {ev.source_machine} ({ev.ip_address}) to {ev.destination_machine}",
                "is_suspicious": ev.is_suspicious,
                "username": ev.username,
                "machine": ev.source_machine
            })

        # 2. Add detected IOCs
        iocs = db.query(IOCRecord).order_by(IOCRecord.timestamp.asc()).all()
        for ioc in iocs:
            timeline.append({
                "type": "IOC_ALERT",
                "id": ioc.ioc_id,
                "timestamp": ioc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "time_display": ioc.timestamp.strftime("%H:%M:%S"),
                "title": f"🚨 {ioc.ioc_type}: {ioc.ioc_id}",
                "severity": ioc.severity,
                "details": ioc.description,
                "mitre": f"{ioc.mitre_technique_id} - {ioc.mitre_tactic}",
                "is_suspicious": True,
                "username": ioc.username,
                "machine": ioc.machine
            })

        # Sort combined timeline chronologically
        timeline.sort(key=lambda x: x["timestamp"])
        return timeline
