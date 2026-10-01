"""
Hash Analysis Engine Module

1. What it does:
   - Validates password hash formatting and identifies probable algorithm types.
   - Calculates cryptographic SHA-256 fingerprints for privacy-preserving tracking.
   - Identifies duplicate hash entries within imported datasets.
   - Discovers cross-account hash reuse (same hash value used by multiple accounts).
   - Detects matches against known educational weak synthetic hashes (e.g., blank, default).
   - Evaluates machine and provenance anomalies.
   - Ingests CSV datasets into the SQLite database.

2. Why it is required:
   Password reuse across corporate environments is a primary enabler of lateral movement
   (e.g., Pass-the-Hash / PtH attacks). This engine detects credential vulnerabilities
   without ever attempting unauthorized password cracking.

3. Cybersecurity concept demonstrated:
   Defensive Credential Hygiene Analysis & Collision Detection.
   Instead of trying to crack passwords (which violates the defensive scope),
   the blue team analyzes structural properties: hash entropy, collisions,
   multi-account sharing, and provenance indicators.

4. Example input:
   Record: username="svc_backup", hash="b45cffe0e4c5b3671234a4918732168a", machine="LAB-SRV-01"
   When compared with: username="administrator", hash="b45cffe0e4c5b3671234a4918732168a"

5. Example output:
   Detection of HASH_REUSE between administrator and svc_backup.
   Hash Fingerprint: "5e2b6..."
   Risk Level: "CRITICAL" (privileged account collision)
"""

import csv
import hashlib
import io
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy.orm import Session

from app.core.config import (
    KNOWN_WEAK_SYNTHETIC_HASHES,
    KNOWN_LAB_MACHINES,
    PRIVILEGED_ACCOUNTS
)
from app.models.hash_record import HashRecord

# Hex pattern matching
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")


class HashAnalyzer:
    """
    Core defensive engine for evaluating Windows password hash security properties.
    """

    @staticmethod
    def validate_hash_format(hash_value: str) -> Tuple[bool, str, str]:
        """
        Validates whether a hash string has valid hexadecimal encoding
        and identifies the probable hash algorithm based on bit length.

        Returns: (is_valid: bool, identified_type: str, message: str)
        """
        if not hash_value or not isinstance(hash_value, str):
            return False, "UNKNOWN", "Empty or non-string hash value provided."

        clean_hash = hash_value.strip()

        if not HEX_PATTERN.match(clean_hash):
            return False, "INVALID", "Hash contains non-hexadecimal characters."

        length = len(clean_hash)

        if length == 32:
            # 128-bit: Standard Windows NTLM (or legacy LM / MD5 / MD4)
            return True, "NTLM", "Valid 32-character hexadecimal format (Windows NTLM / 128-bit)."
        elif length == 40:
            return True, "SHA-1", "Valid 40-character hexadecimal format (SHA-1 / 160-bit)."
        elif length == 64:
            return True, "SHA-256", "Valid 64-character hexadecimal format (SHA-256 / 256-bit)."
        elif length == 128:
            return True, "SHA-512", "Valid 128-character hexadecimal format (SHA-512 / 512-bit)."
        else:
            return False, "UNKNOWN", f"Unexpected hash length of {length} characters. Expected 32 for NTLM."

    @staticmethod
    def calculate_sha256_fingerprint(hash_value: str) -> str:
        """
        Calculates a SHA-256 fingerprint of the hash value.

        Educational concept:
        In security operations (SOC), analysts avoid sharing or storing raw password
        hashes in external ticketing or logging systems. Instead, they calculate and log
        a cryptographic SHA-256 fingerprint: SHA256(raw_hash).
        """
        normalized = hash_value.strip().lower().encode("utf-8")
        return hashlib.sha256(normalized).hexdigest()

    @staticmethod
    def check_known_weak_hash(hash_value: str) -> Optional[str]:
        """
        Checks if the hash matches a known synthetic educational weak hash
        (e.g., blank password, 'password', 'admin').
        """
        normalized = hash_value.strip().lower()
        return KNOWN_WEAK_SYNTHETIC_HASHES.get(normalized, None)

    @staticmethod
    def is_suspicious_source(machine: str, source: str) -> bool:
        """
        Determines if the hash originates from an unrecognized lab machine
        or an unauthorized export source.
        """
        machine_clean = machine.strip().upper() if machine else ""
        source_clean = source.strip().upper() if source else ""

        if machine_clean and machine_clean not in KNOWN_LAB_MACHINES:
            return True
        if "UNAUTHORIZED" in source_clean or "SHADOW" in source_clean:
            return True
        return False

    @classmethod
    def analyze_record(cls, record_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs structural inspection on an individual record dictionary.
        """
        raw_hash = str(record_data.get("hash", "")).strip()
        username = str(record_data.get("username", "")).strip()
        machine = str(record_data.get("machine", "")).strip()
        source = str(record_data.get("source", "LAB_IMPORT")).strip()

        is_valid, hash_type, format_msg = cls.validate_hash_format(raw_hash)
        fingerprint = cls.calculate_sha256_fingerprint(raw_hash) if is_valid else ""
        weak_description = cls.check_known_weak_hash(raw_hash) if is_valid else None
        suspicious_src = cls.is_suspicious_source(machine, source)
        is_privileged = username.lower() in PRIVILEGED_ACCOUNTS

        return {
            "is_valid": is_valid,
            "hash_type": hash_type,
            "format_message": format_msg,
            "hash_fingerprint": fingerprint,
            "is_known_weak": weak_description is not None,
            "weak_description": weak_description,
            "is_suspicious_source": suspicious_src,
            "is_privileged_user": is_privileged,
        }

    @classmethod
    def detect_reuse_clusters(cls, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identifies all instances where the same hash value is shared across
        two or more distinct user accounts.

        Returns a list of reuse cluster summaries with:
        - hash_fingerprint
        - affected_accounts (sorted list of unique usernames)
        - affected_count
        - machines involved
        - has_privileged_account (True if any admin/privileged user is affected)
        - risk_level (CRITICAL if privileged or count >= 3, else HIGH)
        - first_seen & last_seen timestamps
        """
        clusters: Dict[str, Dict[str, Any]] = {}

        for rec in records:
            raw_hash = str(rec.get("hash", "")).strip().lower()
            if not raw_hash or len(raw_hash) != 32:
                continue

            username = str(rec.get("username", "")).strip()
            machine = str(rec.get("machine", "")).strip()
            ts_val = rec.get("timestamp")

            if isinstance(ts_val, str):
                try:
                    ts = datetime.strptime(ts_val, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    ts = datetime.now()
            elif isinstance(ts_val, datetime):
                ts = ts_val
            else:
                ts = datetime.now()

            fingerprint = cls.calculate_sha256_fingerprint(raw_hash)

            if fingerprint not in clusters:
                clusters[fingerprint] = {
                    "hash_fingerprint": fingerprint,
                    "raw_hash": raw_hash,
                    "accounts": set(),
                    "machines": set(),
                    "first_seen": ts,
                    "last_seen": ts,
                    "known_weak_note": cls.check_known_weak_hash(raw_hash)
                }

            clusters[fingerprint]["accounts"].add(username)
            if machine:
                clusters[fingerprint]["machines"].add(machine)
            if ts < clusters[fingerprint]["first_seen"]:
                clusters[fingerprint]["first_seen"] = ts
            if ts > clusters[fingerprint]["last_seen"]:
                clusters[fingerprint]["last_seen"] = ts

        # Filter only clusters where hash is reused across >= 2 different usernames
        reused_list = []
        for fp, data in clusters.items():
            if len(data["accounts"]) > 1:
                accounts_sorted = sorted(list(data["accounts"]))
                has_priv = any(u.lower() in PRIVILEGED_ACCOUNTS for u in accounts_sorted)

                if has_priv or len(accounts_sorted) >= 3:
                    risk_level = "CRITICAL"
                else:
                    risk_level = "HIGH"

                reused_list.append({
                    "hash_fingerprint": fp,
                    "hash_display": f"{data['raw_hash'][:6]}...{data['raw_hash'][-6:]}",
                    "raw_hash": data["raw_hash"],
                    "affected_accounts": accounts_sorted,
                    "affected_count": len(accounts_sorted),
                    "machines": sorted(list(data["machines"])),
                    "has_privileged_account": has_priv,
                    "risk_level": risk_level,
                    "first_seen": data["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": data["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                    "known_weak_note": data["known_weak_note"]
                })

        # Sort by affected count descending, then risk level
        reused_list.sort(key=lambda x: (x["risk_level"] == "CRITICAL", x["affected_count"]), reverse=True)
        return reused_list

    @classmethod
    def ingest_csv_content(cls, csv_text_or_path: Union[str, Path, io.StringIO], db: Session) -> Dict[str, Any]:
        """
        Parses CSV input, runs structural checks, detects reuse clusters,
        computes baseline properties, and persists records to the SQLite database.

        Expected CSV columns:
        username, hash_type, hash, machine, source, timestamp
        """
        if isinstance(csv_text_or_path, (str, Path)) and Path(str(csv_text_or_path)).is_file():
            with open(csv_text_or_path, mode="r", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
        elif isinstance(csv_text_or_path, io.StringIO):
            reader = list(csv.DictReader(csv_text_or_path))
        elif isinstance(csv_text_or_path, str):
            reader = list(csv.DictReader(io.StringIO(csv_text_or_path)))
        else:
            raise ValueError("Unsupported input format for CSV ingestion.")

        if not reader:
            return {"error": "CSV file is empty or missing headers."}

        # First pass: collect raw records and identify reuse clusters across the batch
        reuse_clusters = cls.detect_reuse_clusters(reader)
        reuse_map = {c["raw_hash"]: c for c in reuse_clusters}

        imported_records = []
        unique_hashes = set()
        duplicate_records = 0
        weak_count = 0

        for row in reader:
            username = row.get("username", "").strip()
            raw_hash = row.get("hash", "").strip().lower()
            machine = row.get("machine", "LAB-PC-01").strip()
            source = row.get("source", "LAB_IMPORT").strip()
            hash_type_input = row.get("hash_type", "NTLM").strip()
            ts_str = row.get("timestamp", "").strip()

            is_valid, detected_type, _ = cls.validate_hash_format(raw_hash)
            if not is_valid:
                continue

            fingerprint = cls.calculate_sha256_fingerprint(raw_hash)

            if raw_hash in unique_hashes:
                duplicate_records += 1
            else:
                unique_hashes.add(raw_hash)

            weak_note = cls.check_known_weak_hash(raw_hash)
            if weak_note:
                weak_count += 1

            # Parse timestamp
            if ts_str:
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    ts = datetime.now()
            else:
                ts = datetime.now()

            # Determine reuse status
            cluster_info = reuse_map.get(raw_hash)
            is_reused = cluster_info is not None
            reuse_cnt = cluster_info["affected_count"] if cluster_info else 1

            # Calculate preliminary risk properties
            suspicious_src = cls.is_suspicious_source(machine, source)
            is_priv = username.lower() in PRIVILEGED_ACCOUNTS

            # Score calculation
            score = 0
            notes_list = []
            if is_reused:
                score += 30
                notes_list.append(f"Hash shared by {reuse_cnt} accounts")
                if reuse_cnt >= 3:
                    score += 30
                    notes_list.append("Widely reused credential (>= 3 users)")
            if weak_note:
                score += 20
                notes_list.append(f"Weak Hash: {weak_note}")
            if suspicious_src:
                score += 20
                notes_list.append(f"Suspicious host/source: {machine}/{source}")
            if is_priv and is_reused:
                score += 20
                notes_list.append("Privileged account password reuse")

            score = min(score, 100)

            if score >= 71:
                risk_lvl = "CRITICAL"
            elif score >= 41:
                risk_lvl = "HIGH"
            elif score >= 21:
                risk_lvl = "MEDIUM"
            else:
                risk_lvl = "LOW"

            notes = "; ".join(notes_list) if notes_list else "Normal synthetic lab account."

            hash_rec = HashRecord(
                username=username,
                hash_type=detected_type if detected_type != "UNKNOWN" else hash_type_input,
                hash_value=raw_hash,
                hash_fingerprint=fingerprint,
                machine=machine,
                source=source,
                timestamp=ts,
                is_reused=is_reused,
                reuse_count=reuse_cnt,
                risk_score=score,
                risk_level=risk_lvl,
                notes=notes
            )
            imported_records.append(hash_rec)

        # Clear existing hash records or insert newly analyzed batch
        db.query(HashRecord).delete()
        db.add_all(imported_records)
        db.commit()

        return {
            "total_records_processed": len(reader),
            "total_imported": len(imported_records),
            "unique_hashes": len(unique_hashes),
            "duplicate_records": duplicate_records,
            "reused_clusters_detected": len(reuse_clusters),
            "weak_hashes_detected": weak_count,
            "reused_clusters": reuse_clusters
        }

    @classmethod
    def get_reuse_matrix(cls, db: Session) -> List[Dict[str, Any]]:
        """
        Queries all records currently in the database and returns the full
        reuse matrix for dashboard and reporting display.
        """
        records = db.query(HashRecord).all()
        dict_records = [
            {
                "username": r.username,
                "hash": r.hash_value,
                "machine": r.machine,
                "source": r.source,
                "timestamp": r.timestamp
            }
            for r in records
        ]
        return cls.detect_reuse_clusters(dict_records)
