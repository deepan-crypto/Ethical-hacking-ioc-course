"""
Configuration Module: App Settings, Security Thresholds & Risk Weights

1. What it does:
   Centralizes all configuration variables, risk scoring weights, severity thresholds,
   database paths, and baseline anomaly detection parameters for the SOC analysis engine.

2. Why it is required:
   Keeps detection rules maintainable and configurable without hardcoding magic numbers
   directly into analyzer algorithms. Allows blue team analysts to tune sensitivity.

3. Cybersecurity concept demonstrated:
   Detection engineering and configurable rule baselines (similar to SIEM threshold tuning).
   In security monitoring, thresholds (e.g., failure burst counts, off-hours windows)
   must be adjustable per enterprise environment to minimize False Positives (FP).

4. Example input:
   RiskEngine querying `config.WEIGHT_HASH_REUSE` -> returns 30
   Analyzer comparing score 45 against thresholds -> classified as "HIGH"
"""

import os
from pathlib import Path
from typing import Dict, List, Set

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = BASE_DIR / "windows_security.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Application Metadata
APP_TITLE = "Windows Password Hash Security Analysis & Blue Team SOC"
APP_DESCRIPTION = (
    "Defensive cybersecurity course project demonstrating Windows hash risk analysis, "
    "credential reuse detection, authentication log correlation, and MITRE ATT&CK mapped IOCs."
)
APP_VERSION = "1.0.0"

# Educational Disclaimer
DISCLAIMER = (
    "DISCLAIMER: This application is developed strictly for authorized academic security research, "
    "cybersecurity education, and blue-team analysis. It uses synthetic/demo lab data. "
    "Risk scores represent educational heuristics, not Microsoft security ratings."
)

# Risk Scoring Weights (Configurable 0-100 scale)
WEIGHT_HASH_REUSE = 30           # Hash observed across multiple distinct user accounts
WEIGHT_MANY_USERS = 30           # Hash shared by 3 or more user accounts
WEIGHT_KNOWN_WEAK_HASH = 20      # Hash matches known test/default weak password hashes
WEIGHT_SUSPICIOUS_SOURCE = 20    # Hash imported from an unexpected/external or non-domain host
WEIGHT_ABNORMAL_AUTH = 20        # Account associated with authentication failure spikes or anomalies

# Severity Classification Thresholds
# Score Mapping:
# 0-20:   LOW
# 21-40:  MEDIUM
# 41-70:  HIGH
# 71-100: CRITICAL
SEVERITY_THRESHOLDS = {
    "LOW": (0, 20),
    "MEDIUM": (21, 40),
    "HIGH": (41, 70),
    "CRITICAL": (71, 100),
}

# Baseline Authentication Anomaly Detection Thresholds
AUTH_FAILURE_SPIKE_THRESHOLD = 3   # 3 or more failed logons (4625) within a short window
UNUSUAL_HOUR_START = 20            # 8:00 PM (20:00) - Start of off-hours window
UNUSUAL_HOUR_END = 6               # 6:00 AM (06:00) - End of off-hours window

# Baseline Normal Workstations (Controlled Lab Environment)
KNOWN_LAB_MACHINES: Set[str] = {
    "LAB-DC-01",
    "LAB-PC-01",
    "LAB-PC-02",
    "LAB-PC-03",
    "LAB-SRV-01",
    "LAB-FILE-01"
}

# Standard Privileged / Administrative Account Names to Monitor
PRIVILEGED_ACCOUNTS: Set[str] = {
    "administrator",
    "admin",
    "domain_admin",
    "root",
    "krbtgt",
    "svc_backup",
    "sec_admin"
}

# Known synthetic test hashes (Educational weak list - safe synthetic representations)
# E.g. NTLM for common lab test passwords: blank, "password", "admin", "123456", "welcome"
KNOWN_WEAK_SYNTHETIC_HASHES: Dict[str, str] = {
    "31d6cfe0d16ae931b73c59d7e0c089c0": "Blank / Empty Password Hash",
    "8846f7eaee8fb117ad06bdd830b7586c": "Common Lab Password ('password')",
    "209c614c407035e1d4b182376bd6656a": "Default Admin Password ('admin')",
    "329153f560eb329c0e1deea55e88a1e9": "Sequential Test Password ('123456')",
    "c8a149171e2ef6408b04a884d8f89ef9": "Default Lab Welcome Password ('welcome')"
}
