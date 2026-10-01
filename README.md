# Windows Password Hash Security Analysis & Blue Team SOC Platform
### Authorized Defensive Cybersecurity & Indicator of Compromise (IOC) Course Project

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI_0.110+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_19_+_Vite-61DAFB?logo=react)](https://react.dev)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)](https://attack.mitre.org)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Pytest](https://img.shields.io/badge/Tests-26_Passed-brightgreen?logo=pytest)](https://pytest.org)

---

## 1. Problem Statement & Motivation

Windows Active Directory and local SAM credential stores rely on cryptographic hashes (such as NTLM) for user authentication. In enterprise networks, password reuse across standard user workstations and privileged servers enables attackers to execute **Pass-the-Hash (PtH)** and lateral movement attacks without ever needing to recover the plaintext password.

Furthermore, traditional defensive monitoring often treats password audits and authentication event logs as separate silos. Security Operations Centers (SOCs) urgently need defensive correlation platforms that combine:
1. **Static Credential Hygiene Analysis** (detecting shared hashes, weak baseline hashes, and unapproved machines)
2. **Dynamic Authentication Telemetry Correlation** (detecting Event 4625 logon failure bursts, distributed password spraying, and off-hours administrative logins)
3. **MITRE ATT&CK Matrix Alignment** (mapping threat indicators directly to standardized tactics and defensive playbooks)

---

## 2. Ethical Guardrails & Legal Disclaimer

> [!IMPORTANT]
> **Strict Blue-Team & Educational Scope**:
> * This project is developed strictly for **authorized educational research, blue-team SOC defense, and academic coursework**.
> * **No Credential Dumping**: Does NOT dump SAM databases, read LSASS process memory, or implement Mimikatz functionality.
> * **No Password Cracking**: Does NOT perform dictionary attacks, brute-force cracking, rainbow table lookups, or plaintext credential recovery.
> * **Privacy-Preserving Fingerprinting**: Raw hashes are never shared in alerts; records are correlated via SHA-256 cryptographic fingerprints: $\text{SHA256}(\text{hash})$.
> * **Synthetic & Lab Telemetry**: All sample accounts, NTLM hashes, and private IP addresses (`192.168.1.0/24`, `10.0.0.0/8`) are fictional and generated inside a controlled lab environment.

---

## 3. Core Features

### 🛡️ 1. Executive SOC Dashboard
* Real-time metrics: Total hashes analyzed, unique hashes, duplicate hashes, weak synthetic hashes, high-risk accounts, and active IOCs.
* Severity distribution widgets: Categorization across **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL**.
* Live incident telemetry feed and engine status.

### 🔑 2. Hash Security & Credential Reuse Matrix
* **Format & Algorithm Validation**: Confirms 32-character hexadecimal NTLM format (128-bit) and flags malformed strings.
* **Cryptographic Fingerprinting**: Calculates case-normalized SHA-256 fingerprints for safe tracking.
* **Multi-Account Collision Detection**: Detects and groups identical hashes shared across distinct accounts (e.g., `administrator`, `svc_backup`, and `temp_admin`).
* **Privilege Escalation Risk Alerting**: Automatically escalates to `CRITICAL` whenever an administrative account shares a password hash with standard users.

### 🚨 3. IOC Detection & MITRE ATT&CK Mapping
* Standardized Threat Indicators: Every detection creates a unique identifier (e.g., `IOC-2026-001`) with evidence, host provenance, and severity.
* **MITRE ATT&CK Enterprise Matrix**:
  * `T1078.002` — Valid Accounts: Domain Accounts (Credential Reuse across hosts)
  * `T1078.003` — Valid Accounts: Local Accounts (Unauthorized Local SAM accounts)
  * `T1110.001` — Brute Force: Password Guessing (Rapid Event 4625 failure burst on single account)
  * `T1110.003` — Brute Force: Password Spraying (Distributed failures across multiple accounts from single IP)
  * `T1003.002` — OS Credential Dumping: SAM (Default/blank weak test hashes)
  * `T1021.002` — Remote Services: SMB / Windows Admin Shares (Logons from unapproved hosts)
  * `T1098` — Account Manipulation / Anomalous Access (Privileged logons during off-hours 20:00–06:00)
* Operational Triage: Status toggles (`ACTIVE` $\to$ `INVESTIGATING` $\to$ `RESOLVED`).

### 📊 4. Authentication Log Telemetry (Event IDs 4624 & 4625)
* Ingests and inspects Windows Security Event telemetry.
* Analyzes logon success vs. failure rates, burst frequency, and source machine baselines.
* Anomaly tagging for off-hours access and unapproved workstation origins.

### ⏱️ 5. Chronological Incident Attack Timeline
* Merges authentication events and triggered IOC alerts into a chronological sequence.
* Illustrates the simulated adversary attack lifecycle: Reconnaissance / Password Spraying $\to$ Brute-Force Burst $\to$ Successful Logon $\to$ Off-Hours Access $\to$ Lateral Movement.

### 📑 6. Security Reports & Defensive Playbooks
* Generates comprehensive Executive and Technical assessment reports.
* Actionable Blue Team Playbooks: Step-by-step containment instructions (LAPS deployment, MFA enforcement, GPO account lockout, host network isolation).
* One-click export in **Markdown (.md)**, **JSON data**, or printable format.

### 🧪 7. Lab Data Manager & Uploader
* One-click **Seed Standard Lab Datasets** button to reset and load simulated lab scenarios.
* Custom CSV file uploader for hash datasets and Windows event logs exported from student lab VMs.

---

## 4. System Architecture

```mermaid
graph TD
    subgraph Data_Sources [Lab Data Sources]
        H_CSV[sample_hashes.csv<br/>Synthetic NTLM records]
        A_CSV[sample_authentication_logs.csv<br/>Event 4624/4625 logs]
    end

    subgraph Core_Services [Analysis & Detection Core Services]
        HA[hash_analyzer.py<br/>Format Check, Fingerprinting, Collision Matrix]
        RE[risk_engine.py<br/>Configurable 0-100 Heuristics & Scoring]
        MITRE[mitre_mapper.py<br/>MITRE ATT&CK Matrix Alignment]
        IOC[ioc_detector.py<br/>Auth Telemetry Correlator & Timeline Engine]
        RG[report_generator.py<br/>Executive Report & Markdown Builder]
    end

    subgraph Storage [Persistence Layer SQLite]
        DB[(windows_security.db)]
    end

    subgraph API [FastAPI REST Backend]
        ROUTES[/api/dashboard, /api/hashes, /api/iocs, /api/timeline, /api/report]
    end

    subgraph UI [React SOC Frontend]
        SPA[Blue Team Cyber SOC Dark Dashboard<br/>React 19 + Lucide Icons]
    end

    H_CSV --> HA
    A_CSV --> IOC
    HA --> RE
    IOC --> RE
    RE --> MITRE
    MITRE --> DB
    HA --> DB
    IOC --> DB
    RG --> DB
    DB --> API
    API --> SPA
```

---

## 5. Risk Scoring Methodology (0–100 Scale)

The platform evaluates observable structural and behavioral properties using configurable additive weights:

$$\text{Risk Score} = \sum (\text{Weights}) \quad [\text{Clamped between } 0 \text{ and } 100]$$

| Observable Condition | Points | Rationale |
| :--- | :---: | :--- |
| **Duplicate Hash across Accounts** | `+30` | Credential hash observed under $>1$ distinct account. |
| **High Reuse ($\ge 3$ Accounts)** | `+30` | Widespread credential sharing across enterprise endpoints. |
| **Known Weak Test Hash** | `+20` | Matches baseline weak hashes (blank, 'password', 'admin'). |
| **Suspicious Machine / Source** | `+20` | Originating from an unverified or non-domain host. |
| **Abnormal Authentication Telemetry** | `+20` | Associated with failure bursts, spraying, or off-hours logons. |
| **Privileged Credential Sharing Modifier** | `+10` | Administrative account shares hash with lower-tier users. |

### Severity Categorization:
* `0 - 20`: **LOW** (Baseline normal hygiene)
* `21 - 40`: **MEDIUM** (Minor hygiene anomaly)
* `41 - 70`: **HIGH** (Significant credential exposure)
* `71 - 100`: **CRITICAL** (Immediate lateral movement / breach risk)

---

## 6. Directory Structure

```text
d:\EH ioc\
│
├── app/
│   ├── main.py                          # FastAPI entrypoint, lifespan auto-seeder, static mount
│   │
│   ├── api/                             # REST API route controllers
│   │   ├── dashboard.py                 # Summary stats, severity distribution, seed button
│   │   ├── hashes.py                    # Hash records listing, upload, reuse matrix
│   │   ├── iocs.py                      # IOC listing, details, and status triage
│   │   ├── authentication.py            # Event logs, timeline, and log upload
│   │   └── reports.py                   # Executive report data in JSON and Markdown
│   │
│   ├── core/                            # Database engine & global configuration
│   │   ├── config.py                    # Risk weights, thresholds, known weak hashes
│   │   └── database.py                  # SQLite engine, SessionLocal, get_db dependency
│   │
│   ├── models/                          # SQLAlchemy relational ORM models
│   │   ├── hash_record.py               # HashRecord model
│   │   ├── authentication.py            # AuthenticationEvent model
│   │   └── ioc.py                       # IOCRecord and AnalysisResult models
│   │
│   ├── services/                        # Business logic & detection engines
│   │   ├── hash_analyzer.py             # Format checking, fingerprinting, collision detection
│   │   ├── risk_engine.py               # Configurable 0-100 risk scoring
│   │   ├── mitre_mapper.py              # MITRE ATT&CK technique matrix mapping
│   │   ├── ioc_detector.py              # Multi-telemetry anomaly correlation engine
│   │   └── report_generator.py          # Executive and technical report generator
│   │
│   └── static/dist/                     # Production React SOC frontend bundle (JS + CSS)
│
├── frontend/                            # Modern React 19 Blue Team SOC Frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── DashboardView.jsx        # Executive dashboard & MITRE summary
│   │   │   ├── HashesView.jsx           # Hash search & visual reuse matrix
│   │   │   ├── IOCsView.jsx             # IOC triage & defensive playbooks modal
│   │   │   ├── AuthenticationView.jsx   # 4624/4625 telemetry & anomaly filters
│   │   │   ├── TimelineView.jsx         # Chronological incident attack timeline
│   │   │   ├── ReportsView.jsx          # Live executive report & markdown export
│   │   │   └── LabManagerView.jsx       # Sample dataset seeder & CSV upload
│   │   ├── App.jsx                      # Navigation sidebar & state orchestration
│   │   ├── index.css                    # Cyber SOC Dark Theme design system
│   │   └── main.jsx                     # React entrypoint
│   ├── build.js                         # Production bundler using esbuild
│   ├── package.json                     # Frontend dependencies
│   └── vite.config.js                   # Vite configuration with API proxy
│
├── data/                                # Lab synthetic datasets
│   ├── generate_datasets.py             # Data generator script
│   ├── sample_hashes.csv                # Synthetic Windows NTLM hashes
│   └── sample_authentication_logs.csv   # Synthetic Windows security event logs
│
├── tests/                               # Comprehensive automated test suite
│   ├── test_database.py                 # Database session & ORM CRUD tests
│   ├── test_dataset_generator.py        # Data generator & ethical constraint tests
│   ├── test_hash_analyzer.py            # Hash format, fingerprint, and reuse tests
│   ├── test_risk_engine.py              # Heuristic risk calculation & MITRE lookup tests
│   ├── test_ioc_detector.py             # Multi-telemetry anomaly & timeline tests
│   └── test_api.py                      # FastAPI REST endpoints integration tests
│
├── requirements.txt                     # Backend Python dependencies
├── README.md                            # Comprehensive project guide
└── .gitignore                           # Git ignore rules
```

---

## 7. Installation & Quick Start Guide

### Step 1: Clone or Navigate to Project
```powershell
cd "d:\EH ioc"
```

### Step 2: Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Run the SOC Application
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser and navigate to:
```text
http://127.0.0.1:8000
```

> [!TIP]
> The application **automatically seeds sample lab datasets and executes the detection pipeline on first startup** if the database is empty. You will be greeted immediately by a fully populated, glowing Cyber SOC Dashboard!

### Step 4: Interactive API Documentation (Swagger UI)
To explore and test the REST endpoints directly:
```text
http://127.0.0.1:8000/docs
```

---

## 8. Frontend Development (Optional)

If you wish to modify the React frontend:
```powershell
cd frontend
npm install
npm run build    # Builds bundle directly to app/static/dist
```

To run the Vite hot-reloading development server:
```powershell
npm run dev      # Starts dev server on http://localhost:3000 (proxies to :8000)
```

---

## 9. Running Automated Tests

Run the complete 26-test suite with full verbosity:
```powershell
python -m pytest tests/ -v
```

Expected output:
```text
============================= test session starts =============================
tests/test_api.py::test_api_dashboard_endpoint PASSED                    [  3%]
tests/test_api.py::test_api_mitre_matrix_endpoint PASSED                 [  7%]
tests/test_api.py::test_api_hashes_endpoints PASSED                      [ 11%]
tests/test_api.py::test_api_iocs_endpoints PASSED                        [ 15%]
tests/test_api.py::test_api_authentication_and_timeline_endpoints PASSED [ 19%]
tests/test_api.py::test_api_reports_endpoints PASSED                     [ 23%]
tests/test_database.py::test_hash_record_crud PASSED                     [ 26%]
tests/test_database.py::test_authentication_event_crud PASSED            [ 30%]
tests/test_database.py::test_ioc_and_analysis_result_crud PASSED         [ 34%]
tests/test_dataset_generator.py::test_hash_dataset_structure_and_constraints PASSED [ 38%]
tests/test_dataset_generator.py::test_authentication_logs_dataset_structure PASSED [ 42%]
tests/test_hash_analyzer.py::test_validate_hash_format PASSED            [ 46%]
tests/test_hash_analyzer.py::test_calculate_sha256_fingerprint PASSED    [ 50%]
tests/test_hash_analyzer.py::test_check_known_weak_hash PASSED           [ 53%]
tests/test_hash_analyzer.py::test_detect_reuse_clusters PASSED           [ 57%]
tests/test_hash_analyzer.py::test_csv_ingestion_and_db_persistence PASSED [ 61%]
tests/test_ioc_detector.py::test_authentication_log_ingestion PASSED     [ 65%]
tests/test_ioc_detector.py::test_ioc_detection_pipeline_and_mitre_mapping PASSED [ 69%]
tests/test_ioc_detector.py::test_chronological_timeline_generation PASSED [ 73%]
tests/test_ioc_detector.py::test_report_generator_json_and_markdown PASSED [ 76%]
tests/test_risk_engine.py::test_map_score_to_severity PASSED             [ 80%]
tests/test_risk_engine.py::test_calculate_score_clean_account PASSED     [ 84%]
tests/test_risk_engine.py::test_calculate_score_reuse_and_weak PASSED    [ 88%]
tests/test_risk_engine.py::test_calculate_score_critical_clamp PASSED    [ 92%]
tests/test_risk_engine.py::test_configurable_custom_weights PASSED       [ 96%]
tests/test_risk_engine.py::test_mitre_mapping_lookups PASSED             [100%]
======================== 26 passed in 1.2s ========================
```

---

## 10. College Course Viva Voce Questions & Answers

### Q1: What is an NTLM hash and how is it structured in Windows?
**A:** NTLM (NT LAN Manager) is a cryptographic credential representation used in Windows environments. It is calculated by encoding the password string in UTF-16LE and computing its MD4 hash: $\text{MD4}(\text{UTF-16LE}(\text{password}))$. The output is always a 128-bit value, represented as a 32-character hexadecimal string.

### Q2: Why is password hash reuse considered a critical vulnerability in Windows environments?
**A:** In Windows Active Directory, password hashes can be leveraged directly by adversaries in **Pass-the-Hash (PtH)** attacks (MITRE T1550.002) without needing plaintext passwords. If an administrative account (`administrator`) shares a hash with a service account (`svc_backup`) or standard user (`temp_admin`), compromising one endpoint gives the adversary administrative equivalency across the entire domain.

### Q3: Why does our defensive application calculate a SHA-256 fingerprint of the NTLM hash?
**A:** Sharing raw password hashes in ticketing systems, chat notifications, or reports introduces secondary security hazards. Calculating $\text{SHA256}(\text{raw\_hash})$ allows security analysts to publish, correlate, and index IOCs across SIEM/SOAR platforms without exposing the usable credential.

### Q4: What is the operational difference between Password Guessing (Brute Force) and Password Spraying?
**A:**
* **Password Guessing (T1110.001)**: Multiple password attempts directed against a *single targeted account*. This typically triggers Windows account lockout thresholds quickly.
* **Password Spraying (T1110.003)**: A small number of common passwords tested against *many different accounts* from a single host. Attackers use this to evade individual account lockout thresholds. Our engine detects this by correlating Event 4625 failures across multiple usernames from a single source IP.

### Q5: What Windows Security Event IDs are analyzed in this platform?
**A:**
* **Event ID 4624**: Successful Logon (shows logon type, user, source workstation, and IP).
* **Event ID 4625**: Logon Failure (shows failed account, workstation, and failure code).

### Q6: What blue-team defensive solutions prevent Pass-the-Hash lateral movement?
**A:**
1. **Microsoft LAPS (Local Administrator Password Solution)**: Automatically randomizes and manages unique passwords for local administrator accounts on every machine.
2. **Restricting Inbound SMB (Port 445)** between workstations via host firewalls.
3. **Multi-Factor Authentication (MFA)** and Tiered Administration (preventing Domain Admins from logging onto standard user workstations).

---

## 11. Project Presentation Points for Course Demonstration

When presenting this project to your professor, examiner, or class:

1. **Demonstrate the Architecture**:
   * Explain the defensive nature: no offensive SAM dumping or cracking, strictly authorized blue-team analysis.
2. **Show the Executive SOC Dashboard**:
   * Highlight the Cyber Dark theme, KPI stat cards, and the real-time **MITRE ATT&CK Matrix SOC Alignment** panel.
3. **Demonstrate the Credential Reuse Matrix**:
   * Navigate to *Hash Analysis* $\to$ *Credential Reuse Matrix*. Show the cluster where `administrator`, `svc_backup`, and `temp_admin` share the same hash, explaining how it enables lateral movement.
4. **Demonstrate IOC Triage & Playbooks**:
   * Navigate to *IOC Detections*. Click **View Defensive Remediation Playbook** on a Critical alert to display actionable PowerShell, GPO, and LAPS remediation instructions.
5. **Demonstrate the Chronological Attack Timeline**:
   * Walk through the simulated incident progression: Password Spray from `10.0.0.99` $\to$ Brute Force burst on `sarah_finance` $\to$ Off-hours logon at 02:45 AM from `WORKSTATION-X` $\to$ Lateral movement.
6. **Show One-Click Reporting**:
   * Download the complete **Markdown (.md)** report and showcase the executive summary and prioritized recommendations.
7. **Show Test Suite Verification**:
   * Run `python -m pytest tests/ -v` in terminal to prove 100% test passing coverage (26/26 tests).
