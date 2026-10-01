"""
Security Report Generation Module

1. What it does:
   Aggregates hash analysis metrics, authentication telemetry statistics,
   detected IOC records, MITRE ATT&CK techniques, and prioritized blue-team
   defensive recommendations into executive and technical security reports.

2. Why it is required:
   Security assessments and incident responses require standardized documentation
   for CISO / management review and operational remediation tracking.

3. Cybersecurity concept demonstrated:
   Defensive Security Reporting & Remediation Playbooks.
   A cybersecurity analysis is only as good as its operational impact. Structuring
   findings by severity and providing direct GPO/PowerShell/MFA remediation steps
   ensures rapid blue-team containment.

4. Example input:
   Active database session with ingested hashes, auth logs, and detected IOCs.

5. Example output:
   Complete JSON structure, formatted Markdown document, and printable HTML summary.
"""

from datetime import datetime
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.models.authentication import AuthenticationEvent
from app.models.hash_record import HashRecord
from app.models.ioc import IOCRecord
from app.services.hash_analyzer import HashAnalyzer


class ReportGenerator:
    """
    Generates executive and technical blue-team cybersecurity reports.
    """

    @classmethod
    def generate_full_report_data(cls, db: Session) -> Dict[str, Any]:
        """
        Compiles all findings, telemetry, and remediation playbooks into a dictionary.
        """
        # Fetch all records
        hash_records = db.query(HashRecord).all()
        auth_events = db.query(AuthenticationEvent).all()
        iocs = db.query(IOCRecord).order_by(IOCRecord.severity.desc(), IOCRecord.timestamp.desc()).all()
        reuse_clusters = HashAnalyzer.get_reuse_matrix(db)

        # 1. Executive Summary Metrics
        total_hashes = len(hash_records)
        unique_hashes = len({r.hash_value for r in hash_records})
        duplicate_hashes = total_hashes - unique_hashes
        high_risk_findings = sum(1 for r in hash_records if r.risk_level in ["HIGH", "CRITICAL"])
        total_iocs = len(iocs)
        critical_iocs = sum(1 for i in iocs if i.severity == "CRITICAL")
        high_iocs = sum(1 for i in iocs if i.severity == "HIGH")

        # Affected accounts
        affected_accounts_set = set()
        for c in reuse_clusters:
            affected_accounts_set.update(c["affected_accounts"])
        for i in iocs:
            if i.username:
                for u in i.username.split(","):
                    affected_accounts_set.add(u.strip())

        # 2. Hash Analysis Details
        hash_types: Dict[str, int] = {}
        for r in hash_records:
            hash_types[r.hash_type] = hash_types.get(r.hash_type, 0) + 1

        weak_hashes = [r.to_dict() for r in hash_records if "Weak" in (r.notes or "")]
        suspicious_records = [r.to_dict() for r in hash_records if "Suspicious" in (r.notes or "")]

        # 3. Authentication Telemetry Details
        total_logons = len(auth_events)
        successful_logons = sum(1 for e in auth_events if e.status == "SUCCESS")
        failed_logons = sum(1 for e in auth_events if e.status == "FAILURE")
        suspicious_logons = sum(1 for e in auth_events if e.is_suspicious)

        # 4. Standardized Defensive Recommendations
        recommendations = [
            {
                "title": "Immediate Credential Invalidation & Password Rotation",
                "priority": "CRITICAL",
                "target": "Accounts with detected hash reuse and known weak test hashes",
                "rationale": "Shared hashes allow adversaries to execute Pass-the-Hash (PtH) lateral movement.",
                "action": "Force mandatory password changes on next logon across Active Directory."
            },
            {
                "title": "Deploy Microsoft Local Administrator Password Solution (LAPS)",
                "priority": "CRITICAL",
                "target": "All domain-joined workstations and member servers",
                "rationale": "Prevents administrative hash reuse across workstations, containing local breaches.",
                "action": "Implement Windows LAPS via GPO to rotate local administrator passwords automatically."
            },
            {
                "title": "Mandate Multi-Factor Authentication (MFA)",
                "priority": "HIGH",
                "target": "All user and administrative logons",
                "rationale": "Mitigates password guessing and password spraying attacks (MITRE T1110).",
                "action": "Enforce FIDO2 / Authenticator MFA for all interactive and VPN logons."
            },
            {
                "title": "Configure Account Lockout & Smart Lockout Policies",
                "priority": "HIGH",
                "target": "Active Directory Group Policy",
                "rationale": "Halts brute-force bursts (MITRE T1110.001) while minimizing Denial of Service risk.",
                "action": "Set lockout threshold to 5 invalid attempts with a 30-minute observation window."
            },
            {
                "title": "Network Segmentation & Lateral Movement Containment",
                "priority": "MEDIUM",
                "target": "Workstation-to-workstation SMB traffic (Port 445)",
                "rationale": "Prevents lateral movement from rogue hosts (MITRE T1021.002).",
                "action": "Block inbound TCP 445 between endpoints using host-based Windows Firewall."
            },
            {
                "title": "Enhance Windows Security Auditing (Advanced Audit Policies)",
                "priority": "MEDIUM",
                "target": "All domain controllers and critical infrastructure",
                "rationale": "Provides visibility into Logon/Logoff (4624/4625), Kerberos TGS/TGT requests (4768/4769).",
                "action": "Enable Audit Credential Validation, Audit Kerberos Authentication, and Audit User Account Management."
            }
        ]

        return {
            "report_metadata": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "report_title": "Windows Password Hash Security Analysis & Blue Team SOC Report",
                "classification": "AUTHORIZED LAB SECURITY AUDIT - RESTRICTED",
                "author": "Blue Team Defensive SOC Automation Engine"
            },
            "executive_summary": {
                "total_hashes_analyzed": total_hashes,
                "unique_hashes": unique_hashes,
                "duplicate_hashes": duplicate_hashes,
                "high_risk_findings": high_risk_findings,
                "total_iocs_detected": total_iocs,
                "critical_iocs": critical_iocs,
                "high_iocs": high_iocs,
                "total_affected_accounts": len(affected_accounts_set),
                "affected_accounts": sorted(list(affected_accounts_set))
            },
            "hash_analysis": {
                "hash_types_distribution": hash_types,
                "reused_clusters_count": len(reuse_clusters),
                "reused_clusters": reuse_clusters,
                "weak_hashes_count": len(weak_hashes),
                "weak_hashes": weak_hashes,
                "suspicious_records_count": len(suspicious_records)
            },
            "authentication_analysis": {
                "total_events": total_logons,
                "successful_logons": successful_logons,
                "failed_logons": failed_logons,
                "failure_rate_pct": round((failed_logons / total_logons * 100), 1) if total_logons > 0 else 0,
                "suspicious_events": suspicious_logons
            },
            "ioc_findings": [ioc.to_dict() for ioc in iocs],
            "recommendations": recommendations
        }

    @classmethod
    def generate_markdown_report(cls, db: Session) -> str:
        """
        Builds a complete, professional GitHub-flavored Markdown security assessment report.
        """
        data = cls.generate_full_report_data(db)
        meta = data["report_metadata"]
        exec_s = data["executive_summary"]
        hash_s = data["hash_analysis"]
        auth_s = data["authentication_analysis"]
        iocs = data["ioc_findings"]
        recs = data["recommendations"]

        md = []
        md.append(f"# {meta['report_title']}")
        md.append(f"**Classification:** `{meta['classification']}`  ")
        md.append(f"**Generated At:** `{meta['generated_at']}` | **Author:** `{meta['author']}`\n")
        md.append("---\n")

        # Executive Summary
        md.append("## 1. Executive Summary")
        md.append("This report summarizes the defensive security analysis of synthetic Windows password hashes ")
        md.append("and authentication event logs collected from a controlled laboratory environment.\n")

        md.append("| Metric | Value | Security Assessment |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Total Hashes Analyzed** | `{exec_s['total_hashes_analyzed']}` | Baseline dataset coverage |")
        md.append(f"| **Unique Hashes** | `{exec_s['unique_hashes']}` | Entropy baseline |")
        md.append(f"| **Duplicate Hashes** | `{exec_s['duplicate_hashes']}` | Redundancy detected |")
        md.append(f"| **High/Critical Risk Findings** | `{exec_s['high_risk_findings']}` | Immediate action required |")
        md.append(f"| **Total Detected IOCs** | `{exec_s['total_iocs_detected']}` | Threats identified |")
        md.append(f"| **Critical Severity IOCs** | `{exec_s['critical_iocs']}` | Top incident response priority |")
        md.append(f"| **Total Affected Accounts** | `{exec_s['total_affected_accounts']}` | Accounts requiring credential rotation |\n")

        # Hash Analysis
        md.append("## 2. Password Hash Hygiene & Reuse Analysis")
        md.append(f"* **Reused Credential Clusters Detected:** `{hash_s['reused_clusters_count']}`")
        md.append(f"* **Known Weak Test Hashes:** `{hash_s['weak_hashes_count']}`\n")

        if hash_s["reused_clusters"]:
            md.append("### Credential Reuse Matrix")
            md.append("| Fingerprint (SHA-256) | Affected Accounts | Host Machines | Risk Level |")
            md.append("| :--- | :--- | :--- | :--- |")
            for c in hash_s["reused_clusters"]:
                md.append(f"| `{c['hash_fingerprint'][:16]}...` | {', '.join(c['affected_accounts'])} | {', '.join(c['machines'])} | **{c['risk_level']}** |")
            md.append("")

        # Authentication Analysis
        md.append("## 3. Authentication Telemetry & Anomaly Analysis")
        md.append("| Telemetry Metric | Event Count | Percentage |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| Total Authentication Events | `{auth_s['total_events']}` | 100% |")
        md.append(f"| Successful Logons (Event 4624) | `{auth_s['successful_logons']}` | {100 - auth_s['failure_rate_pct']:.1f}% |")
        md.append(f"| Failed Logons (Event 4625) | `{auth_s['failed_logons']}` | {auth_s['failure_rate_pct']}% |")
        md.append(f"| Suspicious/Anomalous Logons | `{auth_s['suspicious_events']}` | - |\n")

        # Detailed IOC Findings
        md.append("## 4. Indicators of Compromise (IOC) Findings")
        for ioc in iocs:
            md.append(f"### 🚨 [{ioc['severity']}] {ioc['ioc_id']}: {ioc['ioc_type']}")
            md.append(f"* **MITRE ATT&CK:** `{ioc['mitre_technique_id']}` ({ioc['mitre_tactic']})")
            md.append(f"* **Account(s):** `{ioc['username']}` | **Machine(s):** `{ioc['machine']}`")
            md.append(f"* **Timestamp:** `{ioc['timestamp']}` | **Status:** `{ioc['status']}`")
            md.append(f"* **Description:** {ioc['description']}")
            md.append(f"* **Evidence:** `{ioc['evidence']}`")
            md.append(f"* **Defensive Playbook Action:**\n```text\n{ioc['defensive_action']}\n```\n")

        # Recommendations
        md.append("## 5. Prioritized Defensive Blue-Team Recommendations\n")
        for idx, rec in enumerate(recs, 1):
            md.append(f"### {idx}. {rec['title']} (`{rec['priority']}`)")
            md.append(f"* **Target:** {rec['target']}")
            md.append(f"* **Rationale:** {rec['rationale']}")
            md.append(f"* **Action:** {rec['action']}\n")

        return "\n".join(md)
