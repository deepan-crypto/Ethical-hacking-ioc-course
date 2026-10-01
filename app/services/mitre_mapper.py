"""
MITRE ATT&CK Mapping Module for Blue Team SOC Operations

1. What it does:
   Correlates detected security events and credential hygiene anomalies with
   the industry-standard MITRE ATT&CK Enterprise Matrix. Maps each IOC to tactics,
   techniques, sub-techniques, and actionable blue-team defensive playbooks.

2. Why it is required:
   Gives the project a professional SOC (Security Operations Center) posture.
   Security teams use MITRE ATT&CK to categorize adversary behaviors, assess coverage,
   and execute specific containment/remediation playbooks.

3. Cybersecurity concept demonstrated:
   Adversary TTP (Tactics, Techniques, and Procedures) Classification & Threat Intelligence.
   Instead of viewing an anomaly as an isolated error, mapping it to MITRE ATT&CK
   places it within an adversary's kill chain (e.g., Initial Access -> Credential Access -> Lateral Movement).

4. Example input:
   ioc_type="AUTH_FAILURE_SPIKE", is_spraying=False

5. Example output:
   {
       "technique_id": "T1110.001",
       "technique_name": "Brute Force: Password Guessing",
       "tactic": "Credential Access",
       "defensive_recommendation": "Lock out targeted account, enforce MFA challenge, inspect source IP for port scans."
   }
"""

from typing import Any, Dict, List, Optional

MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1078.002": {
        "technique_id": "T1078.002",
        "technique_name": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion / Lateral Movement / Persistence",
        "ioc_type": "HASH_REUSE",
        "description": "Adversary leverages shared domain password hashes to move laterally across workstations and servers.",
        "detection_rule": "Identical NTLM hash observed across multiple distinct domain accounts and hosts.",
        "defensive_recommendation": (
            "1. Force immediate password reset and rotate Kerberos TGT (krbtgt).\n"
            "2. Enforce unique local administrator passwords using Microsoft LAPS.\n"
            "3. Enforce Multi-Factor Authentication (MFA) on all interactive logons.\n"
            "4. Terminate active sessions and invalidate cached Kerberos tickets."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/002/"
    },
    "T1078.003": {
        "technique_id": "T1078.003",
        "technique_name": "Valid Accounts: Local Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "ioc_type": "ACCOUNT_ANOMALY",
        "description": "Unexpected or newly created local administrative account detected on a workstation or server.",
        "detection_rule": "Local SAM account observed with administrative privileges or unauthorized source.",
        "defensive_recommendation": (
            "1. Audit local administrators group on target host via PowerShell Get-LocalGroupMember.\n"
            "2. Disable unauthorized local accounts immediately.\n"
            "3. Implement centralized LAPS to prevent static local administrator passwords."
        ),
        "url": "https://attack.mitre.org/techniques/T1078/003/"
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "ioc_type": "AUTH_FAILURE_SPIKE",
        "description": "Adversary attempts multiple passwords against a single targeted user account in rapid succession.",
        "detection_rule": "Burst of Windows Event ID 4625 (Logon Failure) >= threshold on a single username within a short time window.",
        "defensive_recommendation": (
            "1. Enable account lockout policies after 5 failed attempts.\n"
            "2. Temporarily isolate source host IP from the authentication network.\n"
            "3. Notify user and enforce immediate password change and MFA challenge."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1110.003": {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "ioc_type": "AUTH_FAILURE_SPIKE",
        "description": "Adversary attempts a small number of commonly used passwords against a large list of domain accounts.",
        "detection_rule": "Event ID 4625 failures distributed across multiple unique usernames from a single source host/IP.",
        "defensive_recommendation": (
            "1. Block or quarantine the attacking IP at the internal firewall/switch level.\n"
            "2. Deploy smart lockout policies to prevent denial of service (DoS) on domain accounts.\n"
            "3. Audit affected accounts for successful logons following failed attempts."
        ),
        "url": "https://attack.mitre.org/techniques/T1110/003/"
    },
    "T1003.002": {
        "technique_id": "T1003.002",
        "technique_name": "OS Credential Dumping: Security Account Manager (SAM)",
        "tactic": "Credential Access",
        "ioc_type": "ACCOUNT_ANOMALY",
        "description": "Detection of default, blank, or well-known synthetic lab test hashes indicative of credential extraction or misconfigured test accounts.",
        "detection_rule": "Hash matches known test/default weak password hashes (e.g. blank password, 'password', 'admin').",
        "defensive_recommendation": (
            "1. Enforce minimum password complexity and length policies via Group Policy (GPO).\n"
            "2. Prevent blank password usage by enabling 'Accounts: Limit local account use of blank passwords'.\n"
            "3. Audit host for presence of credential dumping artifacts or memory inspection tools."
        ),
        "url": "https://attack.mitre.org/techniques/T1003/002/"
    },
    "T1021.002": {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "ioc_type": "SUSPICIOUS_MACHINE",
        "description": "Adversary leverages network shares (C$, ADMIN$) or remote logon from unapproved or non-standard machines.",
        "detection_rule": "Logon events originating from machines outside approved lab workstation baselines.",
        "defensive_recommendation": (
            "1. Restrict SMB v1 and require SMB signing / encryption.\n"
            "2. Block lateral SMB traffic between workstations using Windows Defender Firewall.\n"
            "3. Investigate the rogue host and isolate from the corporate VLAN."
        ),
        "url": "https://attack.mitre.org/techniques/T1021/002/"
    },
    "T1098": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation / Anomalous Access",
        "tactic": "Persistence / Privilege Escalation",
        "ioc_type": "UNUSUAL_LOGIN_TIME",
        "description": "Privileged account authentication occurs outside authorized operating hours (e.g., 2:00 AM).",
        "detection_rule": "Authentication events for privileged or administrative users during off-hours (20:00 - 06:00).",
        "defensive_recommendation": (
            "1. Verify with the account owner whether maintenance was scheduled.\n"
            "2. Revoke active tokens and force re-authentication with hardware MFA.\n"
            "3. Review Windows Security Event logs for child processes launched during the session."
        ),
        "url": "https://attack.mitre.org/techniques/T1098/"
    }
}


class MitreMapper:
    """
    Lookup engine mapping detection findings to MITRE ATT&CK techniques and blue team playbooks.
    """

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict[str, Any]]:
        """Returns details for a specific MITRE technique ID."""
        return MITRE_TECHNIQUES.get(technique_id)

    @classmethod
    def map_ioc(
        cls,
        ioc_type: str,
        is_spraying: bool = False,
        is_known_weak: bool = False,
        is_off_hours: bool = False,
        is_suspicious_host: bool = False
    ) -> Dict[str, Any]:
        """
        Maps an IOC type and context flags to the best-matching MITRE ATT&CK technique.
        """
        if is_spraying:
            return MITRE_TECHNIQUES["T1110.003"]
        elif ioc_type == "AUTH_FAILURE_SPIKE":
            return MITRE_TECHNIQUES["T1110.001"]
        elif is_off_hours or ioc_type == "UNUSUAL_LOGIN_TIME":
            return MITRE_TECHNIQUES["T1098"]
        elif is_known_weak:
            return MITRE_TECHNIQUES["T1003.002"]
        elif is_suspicious_host or ioc_type == "SUSPICIOUS_MACHINE":
            return MITRE_TECHNIQUES["T1021.002"]
        elif ioc_type == "ACCOUNT_ANOMALY":
            return MITRE_TECHNIQUES["T1078.003"]
        else:
            # Default for HASH_REUSE / PRIVILEGED_ACCOUNT_ACTIVITY
            return MITRE_TECHNIQUES["T1078.002"]

    @classmethod
    def get_all_matrix_techniques(cls) -> List[Dict[str, Any]]:
        """
        Returns all registered MITRE techniques for rendering the SOC ATT&CK matrix heatmap.
        """
        return list(MITRE_TECHNIQUES.values())
