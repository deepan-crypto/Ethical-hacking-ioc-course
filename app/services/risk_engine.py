"""
Risk Scoring Engine Module

1. What it does:
   Evaluates observable security properties of password hashes and accounts,
   applying configurable additive weights to calculate a cumulative risk score
   (0-100) and maps the score to standardized severity levels (LOW, MEDIUM, HIGH, CRITICAL).

2. Why it is required:
   Provides security analysts with an objective, quantified prioritization metric
   so high-risk credential hygiene violations (e.g., domain admin credential reuse)
   are flagged immediately for incident response.

3. Cybersecurity concept demonstrated:
   Heuristic Risk Modeling & Threat Prioritization.
   In modern Security Operations Centers (SOCs), alert fatigue is mitigated by
   scoring events based on environmental context (privilege level, machine provenance,
   multi-account exposure, authentication baseline deviations).

4. Example input:
   properties = {
       "is_reused": True,
       "account_count": 3,
       "is_known_weak": True,
       "is_suspicious_source": False,
       "has_auth_anomalies": False,
       "is_privileged": True
   }

5. Example output:
   {
       "score": 80,
       "severity": "CRITICAL",
       "breakdown": [
           {"factor": "Duplicate hash across accounts", "points": 30},
           {"factor": "Hash associated with multiple users (>=3)", "points": 30},
           {"factor": "Known test/demo weak-password hash", "points": 20}
       ],
       "disclaimer": "Educational heuristic score - not a real Microsoft security rating."
   }
"""

from typing import Any, Dict, List, Optional
from app.core import config


class RiskEngine:
    """
    Configurable heuristic engine for password hash and account risk calculation.
    """

    @classmethod
    def calculate_score(
        cls,
        is_reused: bool = False,
        account_count: int = 1,
        is_known_weak: bool = False,
        is_suspicious_source: bool = False,
        has_auth_anomalies: bool = False,
        is_privileged: bool = False,
        custom_weights: Optional[Dict[str, int]] = None
    ) -> Dict[str, Any]:
        """
        Calculates a 0-100 risk score based on observable record properties.
        Scoring logic is configurable via app.core.config or custom_weights parameter.
        """
        weights = custom_weights or {
            "reused": config.WEIGHT_HASH_REUSE,
            "many_users": config.WEIGHT_MANY_USERS,
            "weak_hash": config.WEIGHT_KNOWN_WEAK_HASH,
            "suspicious_source": config.WEIGHT_SUSPICIOUS_SOURCE,
            "abnormal_auth": config.WEIGHT_ABNORMAL_AUTH,
        }

        score = 0
        breakdown: List[Dict[str, Any]] = []

        # 1. Duplicate hash across accounts (+30)
        if is_reused:
            pts = weights.get("reused", 30)
            score += pts
            breakdown.append({
                "factor": "Duplicate hash across accounts",
                "points": pts,
                "detail": "Credential hash observed under more than one user account."
            })

        # 2. Hash associated with 3 or more users (+30)
        if account_count >= 3:
            pts = weights.get("many_users", 30)
            score += pts
            breakdown.append({
                "factor": "Hash associated with multiple users (>=3 accounts)",
                "points": pts,
                "detail": f"Widespread reuse detected across {account_count} accounts."
            })

        # 3. Known test/demo weak-password hash (+20)
        if is_known_weak:
            pts = weights.get("weak_hash", 20)
            score += pts
            breakdown.append({
                "factor": "Known test/demo weak-password hash",
                "points": pts,
                "detail": "Hash matches known test/default weak credentials (e.g. blank, 'password', 'admin')."
            })

        # 4. Suspicious source / unknown host (+20)
        if is_suspicious_source:
            pts = weights.get("suspicious_source", 20)
            score += pts
            breakdown.append({
                "factor": "Suspicious machine source / unauthorized export",
                "points": pts,
                "detail": "Originating from outside verified lab workstation baselines."
            })

        # 5. Abnormal authentication activity (+20)
        if has_auth_anomalies:
            pts = weights.get("abnormal_auth", 20)
            score += pts
            breakdown.append({
                "factor": "Abnormal authentication activity",
                "points": pts,
                "detail": "Account exhibits logon failure bursts, spraying, or off-hours access."
            })

        # Privilege escalation modifier (+10 if privileged account shares hash)
        if is_privileged and is_reused:
            pts = 10
            score += pts
            breakdown.append({
                "factor": "Privileged account credential sharing",
                "points": pts,
                "detail": "Administrative account shares password hash with standard or service accounts."
            })

        # Clamp score between 0 and 100
        final_score = min(max(score, 0), 100)
        severity = cls.map_score_to_severity(final_score)

        return {
            "score": final_score,
            "severity": severity,
            "breakdown": breakdown,
            "is_high_risk": final_score >= 41,
            "disclaimer": config.DISCLAIMER
        }

    @staticmethod
    def map_score_to_severity(score: int) -> str:
        """
        Maps a 0-100 numerical risk score to categorical severity bands:
        0-20:    LOW
        21-40:   MEDIUM
        41-70:   HIGH
        71-100:  CRITICAL
        """
        if score >= 71:
            return "CRITICAL"
        elif score >= 41:
            return "HIGH"
        elif score >= 21:
            return "MEDIUM"
        else:
            return "LOW"

    @classmethod
    def evaluate_hash_record(cls, record: Any, has_auth_anomaly: bool = False) -> Dict[str, Any]:
        """
        Convenience evaluator for a HashRecord ORM instance or dictionary.
        """
        if isinstance(record, dict):
            is_reused = record.get("is_reused", False)
            reuse_cnt = record.get("reuse_count", 1)
            raw_hash = record.get("hash", "")
            machine = record.get("machine", "")
            source = record.get("source", "")
            username = record.get("username", "")
        else:
            is_reused = getattr(record, "is_reused", False)
            reuse_cnt = getattr(record, "reuse_count", 1)
            raw_hash = getattr(record, "hash_value", "")
            machine = getattr(record, "machine", "")
            source = getattr(record, "source", "")
            username = getattr(record, "username", "")

        from app.services.hash_analyzer import HashAnalyzer
        is_known_weak = HashAnalyzer.check_known_weak_hash(raw_hash) is not None
        is_suspicious_source = HashAnalyzer.is_suspicious_source(machine, source)
        is_privileged = username.lower() in config.PRIVILEGED_ACCOUNTS

        return cls.calculate_score(
            is_reused=is_reused,
            account_count=reuse_cnt,
            is_known_weak=is_known_weak,
            is_suspicious_source=is_suspicious_source,
            has_auth_anomalies=has_auth_anomaly,
            is_privileged=is_privileged
        )
