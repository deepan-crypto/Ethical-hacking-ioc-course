"""
Unit Test: Risk Scoring Engine & MITRE ATT&CK Mapper

Tests the heuristic scoring formula, severity band mapping, configurable weights,
educational disclaimers, and MITRE ATT&CK technique correlation.
"""

import pytest
from app.services.risk_engine import RiskEngine
from app.services.mitre_mapper import MitreMapper


def test_map_score_to_severity():
    """Validates boundary conditions for severity band classification."""
    assert RiskEngine.map_score_to_severity(0) == "LOW"
    assert RiskEngine.map_score_to_severity(20) == "LOW"
    assert RiskEngine.map_score_to_severity(21) == "MEDIUM"
    assert RiskEngine.map_score_to_severity(40) == "MEDIUM"
    assert RiskEngine.map_score_to_severity(41) == "HIGH"
    assert RiskEngine.map_score_to_severity(70) == "HIGH"
    assert RiskEngine.map_score_to_severity(71) == "CRITICAL"
    assert RiskEngine.map_score_to_severity(100) == "CRITICAL"


def test_calculate_score_clean_account():
    """An account with no anomalous properties must score 0 (LOW)."""
    result = RiskEngine.calculate_score(
        is_reused=False,
        account_count=1,
        is_known_weak=False,
        is_suspicious_source=False,
        has_auth_anomalies=False
    )
    assert result["score"] == 0
    assert result["severity"] == "LOW"
    assert len(result["breakdown"]) == 0
    assert "disclaimer" in result


def test_calculate_score_reuse_and_weak():
    """Hash reuse (+30) and weak hash (+20) should equal 50 (HIGH)."""
    result = RiskEngine.calculate_score(
        is_reused=True,
        account_count=2,
        is_known_weak=True,
        is_suspicious_source=False,
        has_auth_anomalies=False
    )
    assert result["score"] == 50
    assert result["severity"] == "HIGH"
    assert len(result["breakdown"]) == 2


def test_calculate_score_critical_clamp():
    """All risk factors combined should accumulate and clamp cleanly at 100."""
    result = RiskEngine.calculate_score(
        is_reused=True,
        account_count=5,          # +30 +30 = 60
        is_known_weak=True,       # +20 = 80
        is_suspicious_source=True,# +20 = 100
        has_auth_anomalies=True,  # +20 = 120 -> clamped to 100
        is_privileged=True        # +10
    )
    assert result["score"] == 100
    assert result["severity"] == "CRITICAL"
    assert result["is_high_risk"] is True


def test_configurable_custom_weights():
    """Tests that blue team analysts can tune rule sensitivity with custom weights."""
    custom = {
        "reused": 10,
        "many_users": 10,
        "weak_hash": 5,
        "suspicious_source": 5,
        "abnormal_auth": 5
    }
    result = RiskEngine.calculate_score(
        is_reused=True,
        account_count=1,
        custom_weights=custom
    )
    assert result["score"] == 10
    assert result["severity"] == "LOW"


def test_mitre_mapping_lookups():
    """Verifies MITRE ATT&CK technique lookups, tactics, and playbook recommendations."""
    # Test Brute Force lookup
    t1110 = MitreMapper.get_technique("T1110.001")
    assert t1110 is not None
    assert "Password Guessing" in t1110["technique_name"]
    assert t1110["tactic"] == "Credential Access"
    assert "lockout" in t1110["defensive_recommendation"].lower()

    # Test Spraying condition
    spray = MitreMapper.map_ioc("AUTH_FAILURE_SPIKE", is_spraying=True)
    assert spray["technique_id"] == "T1110.003"
    assert "Spraying" in spray["technique_name"]

    # Test Off-Hours Access
    off_hours = MitreMapper.map_ioc("UNUSUAL_LOGIN_TIME", is_off_hours=True)
    assert off_hours["technique_id"] == "T1098"

    # Test Matrix list returns all expected techniques
    all_techs = MitreMapper.get_all_matrix_techniques()
    assert len(all_techs) >= 6
    tech_ids = {t["technique_id"] for t in all_techs}
    assert "T1078.002" in tech_ids
    assert "T1003.002" in tech_ids
