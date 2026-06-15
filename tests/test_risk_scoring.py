"""
Tests for the Risk Scoring Service
====================================
Run from project root:
    python -m pytest tests/test_risk_scoring.py -v

These tests verify every boundary scenario and edge case
in the golden dataset before the RAG layer is added.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app.services.risk_scoring import calculate, validate_controls, RISK_MATRIX


# ── Isolated single-control tests ─────────────────────────────────────────────

class TestSingleControls:

    def test_mfa_missing_alone(self):
        """IAM-001: MFA alone = 25 = Medium"""
        r = calculate({"mfa_missing": True})
        assert r.risk_score == 25
        assert r.risk_rating == "Medium"
        assert "MFA" in r.failed_controls
        assert len(r.failed_controls) == 1

    def test_sso_missing_alone(self):
        """IAM-002: SSO alone = 10 = Low"""
        r = calculate({"sso_missing": True})
        assert r.risk_score == 10
        assert r.risk_rating == "Low"

    def test_encryption_missing_alone(self):
        """DP-001: Encryption alone = 30 = Medium"""
        r = calculate({"no_encryption": True})
        assert r.risk_score == 30
        assert r.risk_rating == "Medium"

    def test_pentest_missing_alone(self):
        """VM-001: No pentest alone = 20 = Low (Low ceiling boundary)"""
        r = calculate({"no_annual_pentest": True})
        assert r.risk_score == 20
        assert r.risk_rating == "Low"

    def test_ir_plan_missing_alone(self):
        """IR-001: IR plan alone = 15 = Low"""
        r = calculate({"no_ir_plan": True})
        assert r.risk_score == 15
        assert r.risk_rating == "Low"

    def test_soc2_missing_alone(self):
        """CG-001: SOC2 alone = 15 = Low"""
        r = calculate({"no_soc2_iso_evidence": True})
        assert r.risk_score == 15
        assert r.risk_rating == "Low"

    def test_data_retention_missing_alone(self):
        """DP-002: Data retention alone = 10 = Low"""
        r = calculate({"no_data_retention": True})
        assert r.risk_score == 10
        assert r.risk_rating == "Low"

    def test_critical_cve_alone(self):
        """VM-002: Critical CVE alone = 30 = Medium"""
        r = calculate({"critical_cve_exposure": True})
        assert r.risk_score == 30
        assert r.risk_rating == "Medium"


# ── Boundary scenarios ────────────────────────────────────────────────────────

class TestBoundaries:

    def test_low_ceiling_score_20(self):
        """VM-001: Score exactly 20 = Low ceiling — must NOT return Medium"""
        r = calculate({"no_annual_pentest": True})
        assert r.risk_score == 20
        assert r.risk_rating == "Low", \
            f"Score 20 must be Low, got {r.risk_rating}"

    def test_medium_floor_score_25(self):
        """IAM-001: Score 25 = first Medium — must NOT return Low"""
        r = calculate({"mfa_missing": True})
        assert r.risk_score == 25
        assert r.risk_rating == "Medium", \
            f"Score 25 must be Medium, got {r.risk_rating}"

    def test_medium_ceiling_score_50_iam(self):
        """IAM-010: Score exactly 50 = Medium ceiling — must NOT return High"""
        r = calculate({"mfa_missing": True, "sso_missing": True, "no_ir_plan": True})
        assert r.risk_score == 50
        assert r.risk_rating == "Medium", \
            f"Score 50 must be Medium, got {r.risk_rating}"

    def test_medium_ceiling_score_50_dp(self):
        """DP-005: Another 50 = Medium ceiling with different controls"""
        r = calculate({"no_encryption": True, "no_annual_pentest": True})
        assert r.risk_score == 50
        assert r.risk_rating == "Medium"

    def test_medium_ceiling_score_50_vm(self):
        """VM-003: Natural VM boundary — pentest + CVE = 50"""
        r = calculate({"no_annual_pentest": True, "critical_cve_exposure": True})
        assert r.risk_score == 50
        assert r.risk_rating == "Medium"

    def test_high_ceiling_score_80(self):
        """EC-001: Score exactly 80 = High ceiling — must NOT return Critical"""
        r = calculate({
            "no_encryption":     True,
            "critical_cve_exposure": True,
            "no_annual_pentest": True,
        })
        assert r.risk_score == 80
        assert r.risk_rating == "High", \
            f"Score 80 must be High, got {r.risk_rating}"

    def test_first_high_score_55(self):
        """IAM-004: MFA + encryption = 55 = first common High"""
        r = calculate({"mfa_missing": True, "no_encryption": True})
        assert r.risk_score == 55
        assert r.risk_rating == "High"


# ── Zero failures ─────────────────────────────────────────────────────────────

class TestZeroFailures:

    def test_all_controls_passing(self):
        """IAM-011 / EC-005: Zero failures = score 0 = Low"""
        controls = {k: False for k in RISK_MATRIX}
        r = calculate(controls)
        assert r.risk_score == 0
        assert r.risk_rating == "Low"
        assert r.failed_controls == []

    def test_empty_controls_dict(self):
        """Empty dict = all controls present = score 0"""
        r = calculate({})
        assert r.risk_score == 0
        assert r.risk_rating == "Low"

    def test_missing_keys_treated_as_passing(self):
        """Only specified keys matter — unspecified = passing"""
        r = calculate({"mfa_missing": False})
        assert r.risk_score == 0


# ── Score capping ─────────────────────────────────────────────────────────────

class TestScoreCapping:

    def test_all_controls_failing_capped_at_100(self):
        """IAM-012: All 8 controls failing — raw=155, capped to 100"""
        controls = {k: True for k in RISK_MATRIX}
        r = calculate(controls)
        assert r.risk_score == 100
        assert r.risk_rating == "Critical"
        assert r.score_was_capped is True
        assert r.raw_score == 155
        assert len(r.failed_controls) == 8

    def test_score_cap_exact_100(self):
        """CG-008: Raw sum = exactly 100 — no capping needed"""
        r = calculate({
            "no_soc2_iso_evidence":  True,   # 15
            "mfa_missing":           True,   # 25
            "no_encryption":         True,   # 30
            "critical_cve_exposure": True,   # 30
        })
        assert r.risk_score == 100
        assert r.score_was_capped is False   # 100 <= 100, no cap needed
        assert r.raw_score == 100

    def test_5_controls_exceeds_cap(self):
        """EC-003: 5 controls with raw=105 — capped to 100"""
        r = calculate({
            "mfa_missing":           True,   # 25
            "no_encryption":         True,   # 30
            "no_annual_pentest":     True,   # 20
            "no_ir_plan":            True,   # 15
            "no_soc2_iso_evidence":  True,   # 15
        })
        assert r.raw_score == 105
        assert r.risk_score == 100
        assert r.score_was_capped is True


# ── Failed control detection ──────────────────────────────────────────────────

class TestFailedControlDetection:

    def test_three_controls_all_detected(self):
        """IAM-008: All 3 controls must appear in failed_controls"""
        r = calculate({
            "mfa_missing":    True,
            "sso_missing":    True,
            "no_encryption":  True,
        })
        assert "MFA"        in r.failed_controls
        assert "SSO"        in r.failed_controls
        assert "Encryption" in r.failed_controls
        assert len(r.failed_controls) == 3

    def test_six_controls_all_detected(self):
        """EC-004: All 6 controls must be detected"""
        r = calculate({
            "mfa_missing":          True,
            "sso_missing":          True,
            "no_annual_pentest":    True,
            "no_ir_plan":           True,
            "no_soc2_iso_evidence": True,
            "no_data_retention":    True,
        })
        assert len(r.failed_controls) == 6
        assert r.risk_score == 95
        assert r.risk_rating == "Critical"

    def test_false_controls_not_in_failed(self):
        """Controls set to False must never appear in failed_controls"""
        r = calculate({
            "mfa_missing":    True,
            "no_encryption":  False,
            "sso_missing":    False,
        })
        assert "MFA" in r.failed_controls
        assert "Encryption" not in r.failed_controls
        assert "SSO" not in r.failed_controls
        assert len(r.failed_controls) == 1


# ── Source attribution ────────────────────────────────────────────────────────

class TestSourceAttribution:

    def test_mfa_references_mfa_standard(self):
        r = calculate({"mfa_missing": True})
        assert "MFA Security Standard" in r.relevant_sources

    def test_sso_references_mfa_standard(self):
        """SSO and MFA both reference the same document"""
        r = calculate({"sso_missing": True})
        assert "MFA Security Standard" in r.relevant_sources

    def test_encryption_references_encryption_policy(self):
        r = calculate({"no_encryption": True})
        assert "Encryption Policy" in r.relevant_sources

    def test_retention_references_encryption_policy(self):
        r = calculate({"no_data_retention": True})
        assert "Encryption Policy" in r.relevant_sources

    def test_no_duplicate_sources(self):
        """MFA + SSO should cite MFA Security Standard only once"""
        r = calculate({"mfa_missing": True, "sso_missing": True})
        mfa_standard_count = r.relevant_sources.count("MFA Security Standard")
        assert mfa_standard_count == 1

    def test_all_five_sources_for_ec003(self):
        """EC-003: 5 controls must produce all 5 knowledge base sources"""
        r = calculate({
            "mfa_missing":           True,
            "no_encryption":         True,
            "no_annual_pentest":     True,
            "no_ir_plan":            True,
            "no_soc2_iso_evidence":  True,
        })
        assert "MFA Security Standard"                       in r.relevant_sources
        assert "Encryption Policy"                           in r.relevant_sources
        assert "Annual Penetration Testing Requirement Policy" in r.relevant_sources
        assert "Incident Response Policy"                    in r.relevant_sources
        assert "Compliance Mapping Guide"                    in r.relevant_sources


# ── Validation ────────────────────────────────────────────────────────────────

class TestValidation:

    def test_valid_controls_pass(self):
        is_valid, unknown = validate_controls({"mfa_missing": True})
        assert is_valid is True
        assert unknown == []

    def test_unknown_key_detected(self):
        is_valid, unknown = validate_controls({"nonexistent_control": True})
        assert is_valid is False
        assert "nonexistent_control" in unknown


# ── Golden dataset spot checks ────────────────────────────────────────────────

class TestGoldenDatasetSpotChecks:
    """Verify a sample of golden dataset scenarios score correctly."""

    @pytest.mark.parametrize("scenario_id,controls,expected_score,expected_rating", [
        ("IAM-001", {"mfa_missing": True},                                              25,  "Medium"),
        ("IAM-002", {"sso_missing": True},                                              10,  "Low"),
        ("IAM-003", {"mfa_missing": True, "sso_missing": True},                        35,  "Medium"),
        ("IAM-004", {"mfa_missing": True, "no_encryption": True},                      55,  "High"),
        ("DP-004",  {"no_encryption": True, "critical_cve_exposure": True},            60,  "High"),
        ("VM-001",  {"no_annual_pentest": True},                                        20,  "Low"),
        ("VM-009",  {"critical_cve_exposure": True, "no_annual_pentest": True, "no_soc2_iso_evidence": True}, 65, "High"),
        ("CG-001",  {"no_soc2_iso_evidence": True},                                    15,  "Low"),
        ("CG-008",  {"no_soc2_iso_evidence": True, "mfa_missing": True, "no_encryption": True, "critical_cve_exposure": True}, 100, "Critical"),
        ("IR-005",  {"no_ir_plan": True, "critical_cve_exposure": True, "no_encryption": True}, 75, "High"),
        ("EC-004",  {"mfa_missing": True, "sso_missing": True, "no_annual_pentest": True, "no_ir_plan": True, "no_soc2_iso_evidence": True, "no_data_retention": True}, 95, "Critical"),
        ("EC-005",  {k: False for k in RISK_MATRIX},                                   0,   "Low"),
    ])
    def test_golden_scenario(self, scenario_id, controls, expected_score, expected_rating):
        r = calculate(controls)
        assert r.risk_score == expected_score, \
            f"{scenario_id}: expected score {expected_score}, got {r.risk_score}"
        assert r.risk_rating == expected_rating, \
            f"{scenario_id}: expected rating {expected_rating}, got {r.risk_rating}"
