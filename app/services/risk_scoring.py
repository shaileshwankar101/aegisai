"""
AegisAI — Risk Scoring Service
================================
Pure deterministic Python. No LLM. No cloud. No dependencies.

The LLM explains the score. This service calculates it.
If the LLM ever returns a risk_score that differs from this service's
output, that is a numerical hallucination (FM-004).
"""

from __future__ import annotations
from dataclasses import dataclass

# ── Scoring Matrix ────────────────────────────────────────────────────────────
# Source of truth. Must match Vendor_Risk_Scoring_Matrix.txt exactly.
# Any change here requires re-running the full golden dataset evaluation.

RISK_MATRIX: dict[str, int] = {
    "mfa_missing":           25,
    "no_encryption":         30,
    "no_annual_pentest":     20,
    "no_ir_plan":            15,
    "no_soc2_iso_evidence":  15,
    "sso_missing":           10,
    "no_data_retention":     10,
    "critical_cve_exposure": 30,
}

MAX_SCORE = 100

# ── Rating Bands ──────────────────────────────────────────────────────────────
# (ceiling, rating) — first match wins
RATING_BANDS: list[tuple[int, str]] = [
    (20,  "Low"),
    (50,  "Medium"),
    (80,  "High"),
    (100, "Critical"),
]

# ── Human-readable labels for failed controls ─────────────────────────────────
CONTROL_LABELS: dict[str, str] = {
    "mfa_missing":           "MFA",
    "no_encryption":         "Encryption",
    "no_annual_pentest":     "Annual Penetration Testing",
    "no_ir_plan":            "Incident Response Plan",
    "no_soc2_iso_evidence":  "SOC2/ISO Evidence",
    "sso_missing":           "SSO",
    "no_data_retention":     "Data Retention Policy",
    "critical_cve_exposure": "Critical CVE Exposure",
}

# ── Knowledge base sources for each control ───────────────────────────────────
CONTROL_SOURCES: dict[str, str] = {
    "mfa_missing":           "MFA Security Standard",
    "sso_missing":           "MFA Security Standard",
    "no_encryption":         "Encryption Policy",
    "no_data_retention":     "Encryption Policy",
    "no_annual_pentest":     "Annual Penetration Testing Requirement Policy",
    "critical_cve_exposure": "Annual Penetration Testing Requirement Policy",
    "no_ir_plan":            "Incident Response Policy",
    "no_soc2_iso_evidence":  "Compliance Mapping Guide",
}


# ── Result Dataclass ──────────────────────────────────────────────────────────

@dataclass
class RiskResult:
    """Output of the risk scoring service."""
    risk_score:        int
    risk_rating:       str
    failed_controls:   list[str]   # human-readable labels e.g. ["MFA", "Encryption"]
    failed_keys:       list[str]   # internal keys e.g. ["mfa_missing", "no_encryption"]
    relevant_sources:  list[str]   # knowledge base documents to retrieve
    raw_score:         int         # before capping — useful for detecting cap scenarios
    score_was_capped:  bool        # True when raw_score > MAX_SCORE

    def to_dict(self) -> dict:
        return {
            "risk_score":       self.risk_score,
            "risk_rating":      self.risk_rating,
            "failed_controls":  self.failed_controls,
            "relevant_sources": self.relevant_sources,
            "score_was_capped": self.score_was_capped,
        }


# ── Core Function ─────────────────────────────────────────────────────────────

def calculate(controls: dict[str, bool]) -> RiskResult:
    """
    Calculate deterministic vendor risk score from control failures.

    Args:
        controls: dict mapping control keys to bool.
                  True = control is FAILING (bad).
                  False = control is in place (good).
                  Missing keys are treated as False (control present).

    Returns:
        RiskResult with score, rating, failed controls, and relevant sources.

    Example:
        >>> result = calculate({"mfa_missing": True, "no_encryption": True})
        >>> result.risk_score
        55
        >>> result.risk_rating
        'High'
        >>> result.failed_controls
        ['MFA', 'Encryption']
    """
    raw_score    = 0
    failed_keys  = []

    for control_key, impact in RISK_MATRIX.items():
        if controls.get(control_key, False):
            raw_score   += impact
            failed_keys.append(control_key)

    risk_score    = min(raw_score, MAX_SCORE)
    risk_rating   = _get_rating(risk_score)
    failed_labels = [CONTROL_LABELS[k] for k in failed_keys]
    sources       = _get_sources(failed_keys)

    return RiskResult(
        risk_score       = risk_score,
        risk_rating      = risk_rating,
        failed_controls  = failed_labels,
        failed_keys      = failed_keys,
        relevant_sources = sources,
        raw_score        = raw_score,
        score_was_capped = raw_score > MAX_SCORE,
    )


def _get_rating(score: int) -> str:
    """Map a score to a risk rating using the defined bands."""
    for ceiling, rating in RATING_BANDS:
        if score <= ceiling:
            return rating
    return "Critical"  # safety fallback


def _get_sources(failed_keys: list[str]) -> list[str]:
    """Return deduplicated knowledge base sources for the failing controls."""
    seen    = set()
    sources = []
    for key in failed_keys:
        source = CONTROL_SOURCES.get(key)
        if source and source not in seen:
            seen.add(source)
            sources.append(source)
    # Always include the scoring matrix as a reference
    if "Vendor Risk Scoring Matrix" not in seen:
        sources.append("Vendor Risk Scoring Matrix")
    return sources


# ── Convenience helpers ───────────────────────────────────────────────────────

def get_all_control_keys() -> list[str]:
    """Return all valid control keys."""
    return list(RISK_MATRIX.keys())


def validate_controls(controls: dict) -> tuple[bool, list[str]]:
    """
    Validate that all keys in controls dict are recognised.
    Returns (is_valid, list_of_unknown_keys).
    """
    unknown = [k for k in controls if k not in RISK_MATRIX]
    return len(unknown) == 0, unknown


# ── CLI quick-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    test_cases = [
        ("IAM-001 — MFA only",
         {"mfa_missing": True}),

        ("IAM-010 — Boundary at 50",
         {"mfa_missing": True, "sso_missing": True, "no_ir_plan": True}),

        ("DP-009 — Critical",
         {"mfa_missing": True, "no_encryption": True, "critical_cve_exposure": True}),

        ("EC-001 — High ceiling at 80",
         {"no_encryption": True, "critical_cve_exposure": True, "no_annual_pentest": True}),

        ("IAM-012 — All controls, score capped",
         {k: True for k in RISK_MATRIX}),

        ("IAM-011 — Zero failures",
         {k: False for k in RISK_MATRIX}),
    ]

    print("AegisAI Risk Scoring Service — Quick Test\n" + "=" * 50)
    all_passed = True

    expected = {
        "IAM-001 — MFA only":              (25,  "Medium"),
        "IAM-010 — Boundary at 50":        (50,  "Medium"),
        "DP-009 — Critical":               (85,  "Critical"),
        "EC-001 — High ceiling at 80":     (80,  "High"),
        "IAM-012 — All controls, score capped": (100, "Critical"),
        "IAM-011 — Zero failures":         (0,   "Low"),
    }

    for name, controls in test_cases:
        result    = calculate(controls)
        exp_score, exp_rating = expected[name]
        passed    = result.risk_score == exp_score and result.risk_rating == exp_rating
        status    = "✓ PASS" if passed else "✗ FAIL"
        if not passed:
            all_passed = False

        print(f"\n{status}  {name}")
        print(f"  Score:    {result.risk_score} (expected {exp_score})")
        print(f"  Rating:   {result.risk_rating} (expected {exp_rating})")
        print(f"  Failed:   {result.failed_controls}")
        print(f"  Capped:   {result.score_was_capped} (raw={result.raw_score})")

    print("\n" + "=" * 50)
    print("ALL TESTS PASSED ✓" if all_passed else "SOME TESTS FAILED ✗")
