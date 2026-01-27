"""
Negative Regression Tests for Athena v1.2 Persona.

This test file acts as a "tripwire" to prevent regression of the strict analyst persona constraints.
It defines forbidden phrases that should NEVER appear in the LLM's final rendered output.

Usage:
    pytest tests/test_compliance_tripwire.py
"""
import pytest
import re

# Strict Analyst Constraints
# These phrases constitute a "Fail" condition for the build.
FORBIDDEN_PATTERNS = [
    # Verdicts
    r"\bis malicious\b",
    r"\bis benign\b",
    
    # Certainty Claims
    r"strongly associated with",
    r"this confirms",
    
    # Attribution / Intent (without strong hedging)
    r"used for command and control",
    
    # Actionable Advice (Forbidden)
    r"we recommend blocking",
    r"you should block"
]

def validate_analyst_output(text: str) -> list[str]:
    """
    Scans the text for forbidden patterns.
    Returns a list of violations found.
    """
    violations = []
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            violations.append(pattern)
    return violations

# --- TESTS FOR THE VALIDATOR ITSELF ---

@pytest.mark.parametrize("bad_output, expected_match", [
    ("Based on this, the IP is malicious.", r"is malicious"),
    ("The file is benign and huge.", r"is benign"),
    ("This activity is strongly associated with APT29.", "strongly associated with"),
    ("This confirms the presence of Cobalt Strike.", "this confirms"),
    ("The domain is used for command and control infrastructure.", "used for command and control"),
    ("Therefore, we recommend blocking this subnet.", "recommend blocking"),
    ("You should block port 445.", "you should block"),
])
def test_validator_fails_on_forbidden_phrases(bad_output, expected_match):
    """Ensure the tripwire correctly triggers on known bad inputs."""
    violations = validate_analyst_output(bad_output)
    assert len(violations) > 0, f"Validator failed to catch: '{bad_output}'"
    # Optional: check if specific pattern was caught
    # assert any(re.search(expected_match, v) for v in violations)

def test_validator_passes_compliant_output():
    """Ensure hypothesis-driven, neutral language passes."""
    good_output = """
    Observed Facts:
    - ThreatFox lists IOC 1.2.3.4 with confidence 80%.
    
    Analyst Interpretation:
    - The high confidence score suggests potential malicious activity.
    - Historical data indicates possible linkage to C2 frameworks.
    
    Recommended Next Steps:
    - Investigate internal logs for traffic to this IP.
    """
    violations = validate_analyst_output(good_output)
    assert len(violations) == 0, f"Validator falsely flagged compliant output: {violations}"

# --- OPTIONAL: SNAPSHOT OR FILE SCANNING TESTS ---
# (If you have a directory of 'golden' or 'generated' outputs, iterate them here)
