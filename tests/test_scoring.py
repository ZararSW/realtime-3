"""Tests for the risk/CVSS scoring helpers in run.py."""
import pytest

from scanner.cli import get_risk_level, calculate_cvss_score, extract_cvss_from_severity


@pytest.mark.parametrize(
    "score,level",
    [
        (0, "LOW RISK"),
        (2, "LOW RISK"),
        (2.1, "MEDIUM RISK"),
        (4, "MEDIUM RISK"),
        (5, "HIGH RISK"),
        (7, "HIGH RISK"),
        (8, "CRITICAL RISK"),
        (9, "CRITICAL RISK"),
        (9.5, "SEVERE RISK"),
        (10, "SEVERE RISK"),
    ],
)
def test_get_risk_level_boundaries(score, level):
    assert get_risk_level(score) == level


def test_cvss_known_type_and_unknown_fallback():
    # xss base 6.1, high multiplier 1.0
    assert calculate_cvss_score("xss", "high") == pytest.approx(6.1)
    # unknown type falls back to base 5.0, medium multiplier 0.8 -> 4.0
    assert calculate_cvss_score("totally_unknown", "medium") == pytest.approx(4.0)


def test_cvss_is_clamped_to_10():
    # command_injection 9.8 * critical 1.2 = 11.76 -> clamped
    assert calculate_cvss_score("command_injection", "critical") == 10.0
    for vuln_type in ("sqli", "xss", "ssrf", "idor", "csrf"):
        score = calculate_cvss_score(vuln_type, "critical")
        assert 0.0 <= score <= 10.0


@pytest.mark.parametrize(
    "severity,score",
    [
        ("Critical", 9.5),
        ("High", 7.5),
        ("Medium", 5.0),
        ("Low", 3.0),
        ("Info", 1.0),
        ("unrecognized", 5.0),
    ],
)
def test_extract_cvss_from_severity(severity, score):
    assert extract_cvss_from_severity(severity) == score
