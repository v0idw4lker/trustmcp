"""Tests for mcpwarden.core.scoring."""

from mcpwarden.core.models import Finding, Severity
from mcpwarden.core.scoring import calculate_score_report


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        module="static", rule_id=rule_id, title="t", description="d",
        severity=severity, confidence=90, location="x.py",
    )


def test_clean_scan_scores_100_grade_a():
    report = calculate_score_report([])
    assert report.score == 100
    assert report.grade == "A"
    assert report.total_findings == 0


def test_severity_weights_reduce_score():
    findings = [_finding("static.dangerous-eval-exec", Severity.CRITICAL)]
    report = calculate_score_report(findings)
    assert report.score == 100 - 25
    assert report.grade == "C"


def test_foundation_penalty_applies_on_top_of_severity():
    findings = [
        Finding(module="dynamic", rule_id="dynamic.no-tls", title="t", description="d",
                severity=Severity.CRITICAL, confidence=90, location="http://x"),
    ]
    report = calculate_score_report(findings)
    # CRITICAL severity (-25) plus the foundational extra penalty (-15) = -40
    assert report.score == 60


def test_owasp_mapping_is_keyed_by_rule_id():
    findings = [_finding("static.secret-github-token", Severity.CRITICAL)]
    report = calculate_score_report(findings)
    assert findings[0].owasp_category == "MCP01:2025 Token Mismanagement & Secret Exposure"
    assert report.unmapped_findings == 0


def test_findings_without_a_mapping_are_left_unmapped():
    findings = [_finding("static.syntax-error", Severity.LOW)]
    report = calculate_score_report(findings)
    assert findings[0].owasp_category is None
    assert report.unmapped_findings == 1
