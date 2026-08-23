"""Tests for trustmcp.core.scoring."""

from trustmcp.core.models import Finding, Severity
from trustmcp.core.scoring import calculate_score_report


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


def test_repeated_identical_rule_id_score_deduction_is_capped():
    # 8 identical-rule_id LOW findings (e.g. a dozen ordinary npm ^/~ semver
    # ranges) is one repeated pattern, not 8 independent failures — only the
    # first MAX_SCORED_INSTANCES_PER_RULE (5) should subtract from score.
    findings = [_finding("static.dependency-weak-constraint", Severity.LOW) for _ in range(8)]
    report = calculate_score_report(findings)
    assert report.score == 100 - (5 * 3)  # capped at 5 instances, not 8 (-15, not -24)
    # Nothing is hidden from the full report — only the score deduction is capped.
    assert report.total_findings == 8
    assert report.severity_summary["LOW"] == 8
