"""Tests for mcpwarden.reporters.sarif_reporter."""

from mcpwarden.core.models import Finding, Severity
from mcpwarden.reporters.sarif_reporter import build_sarif


def test_build_sarif_produces_one_rule_and_one_result():
    findings = [
        Finding(module="static", rule_id="static.dangerous-eval-exec", title="Dangerous function usage (eval)",
                description="desc", severity=Severity.CRITICAL, confidence=95, location="app.py", line=10,
                cwe="CWE-95", remediation="Do not use eval."),
    ]
    sarif_log = build_sarif(findings, tool_version="1.0.0")

    run = sarif_log["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpwarden"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "static.dangerous-eval-exec"
    assert len(run["results"]) == 1

    result = run["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


def test_rules_are_deduplicated_by_rule_id():
    findings = [
        Finding(module="static", rule_id="static.os-system", title="t", description="d",
                severity=Severity.HIGH, confidence=90, location="a.py", line=1),
        Finding(module="static", rule_id="static.os-system", title="t", description="d",
                severity=Severity.HIGH, confidence=90, location="b.py", line=2),
    ]
    sarif_log = build_sarif(findings, tool_version="1.0.0")
    run = sarif_log["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
