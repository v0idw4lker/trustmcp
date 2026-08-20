"""Tests for trustmcp.core.static_analyzer against the bundled fixture modules."""

import os

from trustmcp.core.static_analyzer import scan_python_file

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_vulnerable_module_flags_expected_issues():
    findings = scan_python_file(os.path.join(FIXTURES_DIR, "vulnerable_module.py"))
    rule_ids = _rule_ids(findings)

    assert "static.secret-openai-key" in rule_ids
    assert "static.secret-anthropic-key" in rule_ids
    assert "static.secret-github-token" in rule_ids
    assert "static.secret-aws-key" in rule_ids
    assert "static.secret-stripe-key" in rule_ids
    assert "static.secret-google-key" in rule_ids
    assert "static.secret-slack-token" in rule_ids
    assert "static.secret-pem-private-key" in rule_ids
    assert "static.hidden-unicode" in rule_ids
    assert "static.dangerous-eval-exec" in rule_ids
    assert "static.os-system" in rule_ids
    assert "static.subprocess-shell-true" in rule_ids
    assert "static.pickle-deserialization" in rule_ids
    assert "static.path-traversal-open-param" in rule_ids


def test_clean_module_has_no_findings():
    findings = scan_python_file(os.path.join(FIXTURES_DIR, "clean_module.py"))
    assert findings == []


def test_path_traversal_only_flags_parameter_derived_paths():
    findings = scan_python_file(os.path.join(FIXTURES_DIR, "vulnerable_module.py"))
    traversal_findings = [f for f in findings if f.rule_id == "static.path-traversal-open-param"]
    assert len(traversal_findings) == 1
