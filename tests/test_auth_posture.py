"""
Tests for trustmcp.core.auth_posture — specifically the FIX 2 scoring-
calibration bug: analyze_auth_posture() only reads .py files, so any
non-Python package (or a directory with no Python source at all) fell
through to the "none-detected" branch and got flagged HIGH severity with a
foundational penalty, asserting "no auth mechanism" when in truth the
module never had anything to look at.
"""

from __future__ import annotations

from trustmcp.core.auth_posture import analyze_auth_posture
from trustmcp.core.scoring import FOUNDATION_PENALTY_EXTRA, calculate_score_report


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_no_py_files_and_no_dynamic_results_is_undetermined_not_none_detected(tmp_path):
    # Directory has no Python source at all (e.g. a non-Python package) and
    # no live dynamic probe was run — there is nothing for this module to
    # examine, so it must not claim "no auth mechanism".
    _write(tmp_path, "server.js", "console.log('hello');\n")

    result = analyze_auth_posture(str(tmp_path))
    assert result.mechanism == "undetermined"
    assert result.confidence == 15

    rule_ids = {f.rule_id for f in result.findings}
    assert "auth.no-mechanism-detected" not in rule_ids
    assert "auth.posture-undetermined" in rule_ids

    undetermined = next(f for f in result.findings if f.rule_id == "auth.posture-undetermined")
    assert undetermined.severity.value == "LOW"

    # No foundational penalty should apply — no HIGH finding fired, and
    # auth.posture-undetermined is deliberately not in FOUNDATION_PENALTY_EXTRA.
    assert "auth.posture-undetermined" not in FOUNDATION_PENALTY_EXTRA
    report = calculate_score_report(result.findings)
    assert report.score == 100 - 3  # LOW severity weight only, no extra penalty


def test_py_files_present_no_auth_code_still_none_detected_at_confidence_40(tmp_path):
    # Must NOT regress: a Python server with genuinely no auth code, and no
    # dynamic results, keeps the existing "none-detected" / confidence 40
    # behavior the DVMCP benchmark relies on.
    _write(tmp_path, "server.py", (
        "def add(a, b):\n"
        "    return a + b\n"
    ))

    result = analyze_auth_posture(str(tmp_path))
    assert result.mechanism == "none-detected"
    assert result.confidence == 40

    finding = next(f for f in result.findings if f.rule_id == "auth.no-mechanism-detected")
    assert finding.severity.value == "HIGH"
    assert finding.confidence == 40
