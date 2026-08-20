"""
JSON reporter — free tier, reporters.json_reporter.

Writes a single, clean, structured JSON report intended for CI/CD pipeline
consumption (parsing scores/findings programmatically, gating a build,
etc.) — as opposed to reporters.cli_reporter (human terminal output) or
reporters.sarif_reporter (GitHub Security tab integration).
"""

from __future__ import annotations

import json
from typing import Any

from ..core.scoring import ScoreReport
from ..utils.exceptions import ReportWriteError


def build_report_dict(
    *,
    tool_version: str,
    target_directory: str,
    targets_scanned: list[str],
    files_scanned: int,
    confidence_disclaimer: str,
    score_report: ScoreReport,
) -> dict[str, Any]:
    return {
        "tool": {"name": "trustmcp", "version": tool_version},
        "target_directory": target_directory,
        "targets_scanned": targets_scanned,
        "files_scanned": files_scanned,
        "confidence_disclaimer": confidence_disclaimer,
        "score": score_report.score,
        "grade": score_report.grade,
        "total_findings": score_report.total_findings,
        "severity_summary": score_report.severity_summary,
        "owasp_coverage": score_report.owasp_coverage,
        "unmapped_findings": score_report.unmapped_findings,
        "findings": [f.to_dict() for f in score_report.findings],
    }


def write_json_report(path: str, report_dict: dict[str, Any]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report_dict, fh, indent=2, ensure_ascii=False)
    except OSError as e:
        raise ReportWriteError(f"Could not write JSON report to '{path}': {e}") from e
