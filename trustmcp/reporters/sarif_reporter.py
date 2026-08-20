"""
SARIF reporter — free tier, reporters.sarif_reporter.

Converts the unified list of Finding objects (core.models.Finding) into a
single SARIF 2.1.0 log. Any repository that uploads report.sarif via
`github/codeql-action/upload-sarif` in CI automatically gets the findings
in Security > Code scanning, with severity (critical/high/medium/low) and a
deep-link to the source line, where a real file location exists.

Real complication, not a theoretical one: SARIF was designed for findings
tied to ONE source file. Findings from the dynamic and auth-posture modules
describe a running MCP SERVER, not a specific line of code. SARIF still
requires a physical location per result for tools (including GitHub) to
render it — the approach here: a static finding's own file path is used
as-is; a live-target finding uses the target label itself as the location
string (e.g. "stdio:python3 server.py" or a URL), so it stays visible and
attributable without inventing a fake file that does not exist in the repo.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
GitHub docs: https://docs.github.com/en/code-security/code-scanning
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..core.models import Finding, Severity
from ..utils.exceptions import ReportWriteError

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

TOOL_NAME = "trustmcp"
TOOL_INFORMATION_URI = "https://github.com/v0idw4lker/trustmcp"

# SARIF "level" (error/warning/note) — used by most generic SARIF consumers
# to decide how a result is displayed.
SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# "security-severity" — a GitHub-specific extension (properties.security-severity,
# string, 0.0-10.0) that drives the Critical/High/Medium/Low badge in the
# Security tab. Without it, GitHub shows everything as a generic "warning"
# with no visual triage. GitHub buckets: critical >= 9.0, high 7.0-8.9,
# medium 4.0-6.9, low 0.1-3.9.
SEVERITY_TO_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "4.5",
    Severity.LOW: "1.5",
}


def _slugify(text: str) -> str:
    text = (text or "unknown").lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "unknown"


def _clean_uri(path: str) -> str:
    """Normalizes a filesystem path into a clean relative URI for SARIF (POSIX separators, no leading './')."""
    path = (path or "unknown").replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    return path


def _make_rule(rule_id: str, short_description: str, full_description: str, severity: Severity) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": _slugify(short_description).replace("-", "_"),
        "shortDescription": {"text": short_description},
        "fullDescription": {"text": full_description or short_description},
        "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(severity, "warning")},
        "helpUri": "https://owasp.org/www-project-mcp-top-10/",
        "properties": {
            "tags": ["security", "mcp"],
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(severity, "4.5"),
            "problem.severity": (severity.value if isinstance(severity, Severity) else str(severity)).lower(),
        },
    }


def _make_result(rule_id: str, severity: Severity, message: str, uri: str, start_line: int = 1) -> dict[str, Any]:
    try:
        line = max(1, int(start_line or 1))
    except (TypeError, ValueError):
        line = 1
    return {
        "ruleId": rule_id,
        "level": SEVERITY_TO_LEVEL.get(severity, "warning"),
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _clean_uri(uri)}, "region": {"startLine": line}}}],
    }


def build_sarif(findings: list[Finding], tool_version: str) -> dict[str, Any]:
    """Assembles a single SARIF log from every Finding produced by the pipeline. Rules are deduplicated by ruleId."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rules.setdefault(f.rule_id, _make_rule(f.rule_id, f.title, f.description, f.severity))

        message = f.description
        if f.cwe:
            message += f" (CWE: {f.cwe}, confidence {f.confidence}%)."
        if f.owasp_category:
            message += f" [{f.owasp_category}]"
        if f.remediation:
            message += f" Remediation: {f.remediation}"

        results.append(_make_result(f.rule_id, f.severity, message, f.location, f.line))

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "informationUri": TOOL_INFORMATION_URI,
                    "version": tool_version,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif(path: str, sarif_log: dict[str, Any]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif_log, fh, indent=2, ensure_ascii=False)
    except OSError as e:
        raise ReportWriteError(f"Could not write SARIF report to '{path}': {e}") from e
