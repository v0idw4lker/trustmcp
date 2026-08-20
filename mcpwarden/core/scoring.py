"""
Scoring engine — free tier, core.scoring.

Aggregates Finding objects from every analysis module (static, dynamic,
auth-posture, and any premium module registered via core.plugins) into a
single A-F score, and maps each finding to an OWASP MCP Top 10 (MCP01:2025
- MCP10:2025) category where a clear match exists.

Scoring logic:
  - Every finding costs points according to its severity (SEVERITY_WEIGHTS
    in core.models).
  - Two "foundational" categories — missing TLS, missing auth enforcement,
    and no detected auth mechanism at all — incur an ADDITIONAL penalty on
    top of their standard severity deduction, because they are
    prerequisites the rest of a report's findings are conditioned on, not
    just one issue among many.
  - Findings without a direct OWASP match are NOT forced into a category —
    an inaccurate mapping is worse than an honest "unmapped" count.

Design note: unlike the original prototype, findings already arrive here as
Finding objects carrying a stable rule_id (see core.models). The OWASP
mapping below is keyed by rule_id, not by free-text titles — a wording
change to a finding's title can no longer silently break its OWASP
classification, which was a real bug in the previous text-keyed mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Severity, SEVERITY_WEIGHTS

# Additional penalty for foundational categories, ON TOP OF the standard
# severity deduction each already receives (e.g. dynamic.no-tls is already
# CRITICAL=25 via SEVERITY_WEIGHTS; this adds further penalty because these
# are foundational, blocking controls rather than one issue among many).
FOUNDATION_PENALTY_EXTRA: dict[str, int] = {
    "dynamic.no-tls": 15,
    "dynamic.no-auth-enforcement": 10,
    "auth.no-mechanism-detected": 10,
}

# Explicit mapping: rule_id -> OWASP MCP Top 10 (MCP01:2025-MCP10:2025).
# Source: owasp.org/www-project-mcp-top-10 (beta; categories are stable,
# descriptions may still evolve).
OWASP_CATEGORY_MAP: dict[str, str] = {
    # Static — secrets / token mismanagement
    "static.secret-openai-key": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-anthropic-key": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-github-token": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-aws-key": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-stripe-key": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-google-key": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-slack-token": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.secret-pem-private-key": "MCP01:2025 Token Mismanagement & Secret Exposure",
    "static.mcp-hardcoded-secret": "MCP01:2025 Token Mismanagement & Secret Exposure",
    # Static — tool poisoning / hidden content
    "static.hidden-unicode": "MCP03:2025 Tool Poisoning",
    # Static — command injection / execution
    "static.dangerous-eval-exec": "MCP05:2025 Command Injection & Execution",
    "static.os-system": "MCP05:2025 Command Injection & Execution",
    "static.os-popen": "MCP05:2025 Command Injection & Execution",
    "static.subprocess-shell-true": "MCP05:2025 Command Injection & Execution",
    "static.pickle-deserialization": "MCP05:2025 Command Injection & Execution",
    "static.yaml-unsafe-load": "MCP05:2025 Command Injection & Execution",
    "static.path-traversal-open-param": "MCP05:2025 Command Injection & Execution",
    # Static — supply chain
    "static.dependency-unpinned": "MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
    "static.dependency-weak-constraint": "MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
    "static.dependency-known-vulnerable": "MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
    "static.npm-no-lockfile": "MCP04:2025 Software Supply Chain Attacks & Dependency Tampering",
    # Static — exposure
    "static.mcp-bind-all-interfaces": "MCP07:2025 Insufficient Authentication & Authorization",
    # Dynamic
    "dynamic.no-auth-enforcement": "MCP07:2025 Insufficient Authentication & Authorization",
    "dynamic.unexpected-auth-response": "MCP07:2025 Insufficient Authentication & Authorization",
    "dynamic.hidden-unicode-description": "MCP03:2025 Tool Poisoning",
    "dynamic.fuzz-crash": "MCP05:2025 Command Injection & Execution",
    "dynamic.fuzz-stack-trace-leak": "MCP10:2025 Context Injection & Over-Sharing",
    # Auth posture
    "auth.no-mechanism-detected": "MCP07:2025 Insufficient Authentication & Authorization",
    "auth.static-api-key": "MCP07:2025 Insufficient Authentication & Authorization",
    "auth.env-var-token": "MCP07:2025 Insufficient Authentication & Authorization",
    "auth.token-over-plaintext": "MCP01:2025 Token Mismanagement & Secret Exposure",
    # "dynamic.no-tls" is intentionally NOT mapped — general transport
    # security, not specific to an MCP Top 10 category.
}


@dataclass
class ScoreReport:
    score: int
    grade: str
    total_findings: int
    severity_summary: dict[str, int]
    owasp_coverage: dict[str, int]
    unmapped_findings: int
    findings: list[Finding] = field(default_factory=list)


def _grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def calculate_score_report(findings: list[Finding]) -> ScoreReport:
    """
    Computes the unified A-F score for a flat list of Finding objects drawn
    from every module that ran (static, dynamic, auth-posture, and any
    registered premium module). Sets each finding's owasp_category in place
    based on its rule_id.
    """
    rule_ids_present = {f.rule_id for f in findings}

    score = 100
    for rule_id, extra_penalty in FOUNDATION_PENALTY_EXTRA.items():
        if rule_id in rule_ids_present:
            score -= extra_penalty

    for f in findings:
        f.owasp_category = OWASP_CATEGORY_MAP.get(f.rule_id, f.owasp_category)
        score -= SEVERITY_WEIGHTS.get(f.severity, 8)

    score = max(0, score)
    grade = _grade_for(score)

    severity_summary = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
        if sev in severity_summary:
            severity_summary[sev] += 1

    owasp_coverage: dict[str, int] = {}
    unmapped = 0
    for f in findings:
        if f.owasp_category:
            owasp_coverage[f.owasp_category] = owasp_coverage.get(f.owasp_category, 0) + 1
        else:
            unmapped += 1

    return ScoreReport(
        score=score, grade=grade, total_findings=len(findings),
        severity_summary=severity_summary, owasp_coverage=owasp_coverage,
        unmapped_findings=unmapped, findings=findings,
    )
