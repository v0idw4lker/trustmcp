"""
Authentication posture assessment — free tier, core.auth_posture.

Determines HOW an MCP server appears to handle authentication — OAuth 2.1,
a static API key, an environment-variable token, or nothing at all — and
flags weak or missing mechanisms.

This is necessarily heuristic, like the rest of the static analysis engine:
it looks for well-known library imports, header/token comparison patterns,
and OAuth grant-type keywords in source code, then combines that with
whatever core.dynamic_client observed about a LIVE server's actual behavior
(401/403 enforcement) when a dynamic scan result is available. Static-only
evidence is inherently weaker than a directly observed live response and is
reported at lower confidence.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from .dynamic_client import DynamicScanResult
from .models import Finding, Severity

IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "env", "dist", "build",
    # "premium" is this repository's own local-only extension package
    # (see mcpwarden/core/plugins.py) — never part of a real target MCP
    # server, only present here because this tool can scan its own repo.
    "premium",
}

OAUTH_INDICATORS = re.compile(
    r"\b(authlib|oauthlib|requests_oauthlib|OAuth2AuthorizationCodeBearer|"
    r"pkce|code_verifier|code_challenge|authorization_code|client_credentials|www-authenticate)\b",
    re.IGNORECASE,
)
JWT_INDICATORS = re.compile(r"\b(pyjwt|jose\.jwt|jwt\.decode|jwt\.encode)\b", re.IGNORECASE)
STATIC_KEY_COMPARISON = re.compile(
    r"(header|token|api[_-]?key|x-api-key)[^\n]{0,40}==\s*[\"'][^\"']{6,}[\"']"
    r"|==\s*[\"'][^\"']{6,}[\"'][^\n]{0,20}(header|token|api[_-]?key)",
    re.IGNORECASE,
)
ENV_TOKEN_USAGE = re.compile(
    r"os\.(?:getenv|environ(?:\.get)?)\(\s*[\"'][^\"']*(?:API_KEY|TOKEN|SECRET|AUTH)[^\"']*[\"']",
    re.IGNORECASE,
)


@dataclass
class AuthPostureResult:
    target_directory: str
    mechanism: str = "unknown"  # "oauth2.1" | "static-api-key" | "env-var-token" | "unknown-but-enforced" | "none-detected"
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _scan_source_for_auth_evidence(target_directory: str) -> tuple[set[str], list[str]]:
    """Returns (mechanism signals found, human-readable evidence lines)."""
    signals: set[str] = set()
    evidence: list[str] = []

    # Scoped to .py source only, deliberately — every pattern below (the
    # os.getenv(...) call shape, the jwt.decode/encode calls, the "=="
    # comparison shape) is Python syntax. Earlier this also scanned
    # .json/.yaml/.toml/.env files, which produced false positives: a
    # previously generated JSON *report* sitting in the target directory
    # contains remediation text like "os.getenv('...')" as advice, which
    # the same regex would misread as real evidence about the target server.
    self_package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for file in files:
            if not file.endswith(".py"):
                continue
            full_path = os.path.join(root, file)
            # Never treat our own installed package source as evidence
            # about the target server's auth mechanism — see the identical
            # exclusion (and rationale) in static_analyzer.scan_directory.
            try:
                is_self = os.path.commonpath([os.path.abspath(full_path), self_package_dir]) == self_package_dir
            except ValueError:
                is_self = False
            if is_self:
                continue
            try:
                with open(full_path, "r", encoding="utf-8-sig", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            if OAUTH_INDICATORS.search(content) or JWT_INDICATORS.search(content):
                signals.add("oauth2.1")
                evidence.append(f"{full_path}: OAuth 2.1 / JWT-related identifiers found.")
            if STATIC_KEY_COMPARISON.search(content):
                signals.add("static-api-key")
                evidence.append(f"{full_path}: direct comparison of a request header/token against a literal string.")
            if ENV_TOKEN_USAGE.search(content):
                signals.add("env-var-token")
                evidence.append(f"{full_path}: an auth-related token is read from an environment variable.")

    return signals, evidence


def analyze_auth_posture(
    target_directory: str,
    dynamic_results: Optional[list[DynamicScanResult]] = None,
) -> AuthPostureResult:
    """
    Combines static source evidence with any live dynamic-scan results to
    classify the server's authentication posture and produce Finding
    objects for weak or missing mechanisms.
    """
    result = AuthPostureResult(target_directory=target_directory)
    signals, evidence = _scan_source_for_auth_evidence(target_directory)
    result.evidence.extend(evidence)

    dynamic_results = dynamic_results or []
    dynamic_auth_enforced: Optional[bool] = None
    dynamic_no_tls = False

    for dr in dynamic_results:
        for f in dr.findings:
            if f.rule_id == "dynamic.no-auth-enforcement":
                dynamic_auth_enforced = False
            if f.rule_id == "dynamic.no-tls":
                dynamic_no_tls = True
        for c in dr.checks_passed:
            if c.startswith("Auth enforcement OK"):
                dynamic_auth_enforced = True

    # --- Classification -----------------------------------------------------
    if "oauth2.1" in signals:
        result.mechanism = "oauth2.1"
        result.confidence = 65 if dynamic_auth_enforced is None else 85
    elif "static-api-key" in signals:
        result.mechanism = "static-api-key"
        result.confidence = 60
    elif "env-var-token" in signals:
        result.mechanism = "env-var-token"
        result.confidence = 55
    elif dynamic_auth_enforced is True:
        # A live probe confirmed something rejects unauthenticated
        # requests, but static analysis could not identify which mechanism
        # — safer to say so explicitly than to guess.
        result.mechanism = "unknown-but-enforced"
        result.confidence = 50
    elif dynamic_auth_enforced is False:
        result.mechanism = "none-detected"
        result.confidence = 90
    else:
        result.mechanism = "none-detected"
        result.confidence = 40

    # --- Findings -------------------------------------------------------------
    if result.mechanism == "none-detected":
        severity = Severity.CRITICAL if dynamic_auth_enforced is False else Severity.HIGH
        result.findings.append(Finding(
            module="auth-posture", rule_id="auth.no-mechanism-detected", title="No authentication mechanism detected",
            description=(
                "Neither the source code nor a live probe (when available) shows evidence of an authentication "
                "mechanism (OAuth 2.1, a static API key, or an environment-variable token)."
            ),
            severity=severity, confidence=result.confidence, location=target_directory,
            remediation="Implement authentication before exposing this server beyond local, trusted use. OAuth 2.1 is the mechanism recommended by the MCP specification for remote servers.",
        ))
    elif result.mechanism == "static-api-key":
        result.findings.append(Finding(
            module="auth-posture", rule_id="auth.static-api-key", title="Authentication relies on a static API key",
            description=(
                "The server appears to authenticate requests by comparing a header/token against a fixed value "
                "in source. Static keys cannot be scoped, auto-rotated, or individually revoked, and a "
                "non-constant-time comparison can itself be a timing side-channel."
            ),
            severity=Severity.MEDIUM, confidence=result.confidence, location=target_directory,
            remediation="Migrate to OAuth 2.1 with short-lived, scoped tokens. If a static key must remain, compare it with a constant-time function (e.g. hmac.compare_digest) and rotate it regularly.",
        ))
    elif result.mechanism == "env-var-token":
        result.findings.append(Finding(
            module="auth-posture", rule_id="auth.env-var-token", title="Authentication relies on an environment-variable token",
            description=(
                "The server reads an authentication token from an environment variable. This avoids hardcoding "
                "the secret, but the token is typically still static, unscoped, and long-lived compared to an OAuth 2.1 flow."
            ),
            severity=Severity.LOW, confidence=result.confidence, location=target_directory,
            remediation="Consider migrating to OAuth 2.1 for scoped, short-lived, individually revocable credentials, particularly for any server reachable over a network.",
        ))
    # "oauth2.1" and "unknown-but-enforced" are not, by themselves, findings
    # — a finding implies something to fix. They are only recorded as
    # evidence/mechanism metadata in the report.

    if dynamic_no_tls and result.mechanism in ("static-api-key", "env-var-token"):
        result.findings.append(Finding(
            module="auth-posture", rule_id="auth.token-over-plaintext", title="Authentication token transmitted without TLS",
            description="The server appears to authenticate with a static token while also being exposed over plain HTTP — the token travels in clear text.",
            severity=Severity.CRITICAL, confidence=80, location=target_directory,
            remediation="Enable HTTPS/TLS immediately; a token sent over plain HTTP can be captured by anyone on the network path.",
        ))

    return result
