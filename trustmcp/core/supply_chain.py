"""
Pre-install supply-chain signals — free tier, core.supply_chain.

Checks that only make sense BEFORE a package is installed, using registry
metadata gathered by core.registry_resolver: package age, days since last
publish, maintainer count (npm only), whether the manifest's repository URL
actually resolves and plausibly matches the package name, and (npm only)
whether package.json declares an install-time lifecycle script.

These are separate from core.static_analyzer / core.auth_posture, which run
unchanged against the extracted source (core.preinstall wires both together)
and already cover unpinned dependencies in the downloaded package.json /
requirements.txt.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from .models import Finding, Severity
from .registry_resolver import RegistryMetadata

# Weak, heuristic thresholds — see the honesty note in static_analyzer's
# CONFIDENCE_DISCLAIMER: these are priors, not measured false-positive rates.
NEW_PACKAGE_THRESHOLD_DAYS = 30
STALE_PACKAGE_THRESHOLD_DAYS = 730


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _normalize_for_compare(s: str) -> str:
    s = s.rsplit("/", 1)[-1]
    s = re.sub(r"\.git$", "", s, flags=re.IGNORECASE)
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _repo_name_resembles_package(repo_url: str, package_name: str) -> bool:
    """Weak heuristic only: neither substring match failing nor succeeding is proof of anything on its own."""
    repo_slug = _normalize_for_compare(repo_url)
    pkg_slug = _normalize_for_compare(package_name.split("/")[-1])  # strip an npm scope, if any
    if not repo_slug or not pkg_slug:
        return True  # insufficient signal either way — don't flag
    return pkg_slug in repo_slug or repo_slug in pkg_slug


def _check_age_and_staleness(metadata: RegistryMetadata, location: str) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    created_dt = _parse_iso(metadata.created)
    if created_dt is not None:
        age_days = (now - created_dt).days
        if age_days < NEW_PACKAGE_THRESHOLD_DAYS:
            findings.append(Finding(
                module="preinstall", rule_id="preinstall.package-very-new",
                title="Package is very new",
                description=(
                    f"This package's first release was {age_days} day(s) ago ({metadata.created}). "
                    "A very new package has a much shorter track record, which is a weaker trust signal on its "
                    "own — not a vulnerability, but relevant to an install decision."
                ),
                severity=Severity.MEDIUM, confidence=60, location=location,
                remediation="Review the source directly before installing; weigh package age alongside the rest of this report, not in isolation.",
            ))

    last_publish_dt = _parse_iso(metadata.last_publish)
    if last_publish_dt is not None:
        stale_days = (now - last_publish_dt).days
        if stale_days > STALE_PACKAGE_THRESHOLD_DAYS:
            findings.append(Finding(
                module="preinstall", rule_id="preinstall.package-stale",
                title="Package has not been updated recently",
                description=(
                    f"The resolved version was last published {stale_days} day(s) ago ({metadata.last_publish}). "
                    "A long-unmaintained package may not have received security fixes."
                ),
                severity=Severity.LOW, confidence=40, location=location,
                remediation="Check the repository for open security issues and confirm the package is still maintained.",
            ))

    return findings


def _check_maintainers(metadata: RegistryMetadata, location: str) -> list[Finding]:
    if metadata.ecosystem != "npm" or metadata.maintainers_count is None:
        return []
    if metadata.maintainers_count > 1:
        return []
    return [Finding(
        module="preinstall", rule_id="preinstall.single-maintainer",
        title="Package has a single maintainer",
        description=(
            f"npm reports {metadata.maintainers_count} maintainer(s) for this package. A single maintainer is a "
            "bus-factor and account-compromise risk: if that one npm account is compromised, there is no second "
            "publisher to notice or block a malicious release."
        ),
        severity=Severity.LOW, confidence=45, location=location,
        remediation="No direct fix — a judgment call. Weigh this alongside the package's other trust signals.",
    )]


def _check_repository(metadata: RegistryMetadata, location: str, *, timeout: float, offline: bool) -> list[Finding]:
    if not metadata.repository_url or offline:
        return []

    try:
        resp = httpx.head(metadata.repository_url, timeout=timeout, follow_redirects=True)
        if resp.status_code >= 400:
            # Some hosts reject HEAD with 405/403 even for a real, public URL — retry with GET before concluding failure.
            resp = httpx.get(metadata.repository_url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError as e:
        return [Finding(
            module="preinstall", rule_id="preinstall.repository-unreachable",
            title="Manifest repository URL does not resolve",
            description=f"The repository URL declared in the package manifest ('{metadata.repository_url}') could not be reached: {e}",
            severity=Severity.MEDIUM, confidence=50, location=location,
            remediation="Confirm the package's real source repository before installing; a manifest pointing at an unreachable URL is a supply-chain red flag.",
        )]

    if resp.status_code >= 400:
        return [Finding(
            module="preinstall", rule_id="preinstall.repository-unreachable",
            title="Manifest repository URL does not resolve",
            description=f"The repository URL declared in the package manifest ('{metadata.repository_url}') returned HTTP {resp.status_code}.",
            severity=Severity.MEDIUM, confidence=55, location=location,
            remediation="Confirm the package's real source repository before installing; a manifest pointing at a dead URL is a supply-chain red flag.",
        )]

    if not _repo_name_resembles_package(metadata.repository_url, metadata.package_name):
        return [Finding(
            module="preinstall", rule_id="preinstall.repository-name-mismatch",
            title="Repository name does not obviously match the package name",
            description=(
                f"The manifest's repository URL ('{metadata.repository_url}') does not obviously correspond to the "
                f"package name ('{metadata.package_name}'). This is a weak, heuristic signal — many legitimately "
                "renamed or reorganized packages will trigger it too."
            ),
            severity=Severity.LOW, confidence=25, location=location,
            remediation="Manually confirm the linked repository is genuinely the source of this package.",
        )]

    return []


def _check_npm_lifecycle_scripts(metadata: RegistryMetadata, location: str) -> list[Finding]:
    if metadata.ecosystem != "npm" or not metadata.install_scripts:
        return []
    findings = []
    for script_name, script_cmd in sorted(metadata.install_scripts.items()):
        findings.append(Finding(
            module="preinstall", rule_id="preinstall.npm-lifecycle-script",
            title=f"npm lifecycle script declared: {script_name}",
            description=(
                f"package.json declares a '{script_name}' script that runs automatically on `npm install`: "
                f"{script_cmd!r}. This is the classic npm supply-chain attack vector — arbitrary code executes on "
                "install, before anyone reviews the package's contents."
            ),
            severity=Severity.HIGH, confidence=70, location=location,
            remediation="Review the script contents before installing. Consider `npm install --ignore-scripts` if the script is not required.",
            code_snippet=f'"{script_name}": "{script_cmd}"',
        ))
    return findings


def assess_supply_chain(metadata: RegistryMetadata, *, timeout: float, offline: bool) -> list[Finding]:
    """Runs every pre-install-only supply-chain check and returns their combined findings."""
    location = f"{metadata.ecosystem}:{metadata.package_name}"
    findings: list[Finding] = []
    findings.extend(_check_age_and_staleness(metadata, location))
    findings.extend(_check_maintainers(metadata, location))
    findings.extend(_check_repository(metadata, location, timeout=timeout, offline=offline))
    findings.extend(_check_npm_lifecycle_scripts(metadata, location))
    return findings
