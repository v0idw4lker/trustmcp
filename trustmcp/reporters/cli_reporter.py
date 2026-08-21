"""
CLI reporter — free tier, reporters.cli_reporter.

Renders the unified scan result as a color-coded terminal report using
rich: an overall grade/score panel, a severity breakdown table, an OWASP
MCP Top 10 coverage table, per-finding detail grouped by location, and a
deduplicated, severity-ordered remediation checklist.
"""

from __future__ import annotations

from typing import Any, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.models import Finding, Severity, SEVERITY_RANK
from ..core.scoring import ScoreReport

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def _grade_color(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"


def print_score_panel(console: Console, report: ScoreReport) -> None:
    color = _grade_color(report.score)
    console.print()
    console.print(Panel.fit(
        f"[bold {color}]Grade: {report.grade}[/bold {color}]   Score: [bold {color}]{report.score}/100[/bold {color}]\n"
        f"Total findings across all modules: {report.total_findings}",
        title="trustmcp — Security Report",
        border_style=color,
    ))


def print_severity_table(console: Console, report: ScoreReport) -> None:
    table = Table(title="Findings by Severity")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = report.severity_summary.get(sev.value, 0)
        style = SEVERITY_STYLE[sev]
        table.add_row(f"[{style}]{sev.value}[/{style}]", str(count))
    console.print(table)


def print_owasp_table(console: Console, report: ScoreReport) -> None:
    if not report.owasp_coverage:
        return
    table = Table(title="OWASP MCP Top 10 Coverage (MCP01:2025-MCP10:2025)")
    table.add_column("Category")
    table.add_column("Findings", justify="right")
    for category, count in sorted(report.owasp_coverage.items()):
        table.add_row(category, str(count))
    console.print(table)
    if report.unmapped_findings:
        console.print(
            f"[dim]{report.unmapped_findings} finding(s) have no direct OWASP MCP Top 10 match "
            "(not forced into a category).[/dim]"
        )


def print_findings_detail(console: Console, findings: list[Finding]) -> None:
    if not findings:
        console.print("\n[bold green]No findings — clean scan.[/bold green]")
        return

    console.print("\n[bold]Findings (grouped by location):[/bold]")
    by_location: dict[str, list[Finding]] = {}
    for f in findings:
        by_location.setdefault(f.location, []).append(f)

    for location, items in by_location.items():
        console.print(f"\n[bold blue]{location}[/bold blue]")
        for f in sorted(items, key=lambda x: SEVERITY_RANK.get(x.severity, 0), reverse=True):
            style = SEVERITY_STYLE.get(f.severity, "white")
            sev_text = f.severity.value if isinstance(f.severity, Severity) else f.severity
            console.print(f"  [{style}]✖ [{sev_text}][/{style}] line {f.line}: {f.title}")
            console.print(f"    [dim]{f.description}[/dim]")
            if f.code_snippet:
                console.print(f"    [dim]Code: {f.code_snippet}[/dim]")


def build_remediations(findings: list[Finding]) -> list[dict[str, str]]:
    """Deduplicates remediation text, keeping the highest severity seen for each distinct recommendation."""
    bucket: dict[str, Severity] = {}
    for f in findings:
        if not f.remediation:
            continue
        if f.remediation not in bucket or SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(bucket[f.remediation], 0):
            bucket[f.remediation] = f.severity
    ordered = sorted(bucket.items(), key=lambda kv: SEVERITY_RANK.get(kv[1], 0), reverse=True)
    return [{"severity": sev.value, "text": text} for text, sev in ordered]


def print_remediations(console: Console, remediations: list[dict[str, str]]) -> None:
    console.print("\n[bold]Remediation checklist (ordered by severity, deduplicated):[/bold]")
    if not remediations:
        console.print("  [bold green]Nothing to fix.[/bold green]")
        return
    for i, rec in enumerate(remediations, 1):
        style = SEVERITY_STYLE.get(Severity(rec["severity"]), "white")
        console.print(f"  {i}. [{style}][{rec['severity']}][/{style}] {rec['text']}")


def print_verdict(console: Console, verdict: str) -> None:
    style = "bold red" if "Do not install" in verdict else "bold green"
    console.print(Panel.fit(f"[{style}]{verdict}[/{style}]", title="Install Verdict", border_style=style.split()[-1]))


def print_preinstall_metadata(console: Console, metadata: Any) -> None:
    """Prints the pre-install registry signals (`trustmcp check`) — informational, not part of the score."""
    table = Table(title="Pre-Install Signals")
    table.add_column("Signal")
    table.add_column("Value")
    table.add_row("Ecosystem", metadata.ecosystem)
    table.add_row("Package", metadata.package_name)
    table.add_row("Resolved version", str(metadata.resolved_version))
    table.add_row("Repository", metadata.repository_url or "[dim]not declared[/dim]")
    table.add_row("First release", metadata.created or "[dim]unknown[/dim]")
    table.add_row("Last publish", metadata.last_publish or "[dim]unknown[/dim]")
    if metadata.ecosystem == "npm":
        table.add_row("Maintainers", str(metadata.maintainers_count) if metadata.maintainers_count is not None else "[dim]unknown[/dim]")
    elif metadata.ecosystem == "pypi":
        table.add_row("Maintainers", "[dim]unavailable — PyPI's JSON API does not expose this (known gap)[/dim]")
    if metadata.install_scripts:
        table.add_row("npm lifecycle scripts", ", ".join(sorted(metadata.install_scripts)))
    console.print(table)


def print_premium_upsell(console: Console, unregistered: Sequence[Any]) -> None:
    if not unregistered:
        return
    console.print("\n[bold magenta]Premium capabilities (not included in the free tier):[/bold magenta]")
    for module in unregistered:
        console.print(f"  ✦ [bold]{module.display_name}[/bold] — {module.description}")


def print_full_report(
    console: Console,
    report: ScoreReport,
    remediations: list[dict[str, str]],
    unregistered_premium: Sequence[Any] = (),
) -> None:
    print_score_panel(console, report)
    print_severity_table(console, report)
    print_owasp_table(console, report)
    print_findings_detail(console, report.findings)
    print_remediations(console, remediations)
    print_premium_upsell(console, unregistered_premium)
