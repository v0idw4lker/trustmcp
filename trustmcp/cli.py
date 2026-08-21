"""
trustmcp CLI — free tier entrypoint.

Usage:
    trustmcp scan --path ./my-mcp-server --mode both \\
        --target "stdio:python3 server.py" --target "url:http://127.0.0.1:8931/mcp"

    trustmcp check npm:@modelcontextprotocol/server-filesystem

Modes:
    static   Source-code analysis only (no running server required).
    dynamic  Live analysis only (requires at least one --target).
    both     Runs static, dynamic (if targets are given), and auth-posture
             analysis, then produces a single unified score/report (default).

Commands:
    scan     Analyze an MCP server you already have on disk (and/or running).
    check    Resolve a registry reference (npm/PyPI/GitHub/server.json) and
             scan it BEFORE installing — downloads and reads only, never runs
             install scripts or executes anything from the package.
"""

from __future__ import annotations

import argparse
import asyncio
import shlex
import sys

from rich.console import Console

from . import __version__
from .core import plugins
from .core.auth_posture import analyze_auth_posture
from .core.dynamic_client import DynamicScanResult, scan_http_target, scan_stdio_target
from .core.models import Finding, Severity
from .core.preinstall import build_verdict, run_preinstall_scan
from .core.scoring import calculate_score_report
from .core.static_analyzer import CONFIDENCE_DISCLAIMER, scan_directory
from .reporters import cli_reporter, json_reporter, sarif_reporter
from .utils.exceptions import InvalidTargetError, ScannerError
from .utils.logging import console, setup_logging

# Imports a locally installed premium module (semantic LLM analysis,
# cross-server toxic-flow detection), if present. This is NOT part of the
# public package — see core/plugins.py for the extension point it registers
# against. Absent for the vast majority of users and silently skipped.
try:
    import premium  # noqa: F401
except ImportError:
    pass

SEVERITY_THRESHOLDS = ("none", "low", "medium", "high", "critical")
_SEVERITY_RANK_BY_NAME = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _parse_targets(raw_targets: list[str]) -> list[tuple[str, str]]:
    """Parses --target values into (kind, value) pairs. Accepted format: 'stdio:<command>' or 'url:<url>'."""
    targets = []
    for raw in raw_targets:
        if ":" not in raw:
            raise InvalidTargetError(f"Invalid target (missing 'stdio:' or 'url:' prefix): {raw!r}")
        kind, value = raw.split(":", 1)
        kind = kind.strip().lower()
        value = value.strip()
        if kind not in ("stdio", "url"):
            raise InvalidTargetError(f"Unknown target prefix '{kind}' (use 'stdio:' or 'url:'): {raw!r}")
        if not value:
            raise InvalidTargetError(f"Empty target after the '{kind}:' prefix: {raw!r}")
        targets.append((kind, value))
    return targets


async def _scan_dynamic_targets(targets: list[tuple[str, str]], enable_fuzzing: bool) -> list[DynamicScanResult]:
    results: list[DynamicScanResult] = []
    for kind, value in targets:
        if kind == "stdio":
            parts = shlex.split(value)
            if not parts:
                console.print(f"[bold red]Empty stdio command for target: {value!r}[/bold red]")
                continue
            result = await scan_stdio_target(command=parts[0], args=parts[1:], enable_fuzzing=enable_fuzzing)
        else:
            result = await scan_http_target(value, enable_fuzzing=enable_fuzzing)
        results.append(result)
    return results


def _print_dynamic_summary(console: Console, result: DynamicScanResult) -> None:
    console.print(f"\n[bold blue]=== Dynamic scan: {result.target} ({result.transport}) ===[/bold blue]")
    if result.error and not result.connected:
        console.print(f"[bold red]✖ Connection failed: {result.error}[/bold red]")
    if result.connected:
        console.print(
            f"[green]✔ Connected. Tools: {len(result.tools)} | Resources: {len(result.resources)} | "
            f"Prompts: {len(result.prompts)}[/green]"
        )
        for t in result.tools:
            console.print(f"  🔧 [bold]{t['name']}[/bold]: {t['description']}")
        for r in result.resources:
            console.print(f"  📄 [bold]{r['name']}[/bold]: {r['description']}")
        for p in result.prompts:
            console.print(f"  💬 [bold]{p['name']}[/bold]: {p['description']}")
    for c in result.checks_passed:
        console.print(f"  [green]✔ {c}[/green]")


def _fail_on_exceeded(findings: list[Finding], threshold: str) -> bool:
    if threshold == "none":
        return False
    min_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}[threshold]
    for f in findings:
        sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
        if _SEVERITY_RANK_BY_NAME.get(sev, 0) >= min_rank:
            return True
    return False


def _run_scan(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose)
    console.rule("[bold blue]trustmcp — MCP Server Security Scan[/bold blue]")

    all_findings: list[Finding] = []
    files_scanned = 0
    targets_scanned: list[str] = []
    dynamic_results: list[DynamicScanResult] = []

    # --- Static analysis ------------------------------------------------------
    if args.mode in ("static", "both"):
        console.rule("[bold blue]Static analysis[/bold blue]")
        static_result = scan_directory(args.path)
        files_scanned = static_result.files_scanned
        all_findings.extend(static_result.findings)
        console.print(f"Scanned {files_scanned} Python file(s) under '{args.path}'. {len(static_result.findings)} finding(s).")

    # --- Dynamic analysis -------------------------------------------------------
    if args.mode in ("dynamic", "both"):
        try:
            targets = _parse_targets(args.target)
        except InvalidTargetError as e:
            console.print(f"[bold red]{e}[/bold red]")
            return 2

        if not targets:
            if args.mode == "dynamic":
                console.print("[bold red]--mode dynamic requires at least one --target.[/bold red]")
                return 2
            console.print(
                "\n[yellow]No --target given — skipping dynamic analysis. "
                'Example: --target "stdio:python3 server.py"[/yellow]'
            )
        else:
            console.rule("[bold blue]Dynamic analysis[/bold blue]")
            dynamic_results = asyncio.run(_scan_dynamic_targets(targets, enable_fuzzing=not args.no_fuzz))
            for result in dynamic_results:
                _print_dynamic_summary(console, result)
                all_findings.extend(result.findings)
                targets_scanned.append(result.target)

    # --- Authentication posture ---------------------------------------------
    # Runs whenever a path was given; strengthened by dynamic-scan evidence when available.
    console.rule("[bold blue]Authentication posture[/bold blue]")
    auth_result = analyze_auth_posture(args.path, dynamic_results=dynamic_results)
    console.print(f"Detected mechanism: [bold]{auth_result.mechanism}[/bold] (confidence {auth_result.confidence}%)")
    all_findings.extend(auth_result.findings)

    # --- Premium modules, if installed locally (see core/plugins.py) -----------
    all_findings.extend(plugins.run_registered(target_directory=args.path, dynamic_results=dynamic_results))

    # --- Scoring ----------------------------------------------------------------
    console.rule("[bold blue]Score[/bold blue]")
    score_report = calculate_score_report(all_findings)
    remediations = cli_reporter.build_remediations(all_findings)
    cli_reporter.print_full_report(console, score_report, remediations, plugins.unregistered_known_modules())

    # --- Reports on disk ----------------------------------------------------
    try:
        if not args.no_json:
            report_dict = json_reporter.build_report_dict(
                tool_version=__version__,
                target_directory=args.path,
                targets_scanned=targets_scanned,
                files_scanned=files_scanned,
                confidence_disclaimer=CONFIDENCE_DISCLAIMER,
                score_report=score_report,
            )
            json_reporter.write_json_report(args.json_output, report_dict)
            console.print(f"\n[bold green]✔ JSON report written: {args.json_output}[/bold green]")

        if not args.no_sarif:
            sarif_log = sarif_reporter.build_sarif(all_findings, tool_version=__version__)
            sarif_reporter.write_sarif(args.sarif_output, sarif_log)
            console.print(
                f"[bold green]✔ SARIF report written: {args.sarif_output}[/bold green] "
                "[dim](upload with github/codeql-action/upload-sarif for the GitHub Security tab)[/dim]"
            )
    except ScannerError as e:
        console.print(f"[bold red]{e}[/bold red]")
        return 1

    if _fail_on_exceeded(all_findings, args.fail_on):
        console.print(
            f"\n[bold red]✖ Exiting non-zero: a finding at or above severity '{args.fail_on}' was found (--fail-on).[/bold red]"
        )
        return 1

    return 0


def _run_check(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose)
    console.rule("[bold blue]trustmcp check — Pre-Install MCP Server Scan[/bold blue]")
    console.print(f"Resolving reference: [bold]{args.reference}[/bold]")

    max_size_bytes = int(args.max_size * 1024 * 1024)
    result = run_preinstall_scan(args.reference, timeout=args.timeout, max_size_bytes=max_size_bytes, offline=args.offline)

    console.print(
        f"[green]✔ Resolved {result.metadata.ecosystem}:{result.metadata.package_name} "
        f"@ {result.metadata.resolved_version}[/green]"
    )
    console.print("Downloaded and extracted into an isolated temp directory; nothing from the package was executed.")
    cli_reporter.print_preinstall_metadata(console, result.metadata)

    console.rule("[bold blue]Static + auth-posture analysis (extracted source)[/bold blue]")
    console.print(f"Scanned {result.files_scanned} Python file(s) from the downloaded package.")

    console.rule("[bold blue]Score[/bold blue]")
    score_report = calculate_score_report(result.findings)
    remediations = cli_reporter.build_remediations(result.findings)
    verdict = build_verdict(score_report)
    cli_reporter.print_verdict(console, verdict)
    cli_reporter.print_full_report(console, score_report, remediations, plugins.unregistered_known_modules())

    try:
        if not args.no_json:
            report_dict = json_reporter.build_report_dict(
                tool_version=__version__,
                target_directory=args.reference,
                targets_scanned=[f"{result.metadata.ecosystem}:{result.metadata.package_name}@{result.metadata.resolved_version}"],
                files_scanned=result.files_scanned,
                confidence_disclaimer=CONFIDENCE_DISCLAIMER,
                score_report=score_report,
            )
            report_dict["verdict"] = verdict
            report_dict["preinstall"] = {
                "reference": result.reference,
                "ecosystem": result.metadata.ecosystem,
                "package_name": result.metadata.package_name,
                "resolved_version": result.metadata.resolved_version,
                "download_url": result.metadata.download_url,
                "repository_url": result.metadata.repository_url,
                "created": result.metadata.created,
                "last_publish": result.metadata.last_publish,
                "maintainers_count": result.metadata.maintainers_count,
            }
            json_reporter.write_json_report(args.json_output, report_dict)
            console.print(f"\n[bold green]✔ JSON report written: {args.json_output}[/bold green]")

        if not args.no_sarif:
            sarif_log = sarif_reporter.build_sarif(result.findings, tool_version=__version__)
            sarif_reporter.write_sarif(args.sarif_output, sarif_log)
            console.print(f"[bold green]✔ SARIF report written: {args.sarif_output}[/bold green]")
    except ScannerError as e:
        console.print(f"[bold red]{e}[/bold red]")
        return 1

    if _fail_on_exceeded(result.findings, args.fail_on):
        console.print(
            f"\n[bold red]✖ Exiting non-zero: a finding at or above severity '{args.fail_on}' was found (--fail-on).[/bold red]"
        )
        return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trustmcp", description="Security scanner for MCP (Model Context Protocol) servers.")
    parser.add_argument("--version", action="version", version=f"trustmcp {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a security scan against an MCP server.")
    scan_parser.add_argument(
        "--path", type=str, default=".",
        help="Directory to statically scan and to search for auth-posture evidence (default: '.').",
    )
    scan_parser.add_argument(
        "--mode", choices=("static", "dynamic", "both"), default="both",
        help="Which analysis modules to run (default: both).",
    )
    scan_parser.add_argument(
        "--target", action="append", default=[], metavar="stdio:<cmd>|url:<url>",
        help='Live MCP server to scan dynamically. Repeatable. '
             'Example: --target "stdio:python3 server.py" --target "url:http://127.0.0.1:8931/mcp"',
    )
    scan_parser.add_argument("--no-fuzz", action="store_true", help="Disable tool input fuzzing during dynamic analysis.")
    scan_parser.add_argument(
        "--json-output", type=str, default="mcp-scan-report.json",
        help="Output path for the JSON report (default: mcp-scan-report.json).",
    )
    scan_parser.add_argument("--no-json", action="store_true", help="Do not write a JSON report.")
    scan_parser.add_argument(
        "--sarif-output", type=str, default="mcp-scan-report.sarif",
        help="Output path for the SARIF report (default: mcp-scan-report.sarif).",
    )
    scan_parser.add_argument("--no-sarif", action="store_true", help="Do not write a SARIF report.")
    scan_parser.add_argument(
        "--fail-on", choices=SEVERITY_THRESHOLDS, default="none",
        help="Exit with a non-zero status if a finding at or above this severity is present (for CI/CD gating). Default: none.",
    )
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")

    check_parser = subparsers.add_parser(
        "check",
        help="Scan an MCP server BEFORE installing it, resolved directly from a registry reference.",
    )
    check_parser.add_argument(
        "reference", type=str,
        help="'npm:<package>[@version]', 'pypi:<package>[==version]', 'github:<owner>/<repo>[@ref]', or a server.json URL.",
    )
    check_parser.add_argument("--offline", action="store_true", help="Refuse any network access; fail clearly instead of hanging.")
    check_parser.add_argument(
        "--timeout", type=float, default=30.0,
        help="Network timeout in seconds for registry lookups and the download (default: 30).",
    )
    check_parser.add_argument(
        "--max-size", type=float, default=50.0,
        help="Maximum download size in MB; aborts if exceeded (default: 50).",
    )
    check_parser.add_argument(
        "--json-output", type=str, default="mcp-check-report.json",
        help="Output path for the JSON report (default: mcp-check-report.json).",
    )
    check_parser.add_argument("--no-json", action="store_true", help="Do not write a JSON report.")
    check_parser.add_argument(
        "--sarif-output", type=str, default="mcp-check-report.sarif",
        help="Output path for the SARIF report (default: mcp-check-report.sarif).",
    )
    check_parser.add_argument("--no-sarif", action="store_true", help="Do not write a SARIF report.")
    check_parser.add_argument(
        "--fail-on", choices=SEVERITY_THRESHOLDS, default="none",
        help="Exit with a non-zero status if a finding at or above this severity is present (for CI/CD gating). Default: none.",
    )
    check_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command in ("scan", "check"):
        runner = _run_scan if args.command == "scan" else _run_check
        try:
            exit_code = runner(args)
        except ScannerError as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
            sys.exit(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            sys.exit(130)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
