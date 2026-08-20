"""
Static analysis engine (SAST) — free tier, core.static_analyzer.

Scans MCP server source code WITHOUT executing it:
  - AST + regex detection of dangerous functions (eval/exec, os.system,
    os.popen, subprocess with shell=True, pickle deserialization, unsafe
    YAML loading, path-traversal-shaped open() calls).
  - Hardcoded secrets / credential detection.
  - Hidden/obfuscated Unicode in source text (zero-width characters,
    bidirectional control characters, and the Unicode Tag block used for
    invisible "ASCII smuggling" against LLMs).
  - MCP manifest (mcp.json / manifest.json) misconfiguration checks.
  - Dependency auditing for requirements.txt and package.json: unpinned or
    weakly constrained versions, missing lockfiles, plus a small curated
    list of packages with well-known, high-impact CVEs.

Every function in this module returns Finding objects (core.models.Finding)
so downstream code (scoring, every reporter) never has to special-case
"static" findings differently from dynamic or auth-posture ones.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import Finding, Severity
from .text_safety import find_hidden_unicode

logger = logging.getLogger("trustmcp")

# Directories skipped during the recursive walk: virtual environments, VCS
# metadata, and build artifacts never contain code the user wrote, and
# walking into them wastes time and produces noise from third-party library
# code the user does not control.
IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "env", ".env",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", ".ruff_cache",
}

# Honest disclaimer about what "confidence" means in this report. These are
# per-rule heuristic priors (how specific/unambiguous the signature is), not
# a statistically measured false-positive rate.
CONFIDENCE_DISCLAIMER = (
    "'confidence' values are heuristic per-rule priors (how specific the signature is), "
    "not a statistically measured false-positive rate. Empirical calibration against "
    "known-vulnerable and clean MCP servers is tracked on the project roadmap."
)

SECRET_PATTERNS: dict[str, dict[str, Any]] = {
    "static.secret-openai-key": {
        "title": "Exposed OpenAI API key",
        "pattern": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
        "severity": Severity.CRITICAL, "cwe": "CWE-798", "confidence": 85,
        "description": "A hardcoded OpenAI API key was found in source code.",
        "remediation": "Move the key to an environment variable (e.g. os.getenv('OPENAI_API_KEY')) loaded from a .env file excluded from version control.",
    },
    "static.secret-anthropic-key": {
        "title": "Exposed Anthropic API key",
        "pattern": re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
        "severity": Severity.CRITICAL, "cwe": "CWE-798", "confidence": 90,
        "description": "A hardcoded Anthropic API key was found in source code.",
        "remediation": "Move the key to an environment variable loaded from a .env file excluded from version control.",
    },
    "static.secret-github-token": {
        "title": "Exposed GitHub token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        "severity": Severity.CRITICAL, "cwe": "CWE-798", "confidence": 90,
        "description": "A hardcoded GitHub token (PAT/OAuth/App) was found in source code.",
        "remediation": "Revoke the token immediately in GitHub settings and move it to an environment variable.",
    },
    "static.secret-aws-key": {
        "title": "Exposed AWS access key",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": Severity.CRITICAL, "cwe": "CWE-798", "confidence": 90,
        "description": "A hardcoded AWS Access Key ID was found in source code.",
        "remediation": "Revoke the key in IAM and move credentials to environment variables or an IAM role.",
    },
    "static.secret-stripe-key": {
        "title": "Exposed Stripe key",
        "pattern": re.compile(r"(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{20,}"),
        "severity": Severity.CRITICAL, "cwe": "CWE-798", "confidence": 90,
        "description": "A hardcoded Stripe secret/restricted key was found in source code.",
        "remediation": "Revoke the key in the Stripe dashboard and move it to an environment variable.",
    },
    "static.secret-google-key": {
        "title": "Exposed Google API key",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": Severity.HIGH, "cwe": "CWE-798", "confidence": 85,
        "description": "A hardcoded Google API key was found in source code.",
        "remediation": "Restrict or revoke the key in Google Cloud Console and move it to an environment variable.",
    },
    "static.secret-slack-token": {
        "title": "Exposed Slack token",
        "pattern": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        "severity": Severity.HIGH, "cwe": "CWE-798", "confidence": 85,
        "description": "A hardcoded Slack token was found in source code.",
        "remediation": "Revoke the token in Slack App settings and move it to an environment variable.",
    },
    "static.secret-pem-private-key": {
        "title": "Exposed PEM private key",
        "pattern": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": Severity.CRITICAL, "cwe": "CWE-321", "confidence": 95,
        "description": "A PEM private key block is embedded directly in code or the repository.",
        "remediation": "Remove the key from the repository, revoke it if it has ever been pushed publicly, and load it from secret storage.",
    },
}


class SecurityASTVisitor(ast.NodeVisitor):
    """
    Structural AST visitor for detections that plain regex line-matching
    cannot express: dangerous calls, and open() calls where the path
    expression references a function parameter (a possible path-traversal
    sink if that parameter is attacker-controlled — e.g. an MCP tool argument).
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[Finding] = []
        # Stack of parameter-name sets, one per function scope currently
        # entered. Global scope = empty set.
        self.scope_stack: list[set[str]] = [set()]

    def _params_in_scope(self) -> set[str]:
        params: set[str] = set()
        for scope in self.scope_stack:
            params |= scope
        return params

    @staticmethod
    def _collect_param_names(node) -> set[str]:
        args = node.args
        names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        if args.vararg:
            names.add(args.vararg.arg)
        if args.kwarg:
            names.add(args.kwarg.arg)
        return names

    def _visit_function(self, node) -> None:
        self.scope_stack.append(self._collect_param_names(node))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _add(self, node: ast.AST, rule_id: str, title: str, description: str,
              severity: Severity, cwe: str, confidence: int, remediation: str, snippet: str) -> None:
        self.findings.append(Finding(
            module="static", rule_id=rule_id, title=title, description=description,
            severity=severity, confidence=confidence, location=self.filepath,
            line=getattr(node, "lineno", 1), cwe=cwe, remediation=remediation, code_snippet=snippet,
        ))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        if isinstance(func, ast.Name):
            if func.id in ("eval", "exec"):
                self._add(
                    node, "static.dangerous-eval-exec", f"Dangerous function usage ({func.id})",
                    f"Use of {func.id}() allows execution of arbitrary code at runtime from its argument.",
                    Severity.CRITICAL, "CWE-95", 95,
                    "Avoid eval/exec entirely. Use a safe parser (e.g. ast.literal_eval) for data, never for code.",
                    f"{func.id}(...)",
                )
            elif func.id == "open" and node.args:
                self._check_path_traversal(node, node.args[0])

        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            owner, attr = func.value.id, func.attr
            if owner == "os" and attr == "system":
                self._add(
                    node, "static.os-system", "System command execution (os.system)",
                    "os.system runs a command directly through the shell and is vulnerable to command injection.",
                    Severity.HIGH, "CWE-78", 90,
                    "Use the subprocess module with an argument list and shell=False.", "os.system(...)",
                )
            elif owner == "os" and attr == "popen":
                self._add(
                    node, "static.os-popen", "System command execution (os.popen)",
                    "os.popen runs a command through the shell and is vulnerable to command injection.",
                    Severity.HIGH, "CWE-78", 90,
                    "Use the subprocess module with an argument list and shell=False.", "os.popen(...)",
                )
            elif owner == "subprocess" and attr in ("run", "Popen", "call", "check_output", "check_call"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self._add(
                            node, "static.subprocess-shell-true", "Unsafe shell command execution (subprocess shell=True)",
                            "The subprocess call uses shell=True, exposing the application to command injection.",
                            Severity.CRITICAL, "CWE-78", 95,
                            "Set shell=False and pass arguments as a list.", "subprocess(..., shell=True)",
                        )
            elif owner == "pickle" and attr in ("load", "loads"):
                self._add(
                    node, "static.pickle-deserialization", "Potentially unsafe deserialization (pickle)",
                    "Using pickle on untrusted data can lead to Remote Code Execution (RCE).",
                    Severity.HIGH, "CWE-502", 80,
                    "Use a safe format such as JSON, or verify the data source is fully trusted.", f"pickle.{attr}(...)",
                )
            elif owner == "yaml" and attr == "load":
                uses_safe_loader = any(
                    kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader"
                    for kw in node.keywords
                )
                if not uses_safe_loader:
                    self._add(
                        node, "static.yaml-unsafe-load", "Unsafe YAML deserialization (yaml.load)",
                        "yaml.load without Loader=yaml.SafeLoader can construct arbitrary Python objects from untrusted input, leading to RCE.",
                        Severity.HIGH, "CWE-502", 85,
                        "Use yaml.safe_load(), or yaml.load(data, Loader=yaml.SafeLoader).", "yaml.load(...)",
                    )

        self.generic_visit(node)

    def _check_path_traversal(self, call_node: ast.Call, path_arg: ast.expr) -> None:
        """
        Flags open(<expr>) when <expr> references a function parameter
        anywhere in its expression tree — not only a bare parameter name.
        This deliberately covers realistic shapes such as
        open(os.path.join(base_dir, user_path)) or open(f"./{user_path}"),
        not just the narrow open(user_path) case, since those are just as
        exploitable if user_path is attacker-controlled (e.g. an MCP tool
        argument) and reaches open() without validation.
        """
        referenced_params = {
            n.id for n in ast.walk(path_arg) if isinstance(n, ast.Name)
        } & self._params_in_scope()
        if not referenced_params:
            return
        self._add(
            call_node, "static.path-traversal-open-param",
            "Possible path traversal (open() built from a function parameter)",
            f"open(...) is built from parameter(s) {sorted(referenced_params)} without visible path validation. "
            "If the parameter comes from external input (e.g. an MCP tool call), this may allow reading arbitrary files.",
            Severity.MEDIUM, "CWE-22", 55,
            "Normalize and validate the path (os.path.abspath / Path.resolve) and confirm it stays within an allowed directory before calling open().",
            "open(<expression referencing a parameter>, ...)",
        )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.location, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_python_file(file_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(file_path, "r", encoding="utf-8-sig") as fh:
            content = fh.read()
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            for rule_id, meta in SECRET_PATTERNS.items():
                if meta["pattern"].search(line):
                    findings.append(Finding(
                        module="static", rule_id=rule_id, title=meta["title"], description=meta["description"],
                        severity=meta["severity"], confidence=meta["confidence"], location=file_path,
                        line=line_num, cwe=meta["cwe"], remediation=meta["remediation"], code_snippet=line.strip(),
                    ))
            hidden = find_hidden_unicode(line)
            if hidden:
                findings.append(Finding(
                    module="static", rule_id="static.hidden-unicode", title="Hidden or obfuscated Unicode characters",
                    description=f"Hidden or obfuscation-capable Unicode characters found: {', '.join(hidden)}.",
                    severity=Severity.MEDIUM, confidence=70, location=file_path, line=line_num,
                    cwe="N/A (Unicode heuristic)",
                    remediation="Remove the non-standard invisible characters and confirm their presence was intentional.",
                    code_snippet=line.strip(),
                ))

        tree = ast.parse(content, filename=file_path)
        visitor = SecurityASTVisitor(file_path)
        visitor.visit(tree)
        findings.extend(visitor.findings)

    except SyntaxError as se:
        findings.append(Finding(
            module="static", rule_id="static.syntax-error", title="Python syntax error",
            description=f"The file contains a syntax error and could not be fully parsed via AST: {se.msg}",
            severity=Severity.LOW, confidence=100, location=file_path, line=se.lineno or 1,
            remediation="Fix the file's syntax.", code_snippet=str(se.text or ""),
        ))
    except UnicodeDecodeError as ude:
        findings.append(Finding(
            module="static", rule_id="static.file-unreadable", title="Unreadable file (encoding issue)",
            description=f"The file could not be decoded as UTF-8: {ude}",
            severity=Severity.LOW, confidence=100, location=file_path, line=1,
            remediation="Verify the file's actual encoding, or explicitly exclude it from scanning.",
        ))
    except OSError as e:
        findings.append(Finding(
            module="static", rule_id="static.analysis-error", title="File analysis error",
            description=f"An unexpected error occurred while reading/parsing the file: {e}",
            severity=Severity.LOW, confidence=100, location=file_path, line=1,
            remediation="Inspect the file manually; the scanner could not complete automated analysis.",
        ))
        logger.warning("Error reading %s: %s", file_path, e)

    return _dedupe(findings)


# --- Dependency auditing ---------------------------------------------------

def _parse_version(version: str) -> Optional[tuple[int, ...]]:
    parts = re.findall(r"\d+", version)
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])


def _version_lte(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return a <= b


# Non-exhaustive, hand-curated list of package versions with well-known,
# high-impact CVEs. This is NOT a substitute for pip-audit / npm audit /
# OSV.dev — it lets the free-tier offline scan flag a handful of notorious
# cases without a network call. Values: (max vulnerable version INCLUSIVE, advisory summary).
KNOWN_VULNERABLE_PYTHON_PACKAGES: dict[str, tuple[str, str]] = {
    "pyyaml": ("5.3.1", "CVE-2020-14343: arbitrary code execution via yaml.load on untrusted input (fixed in 5.4)."),
    "pillow": ("9.0.0", "CVE-2022-22817: arbitrary code execution via ImageMath.eval (fixed in 9.0.1)."),
    "urllib3": ("1.26.4", "CVE-2021-33503: catastrophic backtracking / ReDoS in URL parsing (fixed in 1.26.5)."),
    "jinja2": ("2.11.2", "CVE-2020-28493: ReDoS in the urlize filter (fixed in 2.11.3)."),
    "cryptography": ("3.3.1", "CVE-2020-36242: denial of service via a crafted PKCS7 blob (fixed in 3.3.2)."),
    "requests": ("2.19.1", "CVE-2018-18074: Authorization header leaked on cross-origin redirect (fixed in 2.20.0)."),
    "flask": ("0.12.2", "CVE-2018-1000656: denial of service via crafted JSON (fixed in 0.12.3)."),
    "django": ("3.2.12", "CVE-2022-28346: SQL injection via QuerySet.explain() (fixed in 3.2.13)."),
    "paramiko": ("2.10.0", "CVE-2022-24302: race condition in server key handling (fixed in 2.10.1)."),
}

KNOWN_VULNERABLE_NPM_PACKAGES: dict[str, tuple[str, str]] = {
    "lodash": ("4.17.20", "CVE-2021-23337: command injection via template() (fixed in 4.17.21)."),
    "axios": ("0.21.1", "CVE-2021-3749: ReDoS in the trim function (fixed in 0.21.2)."),
    "minimist": ("1.2.5", "CVE-2021-44906: prototype pollution (fixed in 1.2.6)."),
    "node-fetch": ("2.6.6", "CVE-2022-0235: exposure of sensitive information (fixed in 2.6.7)."),
    "ws": ("7.4.5", "CVE-2021-32640: denial of service via a crafted request (fixed in 7.4.6)."),
    "semver": ("7.3.4", "CVE-2022-25883: ReDoS in range parsing (fixed in 7.5.2)."),
    "json5": ("1.0.1", "CVE-2022-46175: prototype pollution via a crafted JSON5 document (fixed in 1.0.2)."),
}

_STRONG_PIN_OPERATORS = ("==", "~=")
_WEAK_PIN_OPERATORS = (">=", "<=", ">", "<", "!=")


def _scan_requirements_txt_file(req_path: str) -> list[Finding]:
    findings: list[Finding] = []

    with open(req_path, "r", encoding="utf-8-sig") as fh:
        for line_num, raw_line in enumerate(fh, 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("git+") or line.startswith("-"):
                continue

            has_strong = any(op in line for op in _STRONG_PIN_OPERATORS)
            has_weak = any(op in line for op in _WEAK_PIN_OPERATORS)

            if not has_strong and not has_weak:
                findings.append(Finding(
                    module="static", rule_id="static.dependency-unpinned", title="Dependency without a version pin",
                    description="The dependency has no version specifier at all, so it installs whatever is newest at build time.",
                    severity=Severity.MEDIUM, confidence=90, location=req_path, line=line_num,
                    cwe="CWE-1104", remediation="Pin an exact version (==) or a compatible-release constraint (~=).",
                    code_snippet=line,
                ))
            elif not has_strong:
                # Functional fix versus the previous version of this check:
                # a bound like ">=2.0" used to be treated as "pinned" simply
                # because SOME operator was present. It is not pinned — it
                # is unbounded above and can silently resolve to a future,
                # unvetted (or vulnerable) release.
                findings.append(Finding(
                    module="static", rule_id="static.dependency-weak-constraint", title="Dependency with a weak, unbounded version constraint",
                    description="The dependency uses an inequality constraint (e.g. >=, <) with no exact or upper-bounded pin, so it can still resolve to an unvetted future version.",
                    severity=Severity.LOW, confidence=60, location=req_path, line=line_num,
                    cwe="CWE-1104", remediation="Prefer an exact pin (==) or a compatible-release constraint (~=), backed by a lockfile.",
                    code_snippet=line,
                ))

            match = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if match:
                pkg = match.group(1).lower()
                if pkg in KNOWN_VULNERABLE_PYTHON_PACKAGES:
                    max_vuln, advisory = KNOWN_VULNERABLE_PYTHON_PACKAGES[pkg]
                    version_match = re.search(r"==\s*([0-9][0-9A-Za-z.\-]*)", line)
                    version = _parse_version(version_match.group(1)) if version_match else None
                    max_vuln_parsed = _parse_version(max_vuln)
                    if version is None or (max_vuln_parsed and _version_lte(version, max_vuln_parsed)):
                        findings.append(Finding(
                            module="static", rule_id="static.dependency-known-vulnerable", title=f"Known-vulnerable dependency: {pkg}",
                            description=f"'{pkg}' matches a package with a well-known, high-impact advisory: {advisory}",
                            severity=Severity.HIGH, confidence=75, location=req_path, line=line_num,
                            cwe="CWE-1104",
                            remediation=f"Upgrade '{pkg}' past the version fixed in the advisory above, or run pip-audit for full, up-to-date coverage.",
                            code_snippet=line,
                        ))

    return findings


def _scan_package_json_file(pkg_path: str) -> list[Finding]:
    findings: list[Finding] = []
    target_directory = os.path.dirname(pkg_path) or "."

    try:
        with open(pkg_path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        findings.append(Finding(
            module="static", rule_id="static.package-json-invalid", title="Invalid package.json",
            description=f"package.json could not be parsed: {e}",
            severity=Severity.LOW, confidence=100, location=pkg_path, line=1,
            remediation="Fix the JSON syntax of package.json.",
        ))
        return findings

    dependency_blocks = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for pkg, version_spec in dependency_blocks.items():
        version_spec = str(version_spec)
        pkg_lower = pkg.lower()

        if version_spec in ("*", "latest", "") or version_spec.endswith(".x"):
            findings.append(Finding(
                module="static", rule_id="static.dependency-unpinned", title="npm dependency without a real version pin",
                description=f"'{pkg}' is declared as '{version_spec}', which resolves to whatever is newest at install time.",
                severity=Severity.MEDIUM, confidence=85, location=pkg_path, line=1,
                cwe="CWE-1104", remediation="Pin an exact version and commit a package-lock.json.",
                code_snippet=f'"{pkg}": "{version_spec}"',
            ))
        elif version_spec.startswith(("^", "~")):
            findings.append(Finding(
                module="static", rule_id="static.dependency-weak-constraint", title="npm dependency with a semver range constraint",
                description=f"'{pkg}' is declared as '{version_spec}' (semver range), which can still resolve to an unvetted newer version without a lockfile.",
                severity=Severity.LOW, confidence=50, location=pkg_path, line=1,
                cwe="CWE-1104", remediation="Commit package-lock.json (or an equivalent lockfile) so installs are reproducible.",
                code_snippet=f'"{pkg}": "{version_spec}"',
            ))

        if pkg_lower in KNOWN_VULNERABLE_NPM_PACKAGES:
            max_vuln, advisory = KNOWN_VULNERABLE_NPM_PACKAGES[pkg_lower]
            base_version = re.sub(r"^[\^~>=<\s]+", "", version_spec)
            version = _parse_version(base_version)
            max_vuln_parsed = _parse_version(max_vuln)
            if version is None or (max_vuln_parsed and _version_lte(version, max_vuln_parsed)):
                findings.append(Finding(
                    module="static", rule_id="static.dependency-known-vulnerable", title=f"Known-vulnerable dependency: {pkg}",
                    description=f"'{pkg}' matches a package with a well-known, high-impact advisory: {advisory}",
                    severity=Severity.HIGH, confidence=70, location=pkg_path, line=1,
                    cwe="CWE-1104",
                    remediation=f"Upgrade '{pkg}' past the version fixed in the advisory above, or run npm audit for full, up-to-date coverage.",
                    code_snippet=f'"{pkg}": "{version_spec}"',
                ))

    has_lockfile = any(
        os.path.exists(os.path.join(target_directory, name))
        for name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
    )
    if not has_lockfile:
        findings.append(Finding(
            module="static", rule_id="static.npm-no-lockfile", title="No npm lockfile found",
            description="package.json exists without a package-lock.json / yarn.lock / pnpm-lock.yaml, so dependency resolution is not reproducible across installs.",
            severity=Severity.LOW, confidence=80, location=pkg_path, line=1,
            remediation="Commit a lockfile so every install resolves to the exact same dependency tree.",
        ))

    return findings


def scan_dependencies(target_directory: str) -> list[Finding]:
    """
    Recursively finds every requirements.txt / package.json under
    target_directory (not just at the top level) — a real MCP server repo,
    especially a monorepo, may keep its manifest one or more directories
    below the path the user points the scanner at.
    """
    findings: list[Finding] = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        if "requirements.txt" in files:
            findings.extend(_scan_requirements_txt_file(os.path.join(root, "requirements.txt")))
        if "package.json" in files:
            findings.extend(_scan_package_json_file(os.path.join(root, "package.json")))
    return _dedupe(findings)


# --- MCP manifest auditing --------------------------------------------------

def _find_line_for_key(lines: list[str], key: str) -> int:
    needle = f'"{key}"'
    for line_num, line in enumerate(lines, 1):
        if needle in line:
            return line_num
    return 1


def _scan_mcp_config_file(config_path: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        with open(config_path, "r", encoding="utf-8-sig") as fh:
            content_str = fh.read()
    except OSError as e:
        logger.warning("Error reading %s: %s", config_path, e)
        return findings

    lines = content_str.splitlines()
    config_name = os.path.basename(config_path)

    # The bind-on-0.0.0.0 check is plain-text and independent of whether the
    # JSON parses, so it always runs, even for a malformed file.
    for line_num, line in enumerate(lines, 1):
        if '"0.0.0.0"' in line:
            findings.append(Finding(
                module="static", rule_id="static.mcp-bind-all-interfaces",
                title="MCP server exposed on all network interfaces (0.0.0.0)",
                description="The service listens on every network interface instead of a specific one.",
                severity=Severity.HIGH, confidence=90, location=config_path, line=line_num,
                cwe="CWE-668",
                remediation="Restrict the bind address to localhost (127.0.0.1) unless remote exposure is explicitly intended and secured.",
                code_snippet=line.strip(),
            ))

    try:
        data = json.loads(content_str)
    except json.JSONDecodeError as je:
        findings.append(Finding(
            module="static", rule_id="static.mcp-invalid-json", title="Invalid MCP manifest JSON",
            description=f"{config_name} is not valid JSON ({je.msg}). The hardcoded-secret check could not run on this file.",
            severity=Severity.LOW, confidence=100, location=config_path, line=getattr(je, "lineno", 1),
            remediation="Fix the JSON syntax of the configuration file.",
        ))
        return findings

    def check_dict(d: Any) -> None:
        if isinstance(d, dict):
            for k, v in d.items():
                if any(term in k.upper() for term in ("API_KEY", "TOKEN", "SECRET", "PASSWORD")):
                    if isinstance(v, str) and v and not (v.startswith("${") or v.startswith("$") or "env" in v.lower()):
                        findings.append(Finding(
                            module="static", rule_id="static.mcp-hardcoded-secret",
                            title="Potential hardcoded secret in MCP configuration",
                            description=f"The key '{k}' appears to contain a hardcoded secret rather than an environment variable reference.",
                            severity=Severity.CRITICAL, confidence=85, location=config_path,
                            line=_find_line_for_key(lines, k), cwe="CWE-798",
                            remediation="Reference an environment variable instead of a literal secret value.",
                            code_snippet=f'"{k}": "{v[:5]}..."',
                        ))
                check_dict(v)
        elif isinstance(d, list):
            for item in d:
                check_dict(item)

    check_dict(data)
    return findings


def scan_mcp_config(target_directory: str) -> list[Finding]:
    """Recursively finds every mcp.json / manifest.json under target_directory and audits each one."""
    findings: list[Finding] = []
    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for config_name in ("mcp.json", "manifest.json"):
            if config_name in files:
                findings.extend(_scan_mcp_config_file(os.path.join(root, config_name)))
    return _dedupe(findings)


# --- Top-level orchestration -------------------------------------------------

@dataclass
class StaticAnalysisResult:
    target_directory: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    confidence_disclaimer: str = CONFIDENCE_DISCLAIMER


def scan_directory(target_directory: str) -> StaticAnalysisResult:
    """Runs the full static analysis pass: source code + MCP manifest + dependencies."""
    self_package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = StaticAnalysisResult(target_directory=target_directory)

    for root, dirs, files in os.walk(target_directory):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for file in files:
            if not file.endswith(".py"):
                continue
            full_path = os.path.join(root, file)
            # Never scan our own installed package source — it would flag
            # its own regex literals and AST-detection logic as findings
            # about itself, which is meaningless noise for the user.
            try:
                is_self = os.path.commonpath([os.path.abspath(full_path), self_package_dir]) == self_package_dir
            except ValueError:
                is_self = False
            if is_self:
                continue
            result.files_scanned += 1
            result.findings.extend(scan_python_file(full_path))

    result.findings.extend(scan_mcp_config(target_directory))
    result.findings.extend(scan_dependencies(target_directory))
    result.findings = _dedupe(result.findings)
    return result
