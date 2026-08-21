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
import math
import os
import re
from collections import Counter
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

# --- Inline suppression comments --------------------------------------------
#
# `# trustmcp: ignore` (all rules) or `# trustmcp: ignore[rule.id, other.id]`
# (specific rules only), the same convention linters use (# noqa, # pylint:
# disable=...). Honored on the finding's own line, or the line immediately
# above it. Works uniformly for AST findings (scan_python_file) and every
# line-based check (requirements.txt, mcp.json/manifest.json, package.json)
# because it only ever looks at raw source lines by line number — it never
# needs to know how a given finding was produced.
_SUPPRESS_RE = re.compile(r"#\s*trustmcp:\s*ignore(?:\[([^\]]*)\])?")


def _parse_suppression_directive(line: str) -> Optional[set[str]]:
    """
    Returns None if `line` carries no suppression comment, {"*"} for a
    blanket `# trustmcp: ignore`, or the set of rule_ids named in
    `# trustmcp: ignore[rule.a, rule.b]`.
    """
    match = _SUPPRESS_RE.search(line)
    if not match:
        return None
    rules_str = match.group(1)
    if not rules_str:
        return {"*"}
    rules = {r.strip() for r in rules_str.split(",") if r.strip()}
    return rules or {"*"}


def _filter_suppressed(findings: list[Finding], lines: list[str]) -> list[Finding]:
    """Drops findings whose own line, or the line above it, carries a matching suppression comment."""
    kept: list[Finding] = []
    for f in findings:
        idx = f.line - 1
        directive = _parse_suppression_directive(lines[idx]) if 0 <= idx < len(lines) else None
        if directive is None and 0 <= idx - 1 < len(lines):
            directive = _parse_suppression_directive(lines[idx - 1])
        if directive and ("*" in directive or f.rule_id in directive):
            continue
        kept.append(f)
    return kept


def _strip_suppression_comments_for_json(content: str) -> str:
    """
    JSON has no comment syntax, so a literal `# trustmcp: ignore[...]` left
    in an mcp.json/manifest.json/package.json would otherwise fail to parse.
    Strips only text matching our specific suppression syntax (never a bare
    `#`, which could legitimately appear inside a JSON string value) before
    handing content to json.loads. Callers still use the ORIGINAL lines (with
    the comment intact) for line numbers and for detecting the suppression itself.
    """
    out_lines = []
    for line in content.splitlines():
        match = _SUPPRESS_RE.search(line)
        out_lines.append(line[: match.start()] if match else line)
    return "\n".join(out_lines)


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
    "static.secret-jwt": {
        "title": "Exposed JWT (JSON Web Token)",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "severity": Severity.HIGH, "cwe": "CWE-798", "confidence": 80,
        "description": "A hardcoded JSON Web Token (JWT) was found in source code. A leaked JWT can be replayed to impersonate whatever principal/claims it carries until it expires.",
        "remediation": "Move tokens to environment variables or a secret store; never hardcode a bearer token in source.",
    },
}

# --- Generic prefixed-credential heuristic (Rule 2, part 2) -----------------
#
# Vendor-specific patterns above (OpenAI, AWS, Stripe, ...) match an exact,
# known format, so a hit is close to a confirmed positive. This one instead
# matches a *shape* many custom/internal API keys follow ("epro_api_...",
# "cbx_api_...") and is inherently much weaker evidence: plenty of non-secret
# identifiers could coincidentally fit it. Shannon entropy on the random-
# looking suffix is used to reject obviously-fake placeholders (e.g. a
# fixture's "aa_api_0000000000000000") before they ever become a finding —
# a real secret's suffix looks close to random, a placeholder's usually
# doesn't.
_GENERIC_CREDENTIAL_RE = re.compile(r"\b[a-z]{2,6}_(?:api|key|token|sk)_([A-Za-z0-9]{16,})\b")
_GENERIC_CREDENTIAL_ENTROPY_THRESHOLD = 3.0  # bits/char; an all-same-char or all-digit run of 16+ chars sits well below this


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


# --- Tool/resource/prompt description injection (Rule 1) --------------------
#
# Deliberately scoped to the two places an MCP client actually reads and
# trusts as a tool/resource/prompt's description — a decorated function's
# docstring and a `description=` kwarg on the decorator itself — NOT
# arbitrary text anywhere in a file. A whole-file text scan for phrases like
# "hidden instructions" or "ignore previous instructions" self-triggers on
# this project's own README and on core/plugins.py / core/dynamic_client.py,
# which legitimately discuss those exact phrases in prose to explain what
# this vulnerability class is.
_MCP_DECORATOR_ATTRS = ("tool", "resource", "prompt")

_PSEUDO_TAG_RE = re.compile(
    r"<\s*(?:IMPORTANT|HIDDEN|SYSTEM|SECRET|INSTRUCTIONS)\s*>|\[\s*SYSTEM\s*\]",
    re.IGNORECASE,
)
_CONCEALMENT_RE = re.compile(
    r"do\s+not\s+(?:tell|mention|inform|disclose)"
    r"|without\s+(?:informing|telling)"
    r"|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"
    r"|disregard\s+the\s+above",
    re.IGNORECASE,
)
# Anchored to the START of a line (leading whitespace tolerated) so that
# "Returns System: operational status" — the word appearing mid-sentence,
# not as a role label — correctly does NOT match.
_ROLE_INJECTION_RE = re.compile(r"^[ \t]*(?:system|assistant|ai)\s*:", re.IGNORECASE | re.MULTILINE)


def _is_mcp_decorator(decorator: ast.expr) -> bool:
    """True for `@x.tool(...)` / `@x.resource(...)` / `@x.prompt(...)` for ANY object x —
    matched structurally on decorator.func.attr, not on a specific base name like "mcp",
    since real servers name the object mcp/server/app/etc. interchangeably."""
    return (
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr in _MCP_DECORATOR_ATTRS
    )


def _decorator_description_text(decorator: ast.Call) -> Optional[str]:
    """
    Extracts the text of a `description=` keyword argument on a decorator
    call, if present. An f-string (ast.JoinedStr) has its literal
    (ast.Constant) segments extracted and joined — interpolated variables
    cannot be resolved statically and are not a bug to work around, just an
    acknowledged boundary of static analysis.
    """
    for kw in decorator.keywords:
        if kw.arg != "description":
            continue
        value = kw.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
        if isinstance(value, ast.JoinedStr):
            parts = [v.value for v in value.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            return " ".join(parts) if parts else None
    return None


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
        # Stack of enclosing `if` test expressions, used only by the
        # description-mutation rule's call-counter confidence bonus.
        self.if_test_stack: list[ast.expr] = []

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
        self._check_mcp_description_injection(node)
        self.scope_stack.append(self._collect_param_names(node))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_If(self, node: ast.If) -> None:
        self.if_test_stack.append(node.test)
        self.generic_visit(node)
        self.if_test_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_description_mutation(node, target)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_description_mutation(node, node.target)
        self.generic_visit(node)

    def _add(self, node: ast.AST, rule_id: str, title: str, description: str,
              severity: Severity, cwe: str, confidence: int, remediation: str, snippet: str) -> None:
        self.findings.append(Finding(
            module="static", rule_id=rule_id, title=title, description=description,
            severity=severity, confidence=confidence, location=self.filepath,
            line=getattr(node, "lineno", 1), cwe=cwe, remediation=remediation, code_snippet=snippet,
        ))

    def _check_mcp_description_injection(self, node) -> None:
        """Rule 1: scans ONLY a decorated tool/resource/prompt function's docstring
        and its decorator's `description=` kwarg — see the module-level comment
        above _MCP_DECORATOR_ATTRS for why this is deliberately not a whole-file scan."""
        mcp_decorators = [d for d in node.decorator_list if _is_mcp_decorator(d)]
        if not mcp_decorators:
            return

        texts: list[tuple[str, str]] = []
        docstring = ast.get_docstring(node)
        if docstring:
            texts.append(("docstring", docstring))
        for decorator in mcp_decorators:
            desc_text = _decorator_description_text(decorator)
            if desc_text:
                texts.append(("description= argument", desc_text))
        if not texts:
            return

        pseudo_tag_hit: Optional[tuple[str, str]] = None
        concealment_hit: Optional[tuple[str, str]] = None
        role_injection_hit: Optional[tuple[str, str]] = None
        for label, text in texts:
            if pseudo_tag_hit is None:
                m = _PSEUDO_TAG_RE.search(text)
                if m:
                    pseudo_tag_hit = (label, m.group(0))
            if concealment_hit is None:
                m = _CONCEALMENT_RE.search(text)
                if m:
                    concealment_hit = (label, m.group(0))
            if role_injection_hit is None:
                m = _ROLE_INJECTION_RE.search(text)
                if m:
                    role_injection_hit = (label, m.group(0).strip())

        if not (pseudo_tag_hit or concealment_hit or role_injection_hit):
            return

        evidence_bits = []
        if pseudo_tag_hit:
            evidence_bits.append(f"pseudo-instruction tag {pseudo_tag_hit[1]!r} in its {pseudo_tag_hit[0]}")
        if concealment_hit:
            evidence_bits.append(f"concealment phrase {concealment_hit[1]!r} in its {concealment_hit[0]}")
        if role_injection_hit:
            evidence_bits.append(f"role-spoofing line {role_injection_hit[1]!r} in its {role_injection_hit[0]}")

        # Either a pseudo-tag or a concealment directive alone is a strong,
        # deliberate-looking signal (HIGH); a bare role-spoofing line with
        # neither is weaker on its own (MEDIUM).
        if pseudo_tag_hit or concealment_hit:
            severity, confidence = Severity.HIGH, 75
        else:
            severity, confidence = Severity.MEDIUM, 55

        snippet_source = pseudo_tag_hit or concealment_hit or role_injection_hit
        snippet = snippet_source[1] if snippet_source else ""

        self._add(
            node, "static.tool-description-injection",
            "Possible instruction injection in a tool/resource/prompt description",
            f"The description exposed to the connecting agent for '{node.name}' contains " + "; ".join(evidence_bits) +
            ". MCP tool/resource/prompt descriptions are read and trusted by the calling LLM, not just shown to a human — "
            "hidden or role-spoofing instructions embedded there can hijack the agent's behavior without a human ever "
            "reviewing the raw description text (tool poisoning).",
            severity, "N/A (LLM prompt-injection heuristic)", confidence,
            "Remove pseudo-instruction tags, concealment language, and role-spoofing lines from tool/resource/prompt "
            "descriptions. A description should plainly state behavior for the calling agent, never attempt to covertly "
            "direct it.",
            snippet,
        )

    def _has_call_counter_guard(self) -> bool:
        """
        True if any currently-enclosing `if` test looks like a call-counter
        comparison (`some_name < / <= / > / >= / == <int literal>`) — the
        exact DVMCP rug-pull shape (`if call_count < 3: ...`). This only
        raises confidence on an already-firing description-mutation finding;
        its absence never suppresses the finding.
        """
        for test in self.if_test_stack:
            if not (isinstance(test, ast.Compare) and len(test.ops) == 1
                    and isinstance(test.ops[0], (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq))):
                continue
            left, right = test.left, test.comparators[0]
            if isinstance(left, ast.Name) and isinstance(right, ast.Constant) and isinstance(right.value, int):
                return True
            if isinstance(right, ast.Name) and isinstance(left, ast.Constant) and isinstance(left.value, int):
                return True
        return False

    def _check_description_mutation(self, node: ast.AST, target: ast.expr) -> None:
        """Rule 3: flags any Assign/AugAssign whose target is `<something>.__doc__` or
        `<something>.description` — a real reassignment statement, never the docstring
        itself (a docstring is an Expr(Constant), not an Assign)."""
        if not (isinstance(target, ast.Attribute) and target.attr in ("__doc__", "description")):
            return
        confidence = 85 if self._has_call_counter_guard() else 65
        snippet = f"{ast.unparse(target)} = ..."
        self._add(
            node, "static.description-mutation",
            "Runtime mutation of a tool/resource's description or docstring",
            f"'{ast.unparse(target)}' is reassigned at runtime, after the containing function/class is already defined. "
            "A tool or resource that changes its own description/docstring after deployment (e.g. after N successful "
            "calls) can pass a one-time review cleanly and then present different instructions to the agent later — "
            "a 'rug pull'." + (
                " The reassignment is guarded by what looks like a call-counter comparison, matching that exact pattern."
                if confidence == 85 else ""
            ),
            Severity.HIGH, "N/A (runtime-mutation heuristic)", confidence,
            "Treat tool/resource/prompt descriptions and docstrings as immutable interface contracts: reviewed once, "
            "never reassigned by the running server.",
            snippet,
        )

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
                self._check_path_traversal(node, node.args[0], self._open_mode_category(node))

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

    @staticmethod
    def _open_mode_category(call_node: ast.Call) -> str:
        """
        Classifies open()'s mode argument (second positional arg, or a
        `mode=` keyword) as "read", "write" (any of w/a/x and their
        variants — this is an arbitrary-file-WRITE risk, not a read one),
        or "unknown" (mode is present but not a string literal trustmcp can
        evaluate statically, e.g. a variable — treated like "read" so the
        existing, more cautious behaviour is preserved rather than silently
        dropped). No mode argument at all means Python's default "r".
        """
        mode_node: Optional[ast.expr] = None
        if len(call_node.args) >= 2:
            mode_node = call_node.args[1]
        else:
            for kw in call_node.keywords:
                if kw.arg == "mode":
                    mode_node = kw.value
                    break
        if mode_node is None:
            return "read"
        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
            return "write" if mode_node.value[:1] in ("w", "a", "x") else "read"
        return "unknown"

    def _check_path_traversal(self, call_node: ast.Call, path_arg: ast.expr, mode_category: str = "read") -> None:
        """
        Flags open(<expr>) when <expr> references a function parameter
        anywhere in its expression tree — not only a bare parameter name.
        This deliberately covers realistic shapes such as
        open(os.path.join(base_dir, user_path)) or open(f"./{user_path}"),
        not just the narrow open(user_path) case, since those are just as
        exploitable if user_path is attacker-controlled (e.g. an MCP tool
        argument) and reaches open() without validation.

        mode_category distinguishes read from write/append: open(path, "w")
        cannot leak file contents the way open(path, "r") can, so it gets a
        separate, lower-severity finding with corrected wording rather than
        being reported as arbitrary file READ.
        """
        referenced_params = {
            n.id for n in ast.walk(path_arg) if isinstance(n, ast.Name)
        } & self._params_in_scope()
        if not referenced_params:
            return
        if mode_category == "write":
            self._add(
                call_node, "static.path-traversal-open-param",
                "Possible path traversal (open() built from a function parameter, write mode)",
                f"open(..., <write/append mode>) is built from parameter(s) {sorted(referenced_params)} without visible path validation. "
                "If the parameter comes from external input (e.g. an MCP tool call), this may allow WRITING or overwriting "
                "arbitrary files — this is a distinct risk from arbitrary file READ, not a duplicate of it.",
                Severity.LOW, "CWE-22", 40,
                "Normalize and validate the path (os.path.abspath / Path.resolve) and confirm it stays within an allowed directory before opening it for writing.",
                "open(<expression referencing a parameter>, \"w\"/\"a\"/\"x\"...)",
            )
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
    lines: list[str] = []
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
            for match in _GENERIC_CREDENTIAL_RE.finditer(line):
                if _shannon_entropy(match.group(1)) < _GENERIC_CREDENTIAL_ENTROPY_THRESHOLD:
                    continue
                findings.append(Finding(
                    module="static", rule_id="static.secret-generic-credential",
                    title="Possible hardcoded credential (generic prefixed pattern)",
                    description=(
                        "A string matching a generic '<prefix>_api/key/token/sk_<random>' credential shape was found. "
                        "This is a heuristic shape match, not a vendor-specific signature like the OpenAI/AWS/Stripe/etc. "
                        "checks above, so it carries lower confidence and may occasionally match a non-secret identifier "
                        "that happens to follow this naming convention."
                    ),
                    severity=Severity.MEDIUM, confidence=45, location=file_path, line=line_num,
                    cwe="CWE-798",
                    remediation="If this is a real credential, move it to an environment variable or a secret store. If it is not a credential, consider a naming convention that doesn't resemble one.",
                    code_snippet=line.strip(),
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

    return _dedupe(_filter_suppressed(findings, lines))


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


_PIP_OPERATOR_RE = re.compile(r"(==|~=|!=|<=|>=|<|>)\s*([0-9][0-9A-Za-z.\-]*)")


def _pip_lowest_resolvable_version(version_spec: str) -> tuple[Optional[tuple[int, ...]], bool]:
    """
    Returns (lowest_version_the_constraint_can_resolve_to, is_exact).

    is_exact=True means the constraint pins to exactly one version (a bare
    `==`), so a match against a vulnerable version is a confirmed hit. When
    is_exact=False the lowest bound merely establishes what the constraint
    PERMITS — the resolver is free to (and normally will) pick something
    newer — so a match there is a weaker, "permits a vulnerable version"
    claim, not a confirmed one.

    lowest_version is None when the spec has no lower-bound-establishing
    operator at all (no specifier, or only `<`/`<=`/`!=`), meaning the
    version genuinely cannot be determined from this line.
    """
    ops = _PIP_OPERATOR_RE.findall(version_spec)
    exact = [_parse_version(v) for op, v in ops if op == "=="]
    exact = [v for v in exact if v is not None]
    if exact:
        return exact[0], True
    lowers = [_parse_version(v) for op, v in ops if op in (">=", ">", "~=")]
    lowers = [v for v in lowers if v is not None]
    if lowers:
        return max(lowers), False
    return None, False


def _pip_is_bounded_range(version_spec: str) -> bool:
    """
    True only when the constraint has BOTH a lower bound (>=, >) and an
    upper bound (<, <=) — a genuine range like ">=2.0,<3.0". A constraint
    with only one side (">=2.0" unbounded above, or "<3.0" unbounded below)
    is not a bounded range and must keep firing dependency-weak-constraint.
    """
    ops = {op for op, _ in _PIP_OPERATOR_RE.findall(version_spec)}
    return bool(ops & {">=", ">"}) and bool(ops & {"<", "<="})


_NPM_OPERATOR_RE = re.compile(r"(>=|<=|>|<)\s*([0-9][0-9A-Za-z.\-]*)")
_NPM_BARE_VERSION_RE = re.compile(r"^[\^~]?\s*([0-9][0-9A-Za-z.\-]*)")


def _npm_lowest_resolvable_version(version_spec: str) -> tuple[Optional[tuple[int, ...]], bool]:
    """npm/semver equivalent of _pip_lowest_resolvable_version. A bare version ("4.17.20") is an
    exact pin in npm; "^"/"~" and explicit >=/> establish a lower bound only, not an exact match."""
    spec = version_spec.strip()
    if not spec or spec in ("*", "latest"):
        return None, False
    ops = _NPM_OPERATOR_RE.findall(spec)
    if ops:
        lowers = [_parse_version(v) for op, v in ops if op in (">=", ">")]
        lowers = [v for v in lowers if v is not None]
        return (max(lowers), False) if lowers else (None, False)
    match = _NPM_BARE_VERSION_RE.match(spec)
    if not match:
        return None, False
    parsed = _parse_version(match.group(1))
    is_exact = parsed is not None and not spec.startswith(("^", "~"))
    return parsed, is_exact


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
        raw_lines = fh.readlines()

    for line_num, raw_line in enumerate(raw_lines, 1):
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
        elif not has_strong and not _pip_is_bounded_range(line):
            # Functional fix versus the previous version of this check:
            # a bound like ">=2.0" used to be treated as "pinned" simply
            # because SOME operator was present. It is not pinned — it
            # is unbounded above and can silently resolve to a future,
            # unvetted (or vulnerable) release. But if the line ALSO has an
            # upper bound (e.g. ">=2.0,<3.0") it is a genuinely bounded
            # range, not an unbounded one — that case is deliberately not
            # flagged here rather than reported with wording ("no ... upper-
            # bounded pin") that the printed snippet directly contradicts.
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
                max_vuln_parsed = _parse_version(max_vuln)
                lowest, is_exact = _pip_lowest_resolvable_version(line)

                if lowest is None:
                    findings.append(Finding(
                        module="static", rule_id="static.dependency-known-vulnerable",
                        title=f"Possibly known-vulnerable dependency: {pkg} (version undetermined)",
                        description=(
                            f"'{pkg}' matches a package with a well-known, high-impact advisory, but the "
                            f"version could not be determined from this line's constraint, so this cannot be "
                            f"confirmed either way: {advisory}"
                        ),
                        severity=Severity.LOW, confidence=25, location=req_path, line=line_num,
                        cwe="CWE-1104",
                        remediation=f"Pin '{pkg}' to an exact version so its status against the advisory above can be determined, or run pip-audit for full, up-to-date coverage.",
                        code_snippet=line,
                    ))
                elif max_vuln_parsed and _version_lte(lowest, max_vuln_parsed):
                    if is_exact:
                        findings.append(Finding(
                            module="static", rule_id="static.dependency-known-vulnerable", title=f"Known-vulnerable dependency: {pkg}",
                            description=f"'{pkg}' matches a package with a well-known, high-impact advisory: {advisory}",
                            severity=Severity.HIGH, confidence=75, location=req_path, line=line_num,
                            cwe="CWE-1104",
                            remediation=f"Upgrade '{pkg}' past the version fixed in the advisory above, or run pip-audit for full, up-to-date coverage.",
                            code_snippet=line,
                        ))
                    else:
                        findings.append(Finding(
                            module="static", rule_id="static.dependency-known-vulnerable",
                            title=f"Dependency constraint permits a known-vulnerable version: {pkg}",
                            description=(
                                f"'{pkg}''s version constraint permits resolving down to a version covered by a "
                                f"well-known, high-impact advisory: {advisory} This does not confirm the version "
                                f"that actually gets installed is vulnerable — only that the constraint does not rule it out."
                            ),
                            severity=Severity.LOW, confidence=40, location=req_path, line=line_num,
                            cwe="CWE-1104",
                            remediation=f"Pin '{pkg}' to a version above the one fixed in the advisory above (==, or a lower bound past it), or run pip-audit for full, up-to-date coverage.",
                            code_snippet=line,
                        ))
                # else: the lowest version the constraint can resolve to is already past the
                # advisory's fixed version — genuinely not vulnerable, so nothing is reported.

    return _filter_suppressed(findings, [l.rstrip("\n") for l in raw_lines])


def _scan_package_json_file(pkg_path: str) -> list[Finding]:
    findings: list[Finding] = []
    target_directory = os.path.dirname(pkg_path) or "."

    try:
        with open(pkg_path, "r", encoding="utf-8-sig") as fh:
            content_str = fh.read()
        data = json.loads(_strip_suppression_comments_for_json(content_str))
    except (OSError, json.JSONDecodeError) as e:
        findings.append(Finding(
            module="static", rule_id="static.package-json-invalid", title="Invalid package.json",
            description=f"package.json could not be parsed: {e}",
            severity=Severity.LOW, confidence=100, location=pkg_path, line=1,
            remediation="Fix the JSON syntax of package.json.",
        ))
        return findings

    lines = content_str.splitlines()

    dependency_blocks = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for pkg, version_spec in dependency_blocks.items():
        version_spec = str(version_spec)
        pkg_lower = pkg.lower()
        pkg_line = _find_line_for_key(lines, pkg)

        if version_spec in ("*", "latest", "") or version_spec.endswith(".x"):
            findings.append(Finding(
                module="static", rule_id="static.dependency-unpinned", title="npm dependency without a real version pin",
                description=f"'{pkg}' is declared as '{version_spec}', which resolves to whatever is newest at install time.",
                severity=Severity.MEDIUM, confidence=85, location=pkg_path, line=pkg_line,
                cwe="CWE-1104", remediation="Pin an exact version and commit a package-lock.json.",
                code_snippet=f'"{pkg}": "{version_spec}"',
            ))
        elif version_spec.startswith(("^", "~")):
            findings.append(Finding(
                module="static", rule_id="static.dependency-weak-constraint", title="npm dependency with a semver range constraint",
                description=f"'{pkg}' is declared as '{version_spec}' (semver range), which can still resolve to an unvetted newer version without a lockfile.",
                severity=Severity.LOW, confidence=50, location=pkg_path, line=pkg_line,
                cwe="CWE-1104", remediation="Commit package-lock.json (or an equivalent lockfile) so installs are reproducible.",
                code_snippet=f'"{pkg}": "{version_spec}"',
            ))

        if pkg_lower in KNOWN_VULNERABLE_NPM_PACKAGES:
            max_vuln, advisory = KNOWN_VULNERABLE_NPM_PACKAGES[pkg_lower]
            max_vuln_parsed = _parse_version(max_vuln)
            lowest, is_exact = _npm_lowest_resolvable_version(version_spec)

            if lowest is None:
                findings.append(Finding(
                    module="static", rule_id="static.dependency-known-vulnerable",
                    title=f"Possibly known-vulnerable dependency: {pkg} (version undetermined)",
                    description=(
                        f"'{pkg}' matches a package with a well-known, high-impact advisory, but the version "
                        f"could not be determined from '{version_spec}', so this cannot be confirmed either way: {advisory}"
                    ),
                    severity=Severity.LOW, confidence=25, location=pkg_path, line=pkg_line,
                    cwe="CWE-1104",
                    remediation=f"Pin '{pkg}' to an exact version so its status against the advisory above can be determined, or run npm audit for full, up-to-date coverage.",
                    code_snippet=f'"{pkg}": "{version_spec}"',
                ))
            elif max_vuln_parsed and _version_lte(lowest, max_vuln_parsed):
                if is_exact:
                    findings.append(Finding(
                        module="static", rule_id="static.dependency-known-vulnerable", title=f"Known-vulnerable dependency: {pkg}",
                        description=f"'{pkg}' matches a package with a well-known, high-impact advisory: {advisory}",
                        severity=Severity.HIGH, confidence=70, location=pkg_path, line=pkg_line,
                        cwe="CWE-1104",
                        remediation=f"Upgrade '{pkg}' past the version fixed in the advisory above, or run npm audit for full, up-to-date coverage.",
                        code_snippet=f'"{pkg}": "{version_spec}"',
                    ))
                else:
                    findings.append(Finding(
                        module="static", rule_id="static.dependency-known-vulnerable",
                        title=f"Dependency constraint permits a known-vulnerable version: {pkg}",
                        description=(
                            f"'{pkg}''s version constraint ('{version_spec}') permits resolving down to a version "
                            f"covered by a well-known, high-impact advisory: {advisory} This does not confirm the "
                            f"version that actually gets installed is vulnerable — only that the constraint does not rule it out."
                        ),
                        severity=Severity.LOW, confidence=35, location=pkg_path, line=pkg_line,
                        cwe="CWE-1104",
                        remediation=f"Pin '{pkg}' to a version above the one fixed in the advisory above, or run npm audit for full, up-to-date coverage.",
                        code_snippet=f'"{pkg}": "{version_spec}"',
                    ))
            # else: the lowest version the constraint can resolve to is already past the
            # advisory's fixed version — genuinely not vulnerable, so nothing is reported.

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

    return _filter_suppressed(findings, lines)


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
        data = json.loads(_strip_suppression_comments_for_json(content_str))
    except json.JSONDecodeError as je:
        findings.append(Finding(
            module="static", rule_id="static.mcp-invalid-json", title="Invalid MCP manifest JSON",
            description=f"{config_name} is not valid JSON ({je.msg}). The hardcoded-secret check could not run on this file.",
            severity=Severity.LOW, confidence=100, location=config_path, line=getattr(je, "lineno", 1),
            remediation="Fix the JSON syntax of the configuration file.",
        ))
        return _filter_suppressed(findings, lines)

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
    return _filter_suppressed(findings, lines)


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
