# trustmcp

**Security scanner for MCP (Model Context Protocol) servers** — the protocol through which AI agents (Claude, ChatGPT, Cursor, etc.) connect to external tools.

Given an MCP server (source code, a running server, or both), `trustmcp` produces a vulnerability report and an **A–F** score, natively integrated into the **GitHub Security tab** via SARIF.

Interested in the premium tier (semantic analysis, cross-server toxic-flow, continuous monitoring)? Join the waitlist at [mcp-scanner.netlify.app](https://mcp-scanner.netlify.app).

```
Grade: F  Score: 45/100
Total findings across all modules: 12
```

---

## ✅ Prerequisites

New to the command line? You'll need three things: [Python 3.10 or newer](https://www.python.org/downloads/) installed on your computer; a terminal open (**Command Prompt** or **PowerShell** on Windows, **Terminal** on Mac); and that terminal pointed at the folder containing the MCP server code you want to scan — use the `cd` command to get there, e.g. `cd path/to/my-mcp-server`.

---

## ⚡ Quick Installation

```bash
# Direct execution without installation (recommended)
uvx trustmcp@latest scan --path . --mode static

# Or permanent installation
pip install trustmcp
trustmcp scan --path . --mode static
```

**Static scan only** (source code, no running server required):

```bash
trustmcp scan --path ./my-mcp-server --mode static
```

**Full scan** (static + live dynamic analysis + auth posture + unified score + SARIF):

```bash
trustmcp scan --path ./my-mcp-server --mode both \
  --target "stdio:python3 server.py" \
  --target "url:http://127.0.0.1:8931/mcp"
```

Outputs: a color-coded console report (via `rich`), `mcp-scan-report.json`, and `mcp-scan-report.sarif` — drop the SARIF file into CI and it automatically appears in the **Security → Code scanning** tab of your repository.

| Flag              | What it does                                                                          |
| ----------------- | -------------------------------------------------------------------------------------- |
| `--path`          | Directory to statically scan and to search for auth-posture evidence (default `.`)     |
| `--mode`          | `static`, `dynamic`, or `both` (default `both`)                                        |
| `--target`        | Live MCP server to scan dynamically. Repeatable. `stdio:<command>` or `url:<url>`      |
| `--no-fuzz`       | Disables tool input fuzzing during dynamic analysis                                    |
| `--json-output`   | Path for the JSON report (default `mcp-scan-report.json`)                              |
| `--no-json`       | Do not write a JSON report                                                             |
| `--sarif-output`  | Path for the SARIF report (default `mcp-scan-report.sarif`)                            |
| `--no-sarif`      | Do not write a SARIF report                                                            |
| `--fail-on`       | Exit non-zero if a finding at/above this severity exists — `low`/`medium`/`high`/`critical` (CI gating) |
| `-v`, `--verbose` | Verbose logging                                                                        |

---

## 🎯 What It Detects

Four modules, all included in the free tier and always combined into a single score.

| Module                | What it checks                                                                                                                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Static** (source code) | `eval`/`exec`, `os.system`/`os.popen`, `subprocess(shell=True)`, unsafe `pickle`/`yaml.load`, path traversal, hardcoded secrets (OpenAI, Anthropic, GitHub, AWS, Stripe, Google, Slack, JWTs, a generic prefixed-credential heuristic, PEM keys), hidden/obfuscated Unicode (zero-width, bidi-control, and Unicode Tag "ASCII smuggling" characters), **prompt-injection patterns in `@tool`/`@resource`/`@prompt` descriptions and docstrings** (pseudo-tags, concealment directives, role-spoofing lines), **runtime mutation of a tool's `__doc__`/`description` after definition** (the "rug pull" mechanism), MCP config exposed on `0.0.0.0`, unpinned or known-vulnerable dependencies (`requirements.txt` and `package.json`) |
| **Dynamic** (live server) | Tool/resource/prompt enumeration, authentication enforcement (401/403 vs. 200), TLS/HSTS for remote servers, live description drift vs. source code, and **input fuzzing** — malformed payloads sent to every discovered tool to catch crashes and stack-trace/error leakage |
| **Auth posture**       | Detects whether a server appears to implement OAuth 2.1, a static API key, or an environment-variable token — and flags weak or missing mechanisms                                                                 |
| **Scoring**             | A–F grade, with findings explicitly mapped to the **OWASP MCP Top 10**                                                                                                                                              |

### OWASP MCP Top 10 Coverage

`trustmcp` maps findings to official categories rather than inventing its own taxonomy:

- `MCP01:2025` Token Mismanagement & Secret Exposure
- `MCP02:2025` Privilege Escalation via Scope Creep
- `MCP03:2025` Tool Poisoning
- `MCP04:2025` Software Supply Chain Attacks & Dependency Tampering
- `MCP05:2025` Command Injection & Execution
- `MCP07:2025` Insufficient Authentication & Authorization
- `MCP10:2025` Context Injection & Over-Sharing

Findings without a clear match are **not** forced into a category — see [`trustmcp/core/scoring.py`](trustmcp/core/scoring.py).

---

## 🔇 Suppressing findings

A specific finding can be suppressed with an inline comment, the same convention most linters use (`# noqa`, `# pylint: disable=...`):

```python
os.system(cmd)  # trustmcp: ignore[static.os-system]

# trustmcp: ignore[static.path-traversal-open-param]
with open(user_path) as f:
    ...

eval(user_input)  # trustmcp: ignore   <- suppresses every rule on this line, not just one
```

- `# trustmcp: ignore` suppresses **all** findings on that line.
- `# trustmcp: ignore[rule.id]` suppresses only the named rule; comma-separate several: `# trustmcp: ignore[static.os-system, static.dangerous-eval-exec]`.
- The comment is honored on the finding's own line, **or** the line immediately above it — useful when the flagged line is long or auto-formatted.
- Works for AST-based findings in Python source, and for the line-based checks over `requirements.txt`, `mcp.json`/`manifest.json`, and `package.json` (in JSON files the comment is stripped before parsing, so it doesn't break `json.loads`).

Use it for confirmed false positives or accepted risk, not to silence findings you haven't actually looked at.

---

## 🔬 Honesty Over Marketing

> The `confidence` field on every finding is a heuristic per-rule prior (how specific/unambiguous the signature is) — **not** a statistically measured false-positive rate. Empirical calibration against known-vulnerable and clean MCP servers was run 2026-08-19 and re-run 2026-08-21 — see [Validation](#-validation-dvmcp-benchmark-2026-08-21) below.

The dependency-vulnerability list is a small, hand-curated set of notorious CVEs, checked entirely offline — it is **not** a substitute for `pip-audit`, `npm audit`, or [OSV.dev](https://osv.dev), which trustmcp does not call out to by design (no network dependency for a security tool's core scan).

---

## 📊 Validation: DVMCP Benchmark (2026-08-21)

Run against [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (DVMCP), cloned fresh, plus 3 clean official [`modelcontextprotocol/python-sdk`](https://github.com/modelcontextprotocol/python-sdk) example servers for false positives. This is a re-run of the original 2026-08-19 benchmark below, after adding three new static rules aimed directly at three of that run's documented misses (challenges 2, 4, and 7). Full methodology, caveats, and per-challenge evidence below — numbers are exact, not rounded up, and a challenge that still misses says so plainly.

**What changed since 2026-08-19:** three new static rules were added —
- `static.tool-description-injection` (MCP03) — flags `<IMPORTANT>`/`<HIDDEN>`/`<SYSTEM>`/`<SECRET>`/`<INSTRUCTIONS>`/`[SYSTEM]` pseudo-tags, concealment phrases ("do not mention...", "ignore previous instructions", ...), and role-spoofing lines (a line starting `System:`/`Assistant:`/`AI:`), scoped *only* to a `@tool`/`@resource`/`@prompt`-decorated function's docstring and its decorator's `description=` argument — deliberately not a whole-file scan, since that self-triggers on this project's own README and source discussing these exact phrases in prose.
- `static.secret-jwt` / `static.secret-generic-credential` (MCP01) — a JWT pattern, plus a generic `<prefix>_api/key/token/sk_<random>` credential shape gated on Shannon entropy (an all-zeros or all-repeated-character placeholder no longer fires).
- `static.description-mutation` (MCP03) — flags any `Assign`/`AugAssign` to `<something>.__doc__` or `<something>.description` occurring after the function/class is defined (the "rug pull" mechanism), with a confidence bonus when the mutation is guarded by what looks like a call-counter comparison (`if call_count < 3: ...`).

**Headline:**

- **Canonical DVMCP challenges (documented vulnerability, `server.py`, matches `docs/challenges.md`): 6/10 fully detected, 1/10 partially detected, 3/10 missed** — up from 3/10 fully detected, 1/10 partial, 6/10 missed. Challenges 2, 4, and 7 flipped from Miss to Hit; challenge 10's partial detection substantially deepened (see table).
- **As-deployed Docker containers (`server_sse.py`, what `docker run` on ports 9001-9010 actually serves): 4/10 detected (2 off-label — see caveat), 6/10 missed — unchanged.** The three new rules are aimed at patterns present in the canonical challenges; on inspection, none of the deployed variants happen to contain a matching pattern that wasn't already either caught or absent. One new rule *did* fire on a deployed variant (challenge 9) but turned out to be a false positive on closer inspection — see the table and the new-limitation note below, and don't skip past it: it's not being rounded into either count above.
- **False positives: 0/3 clean servers** (re-confirmed via static analysis after adding the three new rules — see below).

**New limitation discovered during this run:** the role-spoofing check (a line starting `System:`/`Assistant:`/`AI:`) fired on DVMCP challenge 9's deployed `server_sse.py`, on the docstring line `system: The remote system to access (e.g., "database", "webserver", "fileserver")` inside a Google-style `Args:` block for a parameter literally named `system`. That is not a role-injection attempt — it's ordinary parameter documentation — so this is a genuine false positive, not a hit, and is reported as a Miss in the table below. The rule as specified only anchors on line-start plus a colon, which cannot distinguish "role-spoofing line" from "an Args: entry for a parameter named `system`/`assistant`/`ai`." Flagging for a design decision rather than silently patching it: narrowing this would need either requiring the whole rest of the line to look like an instruction rather than a type/description fragment, or explicitly excluding lines that look like `Args:`-block entries.

**Important caveat (unchanged from 2026-08-19):** DVMCP's own repo has two independent implementations of most challenges — `server.py` (matches the documented vulnerability class in `docs/challenges.md`) and `server_sse.py` (what the official Docker image actually runs on ports 9001-9010). On 6 of 10 challenges these diverge, sometimes completely — e.g. the live "Tool Poisoning" container (port 9002) contains no hidden tool-description instructions at all; it's a command-injection/path-traversal server instead. Both variants are reported below, labeled separately, so neither number is cherry-picked.

**Two upstream DVMCP bugs had to be worked around to get it running at all** (still present today), unrelated to trustmcp: `requirements.txt` pins `mcp[cli]>=0.5.0` unpinned, which today resolves to `mcp==2.0.0` — a version that removed `mcp.server.fastmcp`, so every challenge server crash-loops out of the box (fixed locally with a separate venv pinning `mcp[cli]<2.0.0`, which resolved to `1.29.0`). Challenge 5's canonical `server.py` additionally calls `FastMCP.resource(..., listed=False)`, a kwarg that doesn't exist in any current SDK version — it still cannot start at all, on any modern `mcp` release. Since DVMCP ships only HTTP entrypoints (legacy SSE or raw uvicorn) and trustmcp's dynamic client only speaks Streamable HTTP (not legacy SSE), each challenge was instead driven over **stdio**: the canonical `server.py`'s module-level `FastMCP` object directly via `.run(transport="stdio")`, and the deployed `server_sse.py`'s class-based `Challenge<N>Server().mcp` the same way — same tool/resource/prompt logic, different wire transport only.

**Per-challenge results:**

| # | Challenge | Canonical (`server.py`) | Deployed Docker (`server_sse.py`, port 900*N*) |
|---|---|---|---|
| 1 | Basic Prompt Injection | ❌ Miss — no finding relates to the unsanitized `notes://{user_id}` reflection | ❌ Miss — identical implementation to canonical |
| 2 | Tool Poisoning | ✅ **Hit (new)** — 2× HIGH `static.tool-description-injection` (MCP03), directly on `get_company_data` and `search_company_database`'s poisoned docstrings (`<IMPORTANT>`/`<HIDDEN>` tags plus "do not mention..." concealment phrases) | ⚠️ Off-label hit, unchanged — CRITICAL `subprocess-shell-true` (MCP05) + MEDIUM `path-traversal-open-param` (MCP05); the deployed container still replaces tool poisoning with command injection + arbitrary file read entirely, so the new rule correctly finds nothing tool-poisoning-shaped here |
| 3 | Excessive Permission Scope | ✅ Hit, unchanged — 2× MEDIUM `path-traversal-open-param` (MCP05) on `read_file`/`search_files`' unrestricted `open()` | ✅ Hit, unchanged — MEDIUM `path-traversal-open-param` (read) + LOW `path-traversal-open-param` (write mode) on `file_manager` |
| 4 | Rug Pull Attack | ✅ **Hit (new)** — 2× HIGH `static.description-mutation` (MCP03): the poisoning mutation on `get_weather_forecast.__doc__` (confidence 85 — the call-counter guard `if call_count < 3:` bonus applied) and the later reset in `reset_challenge` (confidence 65); plus the incidental CRITICAL `secret-aws-key` (MCP01) noted previously | ❌ Miss, unchanged — 0 findings beyond generic auth; the deployed variant still strips out both the secret text and the mutation logic |
| 5 | Tool Shadowing | ❌ Miss, still — dynamic scan still can't connect (`server.py` still crashes on the `listed=False` bug above); static analysis catches the same unrelated pre-existing issues as before (4× CRITICAL `dangerous-eval-exec`, 2× CRITICAL `secret-stripe-key`, MCP05/MCP01) plus, new this run, 2× HIGH `static.tool-description-injection` (MCP03) — one each on `malicious_server`'s `calculate` and `combined_server`'s `enhanced_calculate`, the two tools actually carrying `<HIDDEN>` concealment payloads. A real, correct catch of that payload on both shadowing-tool variants, but the scanner still has no rule for the name-collision shadowing mechanism itself, which is the named vulnerability | ❌ Miss, unchanged — only a MEDIUM `dynamic.fuzz-timeout` on `get_user_roles`; the deployed variant is a different role-check server, not the shadowing calculators |
| 6 | Indirect Prompt Injection | ❌ Miss, unchanged — no finding relates to unsanitized external/document data | ❌ Miss, unchanged — same |
| 7 | Token Theft | ✅ **Hit (new)** — 3× HIGH `static.secret-jwt` + 3× MEDIUM `static.secret-generic-credential` (MCP01), directly on the hardcoded `access_token`/`api_key` values in the tokens dict. Deliberate, accepted miss preserved: the `refresh_token` values (`rt_...`) are not caught, since `rt` isn't followed by the literal word api/key/token/sk — broadening that pattern was rejected as raising false-positive risk on ordinary identifiers | ❌ Miss, still — but for a different reason than "no matching pattern": this deployed variant doesn't hardcode any tokens at all. It implements a distinct vulnerability (predictable MD5 session-token generation in `authenticate`/`verify_token`) that no secret-pattern rule could ever catch, hardcoded-credential or not |
| 8 | Malicious Code Execution | ✅ Hit, unchanged — CRITICAL `subprocess-shell-true` (MCP05) on `execute_shell_command` + MEDIUM `path-traversal-open-param` (MCP05) on `analyze_log_file` (plus an incidental CRITICAL `secret-aws-key` and 2 dynamic fuzz-timeouts on `execute_python_code`, not central to the named vulnerability) | ✅ Hit, unchanged — CRITICAL `dangerous-eval-exec` (MCP05); deployed variant's `evaluate_expression` calls `eval()` directly |
| 9 | Remote Access Control | ✅ Hit, unchanged — 4× CRITICAL `subprocess-shell-true` (MCP05) across the network-diagnostic tools | ❌ Miss, unchanged — deployed variant still replaces the shell-exec tools with a broken-auth-token-check simulation (`if auth_token:` truthy check, no shell calls at all). One MEDIUM `static.tool-description-injection` fired on `remote_access`'s docstring but is a **false positive** — see the new-limitation note above — so this row stays a Miss |
| 10 | Multi-Vector Attack | ⚠️ **Partial, substantially deeper** — now 4 of 5 explicitly chained vulnerabilities have direct evidence: CRITICAL `subprocess-shell-true` and MEDIUM `path-traversal-open-param` (unchanged from before), plus (new) 3× HIGH `static.secret-jwt` on the hardcoded `admin_token`/`service_token`/`user_token` dict feeding the token-leakage-in-output vulnerability, and 2× HIGH `static.tool-description-injection` on `get_user_profile` (explicitly commented `VULNERABILITY 2` in the source) and `malicious_check_system_status`'s poisoned descriptions. Still missed: tool-name shadowing itself (`malicious_check_system_status` mimicking `check_system_status`) — no rule looks at name similarity between tools, so the poisoned description on that tool is caught but the shadowing relationship is not | ⚠️ Off-label hit, unchanged — 2× MEDIUM `path-traversal-open-param` (MCP05) on `get_config`; the deployed variant still only implements one vulnerability (file read), not an actual multi-vector chain |

*(Every finding above also produced a generic HIGH `auth.no-mechanism-detected` (MCP07) — omitted from each cell for brevity; it fired on all 10 challenges both ways.)*

**False-positive testing:** re-ran static analysis (the only module touched this session) against the same 3 clean servers from the official SDK's `examples/` — `mcpserver/simple_echo.py`, `servers/simple-prompt`, `servers/simple-pagination` — cloned fresh. 0 findings on all 3 from any rule, old or new (no false secret/JWT/generic-credential/eval/subprocess/traversal/Unicode/description-injection/description-mutation matches). Dynamic and auth-posture results for these 3 servers are unchanged from 2026-08-19 (see that run's notes below) since no dynamic-analysis or auth-posture code was touched this session.

<details>
<summary>2026-08-19 false-positive testing notes (dynamic/auth-posture, unchanged this session)</summary>

Ran full `--mode both` scans (static + stdio dynamic, fuzzing on) against the 3 clean servers. Dynamic analysis: while testing `simple-prompt` (a prompts-only server with no `tools`/`resources` capability), a real trustmcp bug surfaced — `dynamic_client.py`'s `_enumerate_session()` called `list_tools()`/`list_resources()`/`list_prompts()` unconditionally with no per-call exception handling, so a server correctly declining an unsupported capability (JSON-RPC "Method not found") was misreported as a HIGH-severity connection failure. **Fixed** in that session (`_list_capability()` now catches `MCPError` with code `METHOD_NOT_FOUND` per call and records it as a passed check, not a finding); all 3 clean servers correctly showed 0 vulnerability findings. All 3 also triggered a generic "no authentication mechanism" HIGH finding, which is accurate but fires on any unauthenticated local stdio server regardless of context — not counted as a false positive, but worth knowing it inflates finding counts for local dev/example servers.

</details>

**Known limitation this run confirms (narrowed, not closed):** the three new rules catch tool poisoning and rug-pull description mutation when they use one of a specific set of *shapes* — a pseudo-tag, a concealment phrase, a role-spoofing line, or a literal `.__doc__`/`.description` reassignment. A more careful adversary who phrases the same intent in plausible, tag-free natural language, or mutates behavior without ever touching `__doc__`/`description`, is still structurally invisible to pattern matching — that gap, plus indirect prompt injection from runtime-loaded document/resource content (never a decorator description, so out of scope for these rules entirely), is exactly what the paid semantic module (see Enterprise tier below) is for. Regex-based secret detection also has a fixed pattern list and a shape-based heuristic for the rest; a credential that matches neither (DVMCP's own `refresh_token: "rt_..."` being a documented example) won't be caught.

---

## 🏢 Enterprise / SaaS Tier

Everything above is free, open source, and stays that way. It's a genuinely complete scanner on its own — static analysis, live dynamic probing with input fuzzing, authentication posture, unified scoring, and SARIF/JSON reporting.

The paid tier builds on top of it with capabilities that go beyond what a single, stateless scan can offer:

- **Semantic (LLM) analysis** — sends every tool/resource/prompt description to an LLM with a strict, conservatively calibrated rubric to catch what regex cannot: naturally phrased hidden instructions, ambiguous scope, and language attempting to dictate model behavior.
- **Cross-server toxic-flow detection** — real AI agents connect multiple MCP servers simultaneously; a file-reading server plus a network-calling server can form an exfiltration channel even though each looks harmless alone. Single-server scans, by definition, cannot see this.
- **Continuous monitoring** — a one-time scan cannot catch a *rug pull*: a server that passes review cleanly, then changes its tool descriptions or scope after gaining trust. This requires fingerprinting + a saved baseline + drift alerting across scans over time.
- API access for CI/CD integration beyond static SARIF, and a verified, embeddable README badge for MCP registries.

The free tier's `trustmcp/core/plugins.py` defines the extension point these capabilities plug into — the architecture already supports them; they are simply not distributed in this open-source package.

📩 Interested in early access? Open an [issue](https://github.com/v0idw4lker/trustmcp/issues) or contact [@v0idw4lker](https://github.com/v0idw4lker).

---

## 🧪 Quick Testing

```bash
git clone https://github.com/v0idw4lker/trustmcp
cd trustmcp
pip install -r requirements.txt

# Static scan on this repo itself (fixtures/ is intentionally vulnerable)
trustmcp scan --path . --mode static

# Full pipeline against a fixture server
trustmcp scan --path . --mode both --target "stdio:python3 fixtures/target_server_stdio.py"

# Two fixture servers at once — a good demo of live multi-target scanning
trustmcp scan --path . --mode both \
  --target "stdio:python3 fixtures/vulnerable_server_a.py" \
  --target "stdio:python3 fixtures/vulnerable_server_b.py"
```

### Running the test suite

```bash
pip install -e ".[dev]"
pytest
```

---

## 🗺️ Roadmap

- [x] Published detection-rate + false-positive-rate validation against known-vulnerable and clean MCP server benchmarks — see [Validation](#-validation-dvmcp-benchmark-2026-08-21) (2026-08-19, re-run 2026-08-21)
- [ ] Complete OAuth 2.1 flow for authenticated dynamic scanning
- [ ] Semantic analysis, cross-server toxic-flow, and continuous monitoring (paid tier)
- [ ] Listing on `awesome-mcp-security` and official MCP registries

---

## Project Structure

```
trustmcp/
├── trustmcp/                   # installable package — the free tier
│   ├── cli.py                   # entrypoint: `trustmcp scan --path ... --mode both`
│   ├── core/
│   │   ├── models.py           # shared Finding contract used by every module + reporter
│   │   ├── text_safety.py      # hidden/obfuscated Unicode detection (shared static + dynamic)
│   │   ├── static_analyzer.py  # AST/regex SAST, secrets, dependency auditing
│   │   ├── dynamic_client.py   # live MCP client — stdio/HTTP, enumeration, TLS/auth, fuzzing
│   │   ├── auth_posture.py     # OAuth 2.1 / static key / env-var token detection
│   │   ├── scoring.py          # A-F scoring engine + OWASP MCP Top 10 mapping
│   │   └── plugins.py          # extension point for premium modules (unused in the free tier)
│   ├── reporters/
│   │   ├── cli_reporter.py     # color-coded terminal report
│   │   ├── json_reporter.py    # structured JSON for CI/CD
│   │   └── sarif_reporter.py   # SARIF 2.1.0 export for GitHub Security
│   └── utils/                  # logging + exception hierarchy
├── fixtures/                   # intentionally vulnerable test MCP servers
├── tests/                      # pytest suite + clean/vulnerable fixture modules
└── premium/                    # LOCAL ONLY, gitignored — see "Enterprise / SaaS Tier" above
```

---

## License

MIT — see [LICENSE](LICENSE).

Built by [@v0idw4lker](https://github.com/v0idw4lker).
