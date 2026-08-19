# mcp-scanner

**Security scanner for MCP (Model Context Protocol) servers** — the protocol through which AI agents (Claude, ChatGPT, Cursor, etc.) connect to external tools.

Given an MCP server (source code, a running server, or both), `mcp-scanner` produces a vulnerability report and an **A–F** score, natively integrated into the **GitHub Security tab** via SARIF.

Interested in the premium tier (semantic analysis, cross-server toxic-flow, continuous monitoring)? Join the waitlist at [mcp-scanner.netlify.app](https://mcp-scanner.netlify.app).

```
Grade: F  Score: 45/100
Total findings across all modules: 12
```

---

## ⚡ Quick Installation

```bash
# Direct execution without installation (recommended)
uvx mcp-scanner@latest scan --path . --mode static

# Or permanent installation
pip install mcp-scanner
mcp-scanner scan --path . --mode static
```

**Static scan only** (source code, no running server required):

```bash
mcp-scanner scan --path ./my-mcp-server --mode static
```

**Full scan** (static + live dynamic analysis + auth posture + unified score + SARIF):

```bash
mcp-scanner scan --path ./my-mcp-server --mode both \
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
| **Static** (source code) | `eval`/`exec`, `os.system`/`os.popen`, `subprocess(shell=True)`, unsafe `pickle`/`yaml.load`, path traversal, hardcoded secrets (OpenAI, Anthropic, GitHub, AWS, Stripe, Google, Slack, PEM keys), hidden/obfuscated Unicode (zero-width, bidi-control, and Unicode Tag "ASCII smuggling" characters), MCP config exposed on `0.0.0.0`, unpinned or known-vulnerable dependencies (`requirements.txt` and `package.json`) |
| **Dynamic** (live server) | Tool/resource/prompt enumeration, authentication enforcement (401/403 vs. 200), TLS/HSTS for remote servers, live description drift vs. source code, and **input fuzzing** — malformed payloads sent to every discovered tool to catch crashes and stack-trace/error leakage |
| **Auth posture**       | Detects whether a server appears to implement OAuth 2.1, a static API key, or an environment-variable token — and flags weak or missing mechanisms                                                                 |
| **Scoring**             | A–F grade, with findings explicitly mapped to the **OWASP MCP Top 10**                                                                                                                                              |

### OWASP MCP Top 10 Coverage

`mcp-scanner` maps findings to official categories rather than inventing its own taxonomy:

- `MCP01:2025` Token Mismanagement & Secret Exposure
- `MCP02:2025` Privilege Escalation via Scope Creep
- `MCP03:2025` Tool Poisoning
- `MCP04:2025` Software Supply Chain Attacks & Dependency Tampering
- `MCP05:2025` Command Injection & Execution
- `MCP07:2025` Insufficient Authentication & Authorization
- `MCP10:2025` Context Injection & Over-Sharing

Findings without a clear match are **not** forced into a category — see [`mcp_scanner/core/scoring.py`](mcp_scanner/core/scoring.py).

---

## 🔬 Honesty Over Marketing

> The `confidence` field on every finding is a heuristic per-rule prior (how specific/unambiguous the signature is) — **not** a statistically measured false-positive rate. Empirical calibration against known-vulnerable and clean MCP servers was run 2026-08-19 — see [Validation](#-validation-dvmcp-benchmark-2026-08-19) below.

The dependency-vulnerability list is a small, hand-curated set of notorious CVEs, checked entirely offline — it is **not** a substitute for `pip-audit`, `npm audit`, or [OSV.dev](https://osv.dev), which mcp-scanner does not call out to by design (no network dependency for a security tool's core scan).

---

## 📊 Validation: DVMCP Benchmark (2026-08-19)

Run against [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (DVMCP), built and run via its own Docker instructions (`docker build -t dvmcp .` / `docker run -p 9001-9010:9001-9010 dvmcp`), plus 3 clean official [`modelcontextprotocol/python-sdk`](https://github.com/modelcontextprotocol/python-sdk) example servers for false positives. Full methodology, caveats, and per-challenge evidence below — numbers are exact, not rounded up.

**Headline:**

- **Canonical DVMCP challenges (documented vulnerability, `server.py`, matches `docs/challenges.md`): 3/10 fully detected, 1/10 partially detected, 6/10 missed.**
- **As-deployed Docker containers (`server_sse.py`, what `docker run` on ports 9001-9010 actually serves): 4/10 detected (2 off-label — see caveat), 6/10 missed.**
- **False positives: 0/3 clean servers** (after a scanner bug found and fixed during this run — see below). All 3 also triggered a generic "no authentication mechanism" HIGH finding, which is accurate but fires on any unauthenticated local stdio server regardless of context — not counted as a false positive, but worth knowing it inflates finding counts for local dev/example servers.

**Important caveat discovered during this run:** DVMCP's own repo has two independent implementations of most challenges — `server.py` (matches the documented vulnerability class in `docs/challenges.md`) and `server_sse.py` (what the official Docker image actually runs on ports 9001-9010). On 6 of 10 challenges these diverge, sometimes completely — e.g. the live "Tool Poisoning" container (port 9002) contains no hidden tool-description instructions at all; it's a command-injection/path-traversal server instead. Both variants are reported below, labeled separately, so neither number is cherry-picked.

**Two upstream DVMCP bugs had to be worked around to get it running at all**, unrelated to mcp-scanner: `requirements.txt` pins `mcp[cli]>=0.5.0` unpinned, which today resolves to `mcp==2.0.0` — a version that removed `mcp.server.fastmcp`, so every challenge server crash-loops out of the box (fixed locally by pinning `<2.0.0`, which resolved to `1.29.0`). Challenge 5's canonical `server.py` additionally calls `FastMCP.resource(..., listed=False)`, a kwarg that doesn't exist in any current SDK version — it cannot start at all, on any modern `mcp` release. Since DVMCP ships only HTTP entrypoints (legacy SSE or raw uvicorn) and mcp-scanner's dynamic client only speaks Streamable HTTP (not legacy SSE), each challenge was instead driven over **stdio** by importing its `FastMCP`/`Challenge<N>Server` object directly and calling `.run(transport="stdio")` — same tool/resource/prompt logic, different wire transport only.

**Per-challenge results:**

| # | Challenge | Canonical (`server.py`) | Deployed Docker (`server_sse.py`, port 900*N*) |
|---|---|---|---|
| 1 | Basic Prompt Injection | ❌ Miss — no finding relates to the unsanitized `notes://{user_id}` reflection | ❌ Miss — identical implementation to canonical |
| 2 | Tool Poisoning | ❌ Miss — hidden `<IMPORTANT>`/`<HIDDEN>` instructions in tool descriptions are plain ASCII text; not caught by the hidden-*Unicode* check or any static rule (semantic/LLM analysis is paid-tier only) | ⚠️ Off-label hit — CRITICAL `subprocess-shell-true` (MCP05) + MEDIUM `path-traversal-open-param` (MCP05), but the deployed container replaces tool poisoning with command injection + arbitrary file read entirely; it does not exercise the named vulnerability |
| 3 | Excessive Permission Scope | ✅ Hit — 2× MEDIUM `path-traversal-open-param` (MCP05), directly on `read_file`/`search_files`' unrestricted `open()` | ✅ Hit — same pattern, same file-access tools |
| 4 | Rug Pull Attack | ❌ Miss — the `__doc__` mutation after 3 calls (the actual rug-pull mechanism) is not detected; the one CRITICAL `secret-aws-key` (MCP01) finding is an unrelated, incidental hardcoded key elsewhere in the file | ❌ Miss — 0 findings beyond generic auth; deployed variant strips out the secret text and the mutation logic |
| 5 | Tool Shadowing | ❌ Miss — dynamic scan couldn't connect (`server.py` itself crashes on the `listed=False` bug above, unrelated to mcp-scanner); static analysis caught real but unrelated issues (4× CRITICAL `dangerous-eval-exec`, 2× CRITICAL `secret-stripe-key`, both MCP05/MCP01) elsewhere in the file, not the name-collision shadowing mechanism | ❌ Miss — only a MEDIUM `dynamic.fuzz-timeout` on `get_user_roles`; the deployed variant is a different role-check server, not the shadowing calculators |
| 6 | Indirect Prompt Injection | ❌ Miss — no finding relates to unsanitized external/document data | ❌ Miss — same |
| 7 | Token Theft | ❌ Miss — tokens are hardcoded JWTs and custom-prefixed API keys (`epro_api_...`, `cbx_api_...`); none match the scanner's curated secret-regex list (OpenAI/Anthropic/GitHub/AWS/Stripe/Google/Slack/PEM) | ❌ Miss — same reason, different tool names |
| 8 | Malicious Code Execution | ✅ Hit — CRITICAL `subprocess-shell-true` (MCP05) on `execute_shell_command` + MEDIUM `path-traversal-open-param` (MCP05) on `analyze_log_file` | ✅ Hit — CRITICAL `dangerous-eval-exec` (MCP05); deployed variant's `evaluate_expression` calls `eval()` directly |
| 9 | Remote Access Control | ✅ Hit — 4× CRITICAL `subprocess-shell-true` (MCP05) across the network-diagnostic tools | ❌ Miss — deployed variant replaced the shell-exec tools with a broken-auth-token-check simulation (`if auth_token:` truthy check, no shell calls at all); a real but different, logic-level flaw the scanner can't reach with regex/AST rules |
| 10 | Multi-Vector Attack | ⚠️ Partial — 2 of 5 explicitly chained vulnerabilities caught (CRITICAL `subprocess-shell-true`, MEDIUM `path-traversal-open-param`, both MCP05); missed: token leakage in tool output, poisoned tool description, and tool-name shadowing | ⚠️ Off-label hit — 2× MEDIUM `path-traversal-open-param` (MCP05) on `get_config`; the deployed variant only implements one vulnerability (file read), not an actual multi-vector chain |

*(Every finding above also produced a generic HIGH `auth.no-mechanism-detected` (MCP07) — omitted from each cell for brevity; it fired on all 10 challenges both ways.)*

**False-positive testing:** ran full `--mode both` scans (static + stdio dynamic, fuzzing on) against 3 clean servers from the official SDK's `examples/` — `mcpserver/simple_echo.py`, `servers/simple-prompt`, `servers/simple-pagination`. Static analysis: 0 findings on all 3 (no false secret/eval/subprocess/traversal/Unicode matches). Dynamic analysis: while testing `simple-prompt` (a prompts-only server with no `tools`/`resources` capability), a real mcp-scanner bug surfaced — `dynamic_client.py`'s `_enumerate_session()` called `list_tools()`/`list_resources()`/`list_prompts()` unconditionally with no per-call exception handling, so a server correctly declining an unsupported capability (JSON-RPC "Method not found") was misreported as a HIGH-severity connection failure. **Fixed** in this session (`_list_capability()` now catches `MCPError` with code `METHOD_NOT_FOUND` per call and records it as a passed check, not a finding); all 3 clean servers now correctly show 0 vulnerability findings.

**Known limitation this run confirms:** the free tier has no semantic/LLM analysis, so any vulnerability that lives entirely in plausible-sounding natural-language tool-description text (tool poisoning, rug-pull description mutation, indirect prompt injection) is structurally invisible to it — that's exactly what the paid semantic module (see Enterprise tier below) is for. Regex-based secret detection also has a fixed pattern list; JWTs and custom-prefixed API keys outside that list won't be caught.

---

## 🏢 Enterprise / SaaS Tier

Everything above is free, open source, and stays that way. It's a genuinely complete scanner on its own — static analysis, live dynamic probing with input fuzzing, authentication posture, unified scoring, and SARIF/JSON reporting.

The paid tier builds on top of it with capabilities that go beyond what a single, stateless scan can offer:

- **Semantic (LLM) analysis** — sends every tool/resource/prompt description to an LLM with a strict, conservatively calibrated rubric to catch what regex cannot: naturally phrased hidden instructions, ambiguous scope, and language attempting to dictate model behavior.
- **Cross-server toxic-flow detection** — real AI agents connect multiple MCP servers simultaneously; a file-reading server plus a network-calling server can form an exfiltration channel even though each looks harmless alone. Single-server scans, by definition, cannot see this.
- **Continuous monitoring** — a one-time scan cannot catch a *rug pull*: a server that passes review cleanly, then changes its tool descriptions or scope after gaining trust. This requires fingerprinting + a saved baseline + drift alerting across scans over time.
- API access for CI/CD integration beyond static SARIF, and a verified, embeddable README badge for MCP registries.

The free tier's `mcp_scanner/core/plugins.py` defines the extension point these capabilities plug into — the architecture already supports them; they are simply not distributed in this open-source package.

📩 Interested in early access? Open an [issue](https://github.com/v0idw4lker/mcp-scanner/issues) or contact [@v0idw4lker](https://github.com/v0idw4lker).

---

## 🧪 Quick Testing

```bash
git clone https://github.com/v0idw4lker/mcp-scanner
cd mcp-scanner
pip install -r requirements.txt

# Static scan on this repo itself (fixtures/ is intentionally vulnerable)
mcp-scanner scan --path . --mode static

# Full pipeline against a fixture server
mcp-scanner scan --path . --mode both --target "stdio:python3 fixtures/target_server_stdio.py"

# Two fixture servers at once — a good demo of live multi-target scanning
mcp-scanner scan --path . --mode both \
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

- [x] Published detection-rate + false-positive-rate validation against known-vulnerable and clean MCP server benchmarks — see [Validation](#-validation-dvmcp-benchmark-2026-08-19) (2026-08-19)
- [ ] Complete OAuth 2.1 flow for authenticated dynamic scanning
- [ ] Semantic analysis, cross-server toxic-flow, and continuous monitoring (paid tier)
- [ ] Listing on `awesome-mcp-security` and official MCP registries

---

## Project Structure

```
mcp-scanner/
├── mcp_scanner/                # installable package — the free tier
│   ├── cli.py                  # entrypoint: `mcp-scanner scan --path ... --mode both`
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
