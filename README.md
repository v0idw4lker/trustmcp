# trustmcp

[![PyPI version](https://img.shields.io/pypi/v/trustmcp)](https://pypi.org/project/trustmcp/)
[![Python versions](https://img.shields.io/pypi/pyversions/trustmcp)](https://pypi.org/project/trustmcp/)
[![License](https://img.shields.io/pypi/l/trustmcp)](https://pypi.org/project/trustmcp/)
[![CI status](https://github.com/v0idw4lker/trustmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/v0idw4lker/trustmcp/actions/workflows/ci.yml)

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

### `trustmcp check` — scan a server BEFORE you install it

`scan` analyzes a server you already have on disk. `check` resolves a registry reference
directly — npm, PyPI, GitHub, or an official MCP registry `server.json` — downloads the
source into an isolated temp directory, and scans it **before it ever touches
`npm install` / `pip install`**. Nothing from the package is ever executed: no install
scripts, no import, no build step — download, extract, and read only.

```bash
# npm (scoped names are handled automatically)
trustmcp check npm:@modelcontextprotocol/server-everything

# PyPI, pinned to a specific version
trustmcp check pypi:some-mcp-server==0.3.0

# GitHub, default branch resolved automatically
trustmcp check github:owner/repo

# An official MCP registry server.json record
trustmcp check https://registry.modelcontextprotocol.io/v0/servers/some-server/server.json
```

On top of the same static + auth-posture analysis `scan` runs, `check` adds signals that
only make sense pre-install: package age and days since last publish, maintainer count
(npm; PyPI does not expose this — reported as a known gap, never faked), whether the
manifest's repository URL actually resolves, and whether `package.json` declares a
`preinstall`/`postinstall`/`install` script — code that runs automatically on
`npm install`, the classic supply-chain attack vector. The report leads with a one-line
install verdict, e.g. `Grade D. Do not install without reviewing tools/exec.py:44 first.`

| Flag              | What it does                                                                          |
| ----------------- | -------------------------------------------------------------------------------------- |
| `--offline`       | Refuse any network access; fail clearly instead of hanging                             |
| `--timeout`       | Network timeout in seconds for registry lookups and the download (default `30`)        |
| `--max-size`      | Maximum download size in MB; aborts if exceeded (default `50`)                         |
| `--json-output`   | Path for the JSON report (default `mcp-check-report.json`)                             |
| `--no-json`       | Do not write a JSON report                                                             |
| `--sarif-output`  | Path for the SARIF report (default `mcp-check-report.sarif`)                           |
| `--no-sarif`      | Do not write a SARIF report                                                            |
| `--fail-on`       | Exit non-zero if a finding at/above this severity exists — `low`/`medium`/`high`/`critical` (CI gating) |
| `-v`, `--verbose` | Verbose logging                                                                        |

> 🔗 **Want SARIF findings showing up automatically in your GitHub Security tab?** See [examples/github-actions.md](examples/github-actions.md) for the one-line composite Action and the manual CI setup.

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

> The `confidence` field on every finding is a heuristic per-rule prior (how specific/unambiguous the signature is) — **not** a statistically measured false-positive rate. Empirical calibration against known-vulnerable and clean MCP servers was run 2026-08-19 and re-run 2026-08-21 — see [Validation](#-validation-dvmcp-benchmark) below.

The dependency-vulnerability list is a small, hand-curated set of notorious CVEs, checked entirely offline — it is **not** a substitute for `pip-audit`, `npm audit`, or [OSV.dev](https://osv.dev), which trustmcp does not call out to by design (no network dependency for a security tool's core scan).

---

## 📊 Validation: DVMCP Benchmark

Run against [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (DVMCP) — a suite of 10 intentionally vulnerable MCP servers — plus 3 clean official SDK example servers to check for false positives. DVMCP ships two independent implementations of most challenges (the documented `server.py` and the as-deployed `server_sse.py` Docker image), which frequently diverge, so results are reported for both, separately, rather than picking whichever looks better.

- **Canonical challenges (`server.py`): 6/10 fully detected, 1/10 partial, 3/10 missed**
- **As-deployed Docker containers (`server_sse.py`): 4/10 detected (2 off-label hits), 6/10 missed**
- **False positives: 0/3 clean servers**

Full methodology, every per-challenge result (including the honest misses), the two DVMCP upstream bugs worked around to run it at all, and one documented false positive the scanner itself produced on challenge 9 (explicitly not counted as a hit above): **[docs/validation.md](docs/validation.md)**.

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

- [x] Published detection-rate + false-positive-rate validation against known-vulnerable and clean MCP server benchmarks — see [Validation](#-validation-dvmcp-benchmark) (2026-08-19, re-run 2026-08-21)
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
│   │   ├── registry_resolver.py # `check`: npm/PyPI/GitHub/server.json -> a downloadable tarball URL
│   │   ├── supply_chain.py     # `check`: pre-install-only signals (age, maintainers, install scripts, repo resolution)
│   │   ├── preinstall.py       # `check`: isolated download/extract + orchestrates static + auth-posture + supply-chain
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
