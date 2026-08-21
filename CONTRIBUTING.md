# Contributing to trustmcp

Thanks for considering a contribution. This is an early-stage, single-maintainer
project, so please open an issue before starting significant work — it saves everyone
time if the approach needs to change before code is written.

## Development setup

```bash
git clone https://github.com/v0idw4lker/trustmcp
cd trustmcp
pip install -e ".[dev]"
pytest
```

CI runs the test suite on Python 3.10 through 3.14 on every push to `main` and every
pull request (see `.github/workflows/ci.yml`) — a PR won't merge cleanly unless it
passes on all five.

## Project layout

- `trustmcp/core/static_analyzer.py` — regex/AST-based static rules (secrets, dangerous
  calls, dependency checks, MCP manifest auditing).
- `trustmcp/core/dynamic_client.py` — live scanning of a running MCP server (capability
  enumeration, fuzzing).
- `trustmcp/core/auth_posture.py` — authentication-mechanism checks.
- `trustmcp/core/scoring.py` — maps findings to the A–F score and MCP top-10 categories.
- `trustmcp/reporters/` — CLI, JSON, and SARIF output.
- `tests/fixtures/` — intentionally vulnerable sample code used by the test suite; do
  not "fix" the vulnerabilities in these files, they exist to be detected.

## Adding or changing a detection rule

- Every rule needs a stable `rule_id` (`static.*`, `dynamic.*`, or `auth.*`) — don't
  rename an existing one; adopters may already be filtering on it.
- Justify the chosen `severity` and `confidence`: `confidence` is a per-rule prior on
  how unambiguous the signature is, not a measured false-positive rate — see the
  "Honesty Over Marketing" section of the README for the reasoning the existing rules
  follow.
- Add a test in `tests/` covering both the positive case (the pattern fires) and, where
  it matters, a negative case (a similar-looking safe pattern that must NOT fire).
- If the change affects a documented DVMCP benchmark result in the README, re-run that
  benchmark and update the numbers rather than leaving them stale.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/` — they ask for the specific
context (command run, rule ID, environment) needed to reproduce a finding-related bug
without you having to guess what's useful.

## Security

Do not open a public issue for a vulnerability in trustmcp itself (as opposed to a
detection gap in what it scans for). Instead see the contact in the README or open a
private security advisory on GitHub.
