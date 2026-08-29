# Contributing to trustmcp

Early-stage, single-maintainer project. Open an issue before starting anything substantial, it saves both of us time if the approach needs to change before code gets written.

## Development setup

```bash
git clone https://github.com/v0idw4lker/trustmcp
cd trustmcp
pip install -e ".[dev]"
pytest
```

CI runs the test suite on Python 3.10 through 3.14 on every push to `main` and every pull request (`.github/workflows/ci.yml`). A PR won't merge unless it passes on all five.

## Project layout

- `trustmcp/core/static_analyzer.py`: regex/AST static rules (secrets, dangerous calls, dependency checks, MCP manifest auditing).
- `trustmcp/core/dynamic_client.py`: live scanning of a running MCP server (capability enumeration, fuzzing).
- `trustmcp/core/auth_posture.py`: authentication-mechanism checks.
- `trustmcp/core/scoring.py`: maps findings to the A-F score and MCP top-10 categories.
- `trustmcp/reporters/`: CLI, JSON, and SARIF output.
- `tests/fixtures/`: intentionally vulnerable sample code used by the test suite. Don't "fix" the vulnerabilities here, they exist to be detected.

## Adding or changing a detection rule

- Every rule needs a stable `rule_id` (`static.*`, `dynamic.*`, or `auth.*`). Don't rename an existing one, adopters may already be filtering on it.
- Justify the `severity` and `confidence` you pick. `confidence` is a per-rule prior on how unambiguous the signature is, not a measured false-positive rate, see the "Honesty Over Marketing" section of the README for the reasoning the existing rules follow.
- Add a test in `tests/` covering the positive case (the pattern fires) and, where it matters, a negative case (a similar-looking safe pattern that must NOT fire).
- If the change affects a documented DVMCP benchmark result in the README, re-run that benchmark and update the numbers. Don't leave them stale.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. They ask for the specific context (command run, rule ID, environment) needed to reproduce a finding-related bug, so you don't have to guess what's useful.

## Security

Don't open a public issue for a vulnerability in trustmcp itself (as opposed to a detection gap in what it scans for). Use the contact in the README, or open a private security advisory on GitHub.
