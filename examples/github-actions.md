# Using trustmcp in GitHub Actions

trustmcp writes [SARIF](https://sarifweb.azurewebsites.net/), the format GitHub's
Security tab understands. Once a workflow uploads it with
[`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action), findings
show up under **Security → Code scanning alerts** on the repo, on the same PR diff view
CodeQL results use.

There are two ways to run it in CI: the composite action, or a plain pip install.

## Option 1: composite action (`v0idw4lker/trustmcp@main`)

No tag has been published yet, so pin to `@main` for now — switch to a version tag
(e.g. `@v1`) once one exists.

```yaml
name: trustmcp

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required — see warning below

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: v0idw4lker/trustmcp@main
        with:
          path: .
          mode: static
          fail-on: high
          sarif-output: trustmcp.sarif
```

> **You must add `permissions: security-events: write` in your own workflow, as shown
> above.** A composite action cannot grant itself permissions — that's entirely
> controlled by the workflow that calls it. If you omit this, the scan will still run
> and the job may even show green on the upload step, but nothing will appear in the
> Security tab: the SARIF upload fails silently on repos without it. This is the
> single most common way this integration breaks for adopters — if your findings
> aren't showing up, check this first.

### Inputs

| Input          | Default            | Description                                              |
|----------------|---------------------|------------------------------------------------------------|
| `path`         | `.`                 | Directory to scan.                                        |
| `mode`         | `static`            | `static`, `dynamic`, or `both`.                            |
| `fail-on`      | `high`              | Minimum severity that fails the job: `none`, `low`, `medium`, `high`, `critical`. |
| `sarif-output` | `trustmcp.sarif`    | Path to write the SARIF report to.                         |

The action always uploads the SARIF file, even when the scan finds issues at or above
`fail-on` — the job is failed as a separate, final step, so the Security tab still gets
populated on a "failing" run instead of silently skipping the upload.

## Option 2: manual pip install

If you'd rather not depend on the composite action (e.g. to pin an exact `trustmcp`
version, or run it as one step among several), install and invoke it directly. You are
responsible for the same `security-events: write` permission and for uploading the
SARIF file yourself:

```yaml
name: trustmcp

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for the upload-sarif step below

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install trustmcp

      - name: Scan
        continue-on-error: true
        run: >
          trustmcp scan --path . --mode static
          --sarif-output trustmcp.sarif --no-json --fail-on high

      - name: Upload SARIF to the Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trustmcp.sarif
```

`continue-on-error: true` on the scan step matters here for the same reason it matters
in the composite action: `--fail-on high` exits 1 as soon as a CRITICAL or HIGH finding
exists, but the SARIF file is written to disk before that exit — if the step is allowed
to fail the job outright, the upload step never runs and the Security tab stays empty.
