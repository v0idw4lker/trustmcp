# Scanning a server before you install it

`trustmcp scan` analyzes a server you already have checked out. `trustmcp check` instead
takes a registry reference — npm, PyPI, GitHub, or an official MCP registry `server.json`
— resolves it, downloads the source into an isolated temp directory, and scans it
**before it ever reaches `npm install` / `pip install`**. Nothing from the package is
executed: no install scripts, no import, no build step. Download, extract, and read only.

## Basic usage

```bash
# npm — scoped names are handled automatically
trustmcp check npm:@modelcontextprotocol/server-everything

# PyPI, pinned to a specific version
trustmcp check pypi:some-mcp-server==0.3.0

# GitHub — the default branch is looked up automatically, no need to guess "main" vs "master"
trustmcp check github:owner/repo

# An official MCP registry server.json record, followed to the package it names
trustmcp check https://registry.modelcontextprotocol.io/v0/servers/some-server/server.json
```

Each of these prints the same static + auth-posture analysis `scan` produces, plus a
"Pre-Install Signals" table (package age, last-publish date, maintainer count where the
registry exposes one, and the resolved repository URL) and a set of supply-chain-only
findings that only make sense before an install: a very new or long-stale package, a
single npm maintainer, a manifest repository URL that doesn't resolve, and — the classic
one — a `package.json` declaring a `preinstall`/`postinstall`/`install` script, which npm
runs automatically the moment `npm install` starts.

## Reading the verdict

The report leads with a one-line install decision:

```
Grade F. Do not install without reviewing npm:some-pkg@1.2.3#index.js:12 first.
```

or, on a clean result:

```
Grade A. No blocking findings.
```

`Grade`/`Score` follow the same A–F scale as `scan`. A `Do not install` verdict always
points at the single worst finding (by severity) so there's one concrete thing to go
look at first, not just a number.

## CI / gating and offline use

`check` supports the same `--json-output` / `--sarif-output` / `--fail-on` flags as
`scan`, so it can gate a pipeline the same way:

```bash
trustmcp check npm:some-mcp-server --fail-on high --no-json
```

For an environment where an untrusted download must never be allowed to hang or exceed a
size budget, use `--offline` (refuses any network access immediately instead of
attempting a connection), `--timeout` (default 30s), and `--max-size` (default 50 MB,
enforced against both the `Content-Length` header and the actual bytes streamed, so a
server that lies about its size can't fill the disk either).

```bash
trustmcp check npm:some-mcp-server --timeout 15 --max-size 20
```
