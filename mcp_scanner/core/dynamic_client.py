"""
Dynamic analysis engine — free tier, core.dynamic_client.

Connects to a LIVE MCP server (over stdio or Streamable HTTP) and:
  - Enumerates every tool, resource, and prompt the server exposes.
  - Compares served descriptions against the same hidden-Unicode check used
    by the static analyzer, so a server that behaves differently at runtime
    than its own source code suggests (drift / a "rug pull") gets caught.
  - Verifies authentication is actually enforced for HTTP servers (a real
    request without credentials must be rejected, not silently accepted).
  - Verifies TLS/HSTS for any non-local HTTP target.
  - Fuzzes every discovered tool with a small, bounded set of structurally
    malformed inputs (wrong types, oversized strings, missing required
    fields) to confirm the server validates its input instead of crashing
    or leaking a raw stack trace back to the caller.

What this module deliberately does NOT do: a full OAuth 2.1 authorization
flow (if the server requires it, the scanner reports that enforcement is
present and stops there — see core.auth_posture for static detection of
which auth mechanism a server appears to implement).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import METHOD_NOT_FOUND

from .models import Finding, Severity
from .text_safety import find_hidden_unicode

DEFAULT_TIMEOUT_SECONDS = 10.0
FUZZ_TIMEOUT_SECONDS = 5.0
MAX_FUZZ_PAYLOADS_PER_TOOL = 5

AUTH_REQUIRED_MARKERS = ("401", "403", "unauthorized", "forbidden")

# Matches the shape of a raw error a server should never hand back to a
# caller: an actual traceback, a "File "...", line N" frame reference, or a
# bare "SomethingError:" / "SomethingException:" prefix. This is what
# distinguishes an information-disclosure finding (CWE-209) from a normal,
# well-formed MCP error message.
STACK_TRACE_PATTERN = re.compile(
    r'Traceback \(most recent call last\)|File "[^"]+", line \d+|\b[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception)\b:'
)


def _describe_exception(e: BaseException) -> str:
    """
    anyio.TaskGroup wraps real errors inside an ExceptionGroup, so a plain
    str(e) produces an unhelpful "unhandled errors in a TaskGroup" message.
    Unwrap recursively to the concrete exception for a useful report message.
    """
    seen = e
    while isinstance(seen, BaseExceptionGroup) and seen.exceptions:
        seen = seen.exceptions[0]
    return f"{type(seen).__name__}: {seen}"


def _safe_payload_repr(payload: dict[str, Any]) -> str:
    try:
        text = json.dumps(payload, default=str)
    except TypeError:
        text = str(payload)
    return text[:200]


@dataclass
class DynamicScanResult:
    target: str
    transport: str  # "stdio" | "http"
    connected: bool = False
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    checks_passed: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "transport": self.transport,
            "connected": self.connected,
            "tools": self.tools,
            "resources": self.resources,
            "prompts": self.prompts,
            "checks_passed": self.checks_passed,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


async def _is_local_host(host: str) -> bool:
    """True if the host is local/private (localhost, 127.0.0.1, ::1, RFC1918, etc.)."""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        pass
    # gethostbyname is blocking — never call it directly inside a coroutine.
    # asyncio.to_thread runs it on a worker thread without blocking the event loop.
    try:
        resolved = await asyncio.to_thread(socket.gethostbyname, host)
        ip = ipaddress.ip_address(resolved)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except (socket.gaierror, ValueError, OSError):
        return False


def _scan_description_for_hidden_content(name: str, description: Optional[str], kind: str, target: str) -> list[Finding]:
    if not description:
        return []
    hidden = find_hidden_unicode(description)
    if not hidden:
        return []
    return [Finding(
        module="dynamic", rule_id="dynamic.hidden-unicode-description",
        title="Hidden Unicode characters in a live description",
        description=(
            f"The {kind} '{name}' description served LIVE by the server contains hidden/obfuscation "
            f"Unicode characters: {', '.join(hidden)}."
        ),
        severity=Severity.MEDIUM, confidence=70, location=target,
        remediation="Remove non-standard invisible characters from the description served by the running server.",
        metadata={"compare_with": "static analysis of the same source file — a mismatch indicates runtime drift."},
    )]


async def _list_capability(coro_factory, capability_name: str, result: DynamicScanResult):
    """
    Calls a session.list_*() method, treating a JSON-RPC "Method not found"
    response as the server legitimately not implementing that capability
    (e.g. a prompts-only server has no tools/resources) rather than a
    connection failure. Any other error still propagates so a genuinely
    broken connection is still reported as such.
    """
    try:
        return await asyncio.wait_for(coro_factory(), timeout=DEFAULT_TIMEOUT_SECONDS)
    except MCPError as e:
        if e.code == METHOD_NOT_FOUND:
            result.checks_passed.append(f"Server does not implement '{capability_name}' (capability not offered — not an error).")
            return None
        raise


async def _enumerate_session(session: ClientSession, result: DynamicScanResult, enable_fuzzing: bool) -> None:
    init_result = await asyncio.wait_for(session.initialize(), timeout=DEFAULT_TIMEOUT_SECONDS)
    result.checks_passed.append(
        f"Connection and initialize() succeeded (server: {init_result.server_info.name} v{init_result.server_info.version})"
    )

    tools_result = await _list_capability(session.list_tools, "tools/list", result)
    for t in (tools_result.tools if tools_result else []):
        result.tools.append({"name": t.name, "description": t.description, "input_schema": t.input_schema})
        result.findings.extend(_scan_description_for_hidden_content(t.name, t.description, "tool", result.target))

    resources_result = await _list_capability(session.list_resources, "resources/list", result)
    for r in (resources_result.resources if resources_result else []):
        result.resources.append({"uri": str(r.uri), "name": r.name, "description": r.description})
        result.findings.extend(_scan_description_for_hidden_content(r.name, r.description, "resource", result.target))

    prompts_result = await _list_capability(session.list_prompts, "prompts/list", result)
    for p in (prompts_result.prompts if prompts_result else []):
        result.prompts.append({"name": p.name, "description": p.description})
        result.findings.extend(_scan_description_for_hidden_content(p.name, p.description, "prompt", result.target))

    if not result.tools and not result.resources and not result.prompts:
        result.findings.append(Finding(
            module="dynamic", rule_id="dynamic.empty-server", title="Server exposes no capabilities",
            description="The server does not expose any tool, resource, or prompt.",
            severity=Severity.LOW, confidence=60, location=result.target,
            remediation="Verify this is intentional — otherwise this may be a placeholder server or a misconfiguration.",
        ))
    elif enable_fuzzing and result.tools:
        await _fuzz_tools(session, result)


# --- Input fuzzing -----------------------------------------------------------

def _fuzz_payloads_for_schema(schema: Optional[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Builds a small, bounded set of structurally malformed argument payloads
    for a tool's declared JSON input schema.

    Deliberately non-destructive: payloads probe type confusion, oversized
    input, missing required fields, and path/control characters in string
    fields — not real exploitation attempts (e.g. no live shell command
    strings, no attempts at actual file deletion). The goal is proving the
    server validates its input robustly, not simulating a specific attack.
    """
    payloads: list[dict[str, Any]] = [{}]  # every argument, including required ones, missing entirely

    properties = (schema or {}).get("properties") if isinstance(schema, dict) else None
    if not properties:
        return payloads[:MAX_FUZZ_PAYLOADS_PER_TOOL]

    oversized: dict[str, Any] = {}
    type_confused: dict[str, Any] = {}
    traversal: dict[str, Any] = {}
    all_null: dict[str, Any] = {}

    for prop_name, prop_schema in properties.items():
        prop_type = (prop_schema or {}).get("type", "string")
        if prop_type == "string":
            oversized[prop_name] = "A" * 10_000
            type_confused[prop_name] = 1234567890
            traversal[prop_name] = "../" * 8 + "etc/passwd\x00.txt"
        elif prop_type in ("integer", "number"):
            oversized[prop_name] = 10 ** 30
            type_confused[prop_name] = "not-a-number"
            traversal[prop_name] = -1
        elif prop_type == "boolean":
            type_confused[prop_name] = "not-a-boolean"
        elif prop_type in ("object", "array"):
            type_confused[prop_name] = "not-an-object-or-array"
        all_null[prop_name] = None

    payloads.extend([oversized, type_confused, traversal, all_null])
    return payloads[:MAX_FUZZ_PAYLOADS_PER_TOOL]


async def _fuzz_tool(session: ClientSession, tool: dict[str, Any], result: DynamicScanResult) -> None:
    name = tool.get("name", "?")
    payloads = _fuzz_payloads_for_schema(tool.get("input_schema"))

    for payload in payloads:
        try:
            call_result = await asyncio.wait_for(session.call_tool(name, payload), timeout=FUZZ_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.fuzz-timeout", title=f"Tool '{name}' timed out on malformed input",
                description=f"Calling '{name}' with a structurally malformed payload did not return within {FUZZ_TIMEOUT_SECONDS:.0f}s.",
                severity=Severity.MEDIUM, confidence=50, location=result.target,
                remediation="Add input validation and bounded processing time for malformed tool arguments.",
                metadata={"payload": _safe_payload_repr(payload)},
            ))
            continue
        except Exception as e:
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.fuzz-crash", title=f"Tool '{name}' raised an unhandled error on malformed input",
                description=(
                    f"Calling '{name}' with a structurally malformed payload raised {_describe_exception(e)} "
                    "instead of returning a controlled MCP error response."
                ),
                severity=Severity.HIGH, confidence=70, location=result.target,
                remediation="Validate tool arguments against the declared input schema before use, and return a normal MCP error response instead of letting exceptions propagate.",
                metadata={"payload": _safe_payload_repr(payload)},
            ))
            continue

        content_text = "".join(
            block.text for block in (getattr(call_result, "content", None) or [])
            if getattr(block, "type", None) == "text"
        )
        if getattr(call_result, "isError", False) and STACK_TRACE_PATTERN.search(content_text):
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.fuzz-stack-trace-leak", title=f"Tool '{name}' leaks a stack trace on malformed input",
                description=f"'{name}' returned an error response that looks like a raw stack trace or internal exception detail.",
                severity=Severity.MEDIUM, confidence=65, location=result.target,
                cwe="CWE-209",
                remediation="Catch exceptions inside the tool handler and return a generic, sanitized error message instead of the raw traceback.",
                code_snippet=content_text[:200],
                metadata={"payload": _safe_payload_repr(payload)},
            ))


async def _fuzz_tools(session: ClientSession, result: DynamicScanResult) -> None:
    for tool in result.tools:
        await _fuzz_tool(session, tool, result)


# --- Transport / target scanning ---------------------------------------------

async def scan_stdio_target(
    command: str,
    args: Optional[list[str]] = None,
    env: Optional[dict[str, str]] = None,
    enable_fuzzing: bool = True,
) -> DynamicScanResult:
    """Scans a local MCP server, started as a subprocess, over the stdio transport."""
    target_desc = f"{command} {' '.join(args or [])}".strip()
    result = DynamicScanResult(target=target_desc, transport="stdio")

    params = StdioServerParameters(command=command, args=args or [], env=env)
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await _enumerate_session(session, result, enable_fuzzing)
                result.connected = True
    except Exception as e:
        result.error = _describe_exception(e)
        result.findings.append(Finding(
            module="dynamic", rule_id="dynamic.connection-failed", title="stdio connection failed",
            description="Could not establish a stdio connection to the server.",
            severity=Severity.HIGH, confidence=90, location=target_desc,
            remediation="Verify the command starts a valid MCP server and check its startup logs.",
            code_snippet=result.error,
        ))

    # TLS and HTTP auth-enforcement checks are not applicable to a local subprocess on stdio.
    result.checks_passed.append("N/A: TLS/HSTS verification does not apply to the stdio transport (local process, no network).")
    result.checks_passed.append("N/A: HTTP auth-enforcement verification does not apply to the stdio transport.")

    return result


async def _check_http_auth_enforcement(url: str, result: DynamicScanResult) -> None:
    """
    Sends an initialize request WITHOUT any authentication header.
    200 -> the server processes unauthenticated requests -> finding.
    401/403 -> enforcement is correct -> checks_passed.
    Anything else -> reported as LOW, to be investigated manually.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp-security-scanner-probe", "version": "1.0"},
        },
    }
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=payload, headers=headers)
        if resp.status_code == 200:
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.no-auth-enforcement", title="Authentication is not enforced",
                description="The server processed an initialize() request WITHOUT any authentication header (status 200).",
                severity=Severity.HIGH, confidence=85, location=url,
                remediation="Require authentication (401/403) for unauthenticated requests — do not process initialize() without valid credentials.",
            ))
        elif resp.status_code in (401, 403):
            result.checks_passed.append(f"Auth enforcement OK: the unauthenticated request received {resp.status_code}.")
        else:
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.unexpected-auth-response", title="Unexpected response to an unauthenticated request",
                description=f"The unauthenticated request received an unexpected status: {resp.status_code}.",
                severity=Severity.LOW, confidence=40, location=url,
                remediation="Investigate manually — neither 200 (no auth) nor 401/403 (auth enforced) was returned.",
            ))
    except Exception as e:
        result.findings.append(Finding(
            module="dynamic", rule_id="dynamic.auth-check-failed", title="Auth enforcement check could not run",
            description="The automated auth-enforcement probe failed for a technical reason (this confirms nothing either way).",
            severity=Severity.LOW, confidence=30, location=url,
            remediation="Investigate manually.", code_snippet=f"{type(e).__name__}: {e}",
        ))


async def _check_tls_and_hsts(url: str, result: DynamicScanResult) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if parsed.scheme != "https":
        if await _is_local_host(host):
            result.checks_passed.append(f"TLS: local target ({host}) — plain HTTP without TLS is expected for local testing.")
        else:
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.no-tls", title="Server exposed over plain HTTP",
                description=f"The server is exposed over plain HTTP (not HTTPS) on a non-local host ({host}).",
                severity=Severity.CRITICAL, confidence=90, location=url,
                remediation="Use HTTPS/TLS for any remote server. Traffic, including any authentication tokens, currently travels unencrypted.",
            ))
        return

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
            resp = await client.get(url)
        hsts = resp.headers.get("strict-transport-security")
        if hsts:
            result.checks_passed.append(f"HSTS present: {hsts}")
        else:
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.missing-hsts", title="Missing HSTS header",
                description="The server uses HTTPS but does not send a Strict-Transport-Security (HSTS) header.",
                severity=Severity.MEDIUM, confidence=75, location=url,
                remediation="Without HSTS, clients can be vulnerable to protocol downgrade attacks (SSL stripping) on the first connection.",
            ))
    except Exception as e:
        result.findings.append(Finding(
            module="dynamic", rule_id="dynamic.tls-check-failed", title="HSTS check could not run",
            description="The HSTS header could not be verified for a technical reason.",
            severity=Severity.LOW, confidence=30, location=url,
            remediation="Investigate manually.", code_snippet=f"{type(e).__name__}: {e}",
        ))


async def scan_http_target(url: str, enable_fuzzing: bool = True) -> DynamicScanResult:
    """Scans an MCP server exposed over Streamable HTTP (local or remote)."""
    result = DynamicScanResult(target=url, transport="http")

    await _check_tls_and_hsts(url, result)
    await _check_http_auth_enforcement(url, result)

    try:
        async with streamable_http_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                await _enumerate_session(session, result, enable_fuzzing)
                result.connected = True
    except Exception as e:
        err_str = _describe_exception(e)
        if any(marker in err_str.lower() for marker in AUTH_REQUIRED_MARKERS):
            # Functional fix versus the previous version: this branch means
            # authentication correctly blocked enumeration — a SECURE
            # outcome, not an error. `result.error` used to still be set
            # here, which made a well-secured server display a misleading
            # "error" in reports. Only checks_passed is populated now.
            result.checks_passed.append(
                "Full enumeration (tools/resources/prompts) was blocked by authentication — the expected "
                "behavior for a secured server. The free-tier scanner does not perform a full OAuth 2.1 "
                "flow, so it stops here without credentials; see core.auth_posture for static auth-mechanism detection."
            )
        else:
            result.error = err_str
            result.findings.append(Finding(
                module="dynamic", rule_id="dynamic.connection-failed", title="Streamable HTTP connection failed",
                description="Could not establish a Streamable HTTP connection to the server.",
                severity=Severity.HIGH, confidence=90, location=url,
                remediation="Verify the server is running and reachable at the given URL.", code_snippet=err_str,
            ))

    return result
