"""
Registry resolution — free tier, core.registry_resolver.

Resolves a `trustmcp check <reference>` reference to a downloadable source
tarball URL, plus the manifest metadata core.supply_chain needs to assess
pre-install trust signals (package age, last-publish recency, maintainer
count, declared install scripts, the manifest's own repository URL).

Supported reference forms:
    npm:<package>[@version]           e.g. npm:@modelcontextprotocol/server-filesystem
    pypi:<package>[==version|@version] e.g. pypi:mcp-server-time==0.3.0
    github:<owner>/<repo>[@ref]        e.g. github:modelcontextprotocol/servers
    <a server.json URL>                fetched and followed to the underlying
                                        npm/pypi/github package it names

Exact response shapes relied on below (verified against the live registries,
not guessed):
    npm    GET https://registry.npmjs.org/<package>
           dist-tags.latest, versions[latest].dist.tarball,
           versions[latest].repository.url, maintainers (array),
           time.created, time[latest_version], versions[latest].scripts
    PyPI   GET https://pypi.org/pypi/<package>/json
           info.version, urls[] (the .tar.gz entry is the sdist),
           info.project_urls.Repository / .Homepage, releases (dict keyed
           by version)
    GitHub GET https://api.github.com/repos/<owner>/<repo> -> default_branch,
           then https://codeload.github.com/<owner>/<repo>/tar.gz/refs/heads/<branch>
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import httpx

from .. import __version__
from ..utils.exceptions import OfflineModeError, RegistryResolutionError

_USER_AGENT = f"trustmcp-check/{__version__} (+https://github.com/v0idw4lker/trustmcp)"


@dataclass
class RegistryMetadata:
    """Resolved package info, plus everything core.supply_chain needs to run pre-install checks."""

    ecosystem: str            # "npm" | "pypi" | "github"
    package_name: str
    resolved_version: str
    download_url: str
    repository_url: Optional[str] = None
    created: Optional[str] = None       # ISO-8601: first-ever release/publish (npm/pypi) or repo creation (github)
    last_publish: Optional[str] = None  # ISO-8601: this version's publish date (npm/pypi) or last push (github)
    maintainers_count: Optional[int] = None  # npm only — PyPI/GitHub don't expose this the same way (known gap)
    install_scripts: dict[str, str] = field(default_factory=dict)  # npm only: preinstall/postinstall/install
    raw_manifest: dict[str, Any] = field(default_factory=dict)


def _http_get_json(url: str, *, timeout: float, offline: bool) -> dict[str, Any]:
    if offline:
        raise OfflineModeError(f"--offline is set; refusing to fetch {url}")
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, headers={"User-Agent": _USER_AGENT})
    except httpx.TimeoutException as e:
        raise RegistryResolutionError(f"Request to {url} timed out after {timeout}s (see --timeout).") from e
    except httpx.HTTPError as e:
        raise RegistryResolutionError(f"Request to {url} failed: {e}") from e
    if resp.status_code == 404:
        raise RegistryResolutionError(f"Not found: {url} (HTTP 404). Check the package name/reference.")
    if resp.status_code >= 400:
        raise RegistryResolutionError(f"Request to {url} failed: HTTP {resp.status_code}.")
    try:
        return resp.json()
    except ValueError as e:
        raise RegistryResolutionError(f"Response from {url} was not valid JSON: {e}") from e


def _normalize_repo_url(url: Optional[str]) -> Optional[str]:
    """Strips npm's 'git+' prefix, git:// / git@ shorthand, and a trailing '.git' so the URL is a plain https:// browser link."""
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip()
    if url.startswith("git+"):
        url = url[4:]
    if url.startswith("git://"):
        url = "https://" + url[len("git://") :]
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:") :]
    if url.endswith(".git"):
        url = url[:-4]
    return url or None


# --- npm ---------------------------------------------------------------------

def _split_npm_name_version(ref: str) -> tuple[str, Optional[str]]:
    """
    Splits 'name@version' or '@scope/name@version' on the version-separating
    '@'. Searches from index 1 so a scoped name's leading '@' (position 0) is
    never mistaken for the version separator.
    """
    at_idx = ref.find("@", 1)
    if at_idx == -1:
        return ref, None
    return ref[:at_idx], ref[at_idx + 1 :] or None


def _resolve_npm(ref: str, *, timeout: float, offline: bool) -> RegistryMetadata:
    name, requested_version = _split_npm_name_version(ref)
    encoded_name = quote(name, safe="@")  # encodes '/' -> %2F, leaves '@' (scope marker) literal
    url = f"https://registry.npmjs.org/{encoded_name}"
    data = _http_get_json(url, timeout=timeout, offline=offline)

    versions = data.get("versions", {})
    version = requested_version or data.get("dist-tags", {}).get("latest")
    if not version or version not in versions:
        raise RegistryResolutionError(
            f"npm:{name} — could not resolve version '{version}' (available via dist-tags.latest or an explicit @version)."
        )
    version_data = versions[version]

    tarball = version_data.get("dist", {}).get("tarball")
    if not tarball:
        raise RegistryResolutionError(f"npm:{name}@{version} has no dist.tarball URL in the registry response.")

    repo = version_data.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else (repo if isinstance(repo, str) else None)

    maintainers = data.get("maintainers")
    maintainers_count = len(maintainers) if isinstance(maintainers, list) else None

    time_data = data.get("time", {}) if isinstance(data.get("time"), dict) else {}
    scripts = version_data.get("scripts") or {}
    install_scripts = {k: v for k, v in scripts.items() if k in ("preinstall", "postinstall", "install")}

    return RegistryMetadata(
        ecosystem="npm", package_name=name, resolved_version=version,
        download_url=tarball, repository_url=_normalize_repo_url(repo_url),
        created=time_data.get("created"), last_publish=time_data.get(version),
        maintainers_count=maintainers_count, install_scripts=install_scripts,
        raw_manifest=data,
    )


# --- PyPI ----------------------------------------------------------------------

def _split_pypi_name_version(ref: str) -> tuple[str, Optional[str]]:
    for sep in ("==", "@"):
        if sep in ref:
            name, version = ref.split(sep, 1)
            return name.strip(), (version.strip() or None)
    return ref.strip(), None


def _resolve_pypi(ref: str, *, timeout: float, offline: bool) -> RegistryMetadata:
    name, requested_version = _split_pypi_name_version(ref)
    encoded_name = quote(name, safe="")
    if requested_version:
        url = f"https://pypi.org/pypi/{encoded_name}/{quote(requested_version, safe='')}/json"
    else:
        url = f"https://pypi.org/pypi/{encoded_name}/json"
    data = _http_get_json(url, timeout=timeout, offline=offline)

    info = data.get("info", {})
    resolved_version = info.get("version")
    urls = data.get("urls", [])
    sdist = next((u for u in urls if isinstance(u, dict) and str(u.get("url", "")).endswith(".tar.gz")), None)
    if sdist is None:
        raise RegistryResolutionError(
            f"pypi:{name} {resolved_version or ''} — no sdist (.tar.gz) is published, only wheel(s); "
            "there is no source tarball to statically scan."
        )
    download_url = sdist["url"]

    project_urls = info.get("project_urls") or {}
    repo_url = project_urls.get("Repository") or project_urls.get("Homepage")

    releases = data.get("releases", {}) if isinstance(data.get("releases"), dict) else {}
    created = None
    if releases:
        # PyPI returns `releases` with the first-ever version as the first key
        # (verified against the live API) — its earliest file's upload time is
        # used as the package's age reference point.
        first_version = next(iter(releases))
        first_files = [f for f in releases[first_version] if isinstance(f, dict)]
        times = [f.get("upload_time_iso_8601") or f.get("upload_time") for f in first_files]
        times = [t for t in times if t]
        if times:
            created = min(times)

    current_files = [u for u in urls if isinstance(u, dict)]
    last_times = [f.get("upload_time_iso_8601") or f.get("upload_time") for f in current_files]
    last_times = [t for t in last_times if t]
    last_publish = max(last_times) if last_times else None

    return RegistryMetadata(
        ecosystem="pypi", package_name=name, resolved_version=resolved_version or (requested_version or "unknown"),
        download_url=download_url, repository_url=_normalize_repo_url(repo_url),
        created=created, last_publish=last_publish,
        maintainers_count=None,  # PyPI's JSON API does not expose a maintainer count the way npm's does — known gap
        install_scripts={},      # pip has no npm-style auto-run lifecycle scripts
        raw_manifest=data,
    )


# --- GitHub --------------------------------------------------------------------

def _resolve_github(ref: str, *, timeout: float, offline: bool) -> RegistryMetadata:
    owner_repo, _, explicit_ref = ref.partition("@")
    owner_repo = owner_repo.strip().strip("/")
    if "/" not in owner_repo:
        raise RegistryResolutionError(f"Invalid github reference {ref!r} — expected 'owner/repo' or 'owner/repo@ref'.")
    owner, repo = owner_repo.split("/", 1)

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    repo_data = _http_get_json(api_url, timeout=timeout, offline=offline)

    branch = explicit_ref or repo_data.get("default_branch")
    if not branch:
        raise RegistryResolutionError(f"github:{owner}/{repo} — could not determine the default branch.")

    download_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"

    return RegistryMetadata(
        ecosystem="github", package_name=f"{owner}/{repo}", resolved_version=branch,
        download_url=download_url, repository_url=f"https://github.com/{owner}/{repo}",
        created=repo_data.get("created_at"), last_publish=repo_data.get("pushed_at"),
        maintainers_count=None,  # GitHub's repo API doesn't expose "maintainers" the way npm's registry does — known gap
        install_scripts={},
        raw_manifest=repo_data,
    )


# --- server.json (official MCP registry record) ---------------------------------

_GITHUB_URL_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")


def _resolve_server_json(url: str, *, timeout: float, offline: bool) -> RegistryMetadata:
    data = _http_get_json(url, timeout=timeout, offline=offline)

    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        raise RegistryResolutionError(f"server.json at {url} lists no 'packages' entry to resolve.")
    pkg = packages[0]  # a record may list several distributions; the first is used deterministically

    registry_type = str(pkg.get("registryType") or "").lower()
    identifier = pkg.get("identifier")
    version = pkg.get("version")
    if not identifier:
        raise RegistryResolutionError(f"server.json at {url} has a package entry with no 'identifier'.")

    if registry_type == "npm":
        resolved = _resolve_npm(f"{identifier}@{version}" if version else identifier, timeout=timeout, offline=offline)
    elif registry_type == "pypi":
        resolved = _resolve_pypi(f"{identifier}=={version}" if version else identifier, timeout=timeout, offline=offline)
    else:
        # oci / mcpb / nuget / cargo / an unrecognized future type: fall back
        # to the record's own repository.url, if it points at GitHub.
        top_repo_url = (data.get("repository") or {}).get("url", "")
        m = _GITHUB_URL_RE.match(top_repo_url or "")
        if not m:
            raise RegistryResolutionError(
                f"server.json at {url} declares registryType '{registry_type or '(none)'}', which trustmcp cannot "
                "resolve to a source tarball, and its 'repository.url' is not a GitHub URL to fall back to."
            )
        resolved = _resolve_github(f"{m.group(1)}/{m.group(2)}", timeout=timeout, offline=offline)

    # The server.json record's own declared repository URL is more
    # authoritative for this MCP server than whatever the underlying
    # npm/PyPI manifest happens to say (which may point at a monorepo, a
    # fork, or be missing entirely).
    top_repo_url = _normalize_repo_url((data.get("repository") or {}).get("url"))
    if top_repo_url:
        resolved.repository_url = top_repo_url
    resolved.raw_manifest = {"server_json": data, "underlying_registry_manifest": resolved.raw_manifest}
    return resolved


# --- Top-level dispatch -----------------------------------------------------------

def resolve_reference(reference: str, *, timeout: float, offline: bool) -> RegistryMetadata:
    """Parses and resolves a `check` reference to a RegistryMetadata (download URL + supply-chain metadata)."""
    reference = reference.strip()
    if not reference:
        raise RegistryResolutionError("Empty reference.")

    if reference.startswith("npm:"):
        return _resolve_npm(reference[len("npm:") :], timeout=timeout, offline=offline)
    if reference.startswith("pypi:"):
        return _resolve_pypi(reference[len("pypi:") :], timeout=timeout, offline=offline)
    if reference.startswith("github:"):
        return _resolve_github(reference[len("github:") :], timeout=timeout, offline=offline)
    if reference.startswith("http://") or reference.startswith("https://"):
        return _resolve_server_json(reference, timeout=timeout, offline=offline)

    raise RegistryResolutionError(
        f"Unrecognized reference {reference!r}. Use 'npm:<package>', 'pypi:<package>', 'github:<owner>/<repo>', "
        "or a server.json URL (http:// or https://)."
    )
