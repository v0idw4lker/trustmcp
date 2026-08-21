"""
Tests for trustmcp.core.registry_resolver — resolving a `check` reference to
a downloadable tarball URL + supply-chain metadata.

No real network calls: httpx.get is monkeypatched to return canned JSON
shaped exactly like the real npm/PyPI/GitHub API responses documented in the
module docstring.
"""

from __future__ import annotations

import pytest

from trustmcp.core import registry_resolver
from trustmcp.utils.exceptions import OfflineModeError, RegistryResolutionError

NPM_RESPONSE = {
    "dist-tags": {"latest": "1.2.3"},
    "maintainers": [{"name": "alice"}, {"name": "bob"}],
    "time": {"created": "2020-01-01T00:00:00.000Z", "1.2.3": "2024-06-01T00:00:00.000Z"},
    "versions": {
        "1.2.3": {
            "dist": {"tarball": "https://registry.npmjs.org/some-pkg/-/some-pkg-1.2.3.tgz"},
            "repository": {"url": "git+https://github.com/someorg/some-pkg.git"},
            "scripts": {"postinstall": "node setup.js", "test": "jest"},
        }
    },
}

PYPI_RESPONSE = {
    "info": {
        "version": "0.5.0",
        "project_urls": {"Repository": "https://github.com/someorg/some-pkg", "Homepage": "https://example.com"},
    },
    "urls": [
        {"url": "https://files.pythonhosted.org/packages/x/some-pkg-0.5.0.whl", "upload_time_iso_8601": "2024-06-01T00:00:00Z"},
        {"url": "https://files.pythonhosted.org/packages/x/some-pkg-0.5.0.tar.gz", "upload_time_iso_8601": "2024-06-01T00:00:00Z"},
    ],
    "releases": {
        "0.1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
        "0.5.0": [{"upload_time_iso_8601": "2024-06-01T00:00:00Z"}],
    },
}

GITHUB_REPO_RESPONSE = {
    "default_branch": "main",
    "created_at": "2019-01-01T00:00:00Z",
    "pushed_at": "2024-06-01T00:00:00Z",
}


class _FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json_data = json_data
        self.status_code = status_code

    def json(self):
        return self._json_data


def _fake_get(url, **kwargs):
    if "registry.npmjs.org" in url:
        return _FakeResponse(NPM_RESPONSE)
    if "pypi.org" in url:
        return _FakeResponse(PYPI_RESPONSE)
    if "api.github.com" in url:
        return _FakeResponse(GITHUB_REPO_RESPONSE)
    return _FakeResponse({}, status_code=404)


def test_resolve_npm_uses_dist_tags_latest_and_confirmed_fields(monkeypatch):
    monkeypatch.setattr(registry_resolver.httpx, "get", _fake_get)
    metadata = registry_resolver.resolve_reference("npm:some-pkg", timeout=5, offline=False)

    assert metadata.ecosystem == "npm"
    assert metadata.resolved_version == "1.2.3"
    assert metadata.download_url == "https://registry.npmjs.org/some-pkg/-/some-pkg-1.2.3.tgz"
    assert metadata.repository_url == "https://github.com/someorg/some-pkg"  # git+ prefix and .git suffix stripped
    assert metadata.maintainers_count == 2
    assert metadata.created == "2020-01-01T00:00:00.000Z"
    assert metadata.last_publish == "2024-06-01T00:00:00.000Z"
    assert metadata.install_scripts == {"postinstall": "node setup.js"}  # "test" is not a lifecycle script


def test_resolve_npm_scoped_name_is_url_encoded(monkeypatch):
    captured_urls = []

    def _capture_get(url, **kwargs):
        captured_urls.append(url)
        return _fake_get(url, **kwargs)

    monkeypatch.setattr(registry_resolver.httpx, "get", _capture_get)
    registry_resolver.resolve_reference("npm:@modelcontextprotocol/server-filesystem", timeout=5, offline=False)

    assert captured_urls == ["https://registry.npmjs.org/@modelcontextprotocol%2Fserver-filesystem"]


def test_resolve_pypi_prefers_tar_gz_sdist_over_wheel(monkeypatch):
    monkeypatch.setattr(registry_resolver.httpx, "get", _fake_get)
    metadata = registry_resolver.resolve_reference("pypi:some-pkg", timeout=5, offline=False)

    assert metadata.ecosystem == "pypi"
    assert metadata.download_url.endswith(".tar.gz")
    assert metadata.repository_url == "https://github.com/someorg/some-pkg"
    assert metadata.maintainers_count is None  # PyPI does not expose this — known gap, not faked
    assert metadata.created == "2020-01-01T00:00:00Z"  # from the earliest key in `releases`


def test_resolve_github_looks_up_default_branch_and_builds_codeload_url(monkeypatch):
    monkeypatch.setattr(registry_resolver.httpx, "get", _fake_get)
    metadata = registry_resolver.resolve_reference("github:someorg/some-pkg", timeout=5, offline=False)

    assert metadata.ecosystem == "github"
    assert metadata.resolved_version == "main"
    assert metadata.download_url == "https://codeload.github.com/someorg/some-pkg/tar.gz/refs/heads/main"


def test_resolve_github_explicit_ref_skips_default_branch_lookup(monkeypatch):
    monkeypatch.setattr(registry_resolver.httpx, "get", _fake_get)
    metadata = registry_resolver.resolve_reference("github:someorg/some-pkg@v2.0.0", timeout=5, offline=False)

    assert metadata.resolved_version == "v2.0.0"
    assert metadata.download_url == "https://codeload.github.com/someorg/some-pkg/tar.gz/refs/heads/v2.0.0"


def test_resolve_server_json_follows_npm_package_entry(monkeypatch):
    server_json = {
        "name": "io.github.someorg/some-pkg",
        "repository": {"url": "https://github.com/someorg/some-pkg", "source": "github"},
        "packages": [{"registryType": "npm", "identifier": "some-pkg", "version": "1.2.3"}],
    }

    def _fake_get_with_server_json(url, **kwargs):
        if url == "https://example.com/server.json":
            return _FakeResponse(server_json)
        return _fake_get(url, **kwargs)

    monkeypatch.setattr(registry_resolver.httpx, "get", _fake_get_with_server_json)
    metadata = registry_resolver.resolve_reference("https://example.com/server.json", timeout=5, offline=False)

    assert metadata.ecosystem == "npm"
    assert metadata.download_url == "https://registry.npmjs.org/some-pkg/-/some-pkg-1.2.3.tgz"
    assert metadata.repository_url == "https://github.com/someorg/some-pkg"  # the record's own repository.url wins


def test_unrecognized_reference_raises_clear_error():
    with pytest.raises(RegistryResolutionError):
        registry_resolver.resolve_reference("not-a-valid-reference", timeout=5, offline=False)


def test_offline_mode_raises_before_any_network_call(monkeypatch):
    def _fail_if_called(url, **kwargs):
        raise AssertionError(f"network call attempted while --offline is set: {url}")

    monkeypatch.setattr(registry_resolver.httpx, "get", _fail_if_called)

    with pytest.raises(OfflineModeError):
        registry_resolver.resolve_reference("npm:some-pkg", timeout=5, offline=True)
