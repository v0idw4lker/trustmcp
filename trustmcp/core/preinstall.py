"""
Pre-install scan orchestration — free tier, core.preinstall.

Implements `trustmcp check <reference>`: resolves a registry reference
(core.registry_resolver), downloads its source tarball into an isolated
temp directory, extracts it WITHOUT ever executing anything from it (no
install scripts, no import, no npm/pip install — extract and read only),
then runs the existing static analyzer and auth-posture analyzer over the
extracted source plus the pre-install-only supply-chain checks
(core.supply_chain), and returns a single combined result.

The dynamic module is deliberately never run here — it requires a live,
running server, which would mean executing untrusted code.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
from urllib.request import url2pathname

import httpx

from ..utils.exceptions import DownloadError, OfflineModeError
from .auth_posture import analyze_auth_posture
from .models import Finding, Severity, SEVERITY_RANK
from .registry_resolver import RegistryMetadata, resolve_reference
from .scoring import ScoreReport
from .static_analyzer import scan_directory
from .supply_chain import assess_supply_chain

# A tarball's DECLARED uncompressed size is checked against
# max_size_bytes * DECOMPRESSED_SIZE_MULTIPLIER before extraction, so a small
# downloaded (compressed, size-capped) tarball can't still decompress into a
# disk-filling zip/tar bomb.
DECOMPRESSED_SIZE_MULTIPLIER = 20


@dataclass
class PreinstallScanResult:
    reference: str
    metadata: RegistryMetadata
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)


def download_tarball(url: str, dest_dir: str, *, timeout: float, max_size_bytes: int, offline: bool) -> str:
    """Downloads url into dest_dir, enforcing --timeout and --max-size (Content-Length AND actual bytes streamed). Returns the local file path."""
    if offline:
        raise OfflineModeError(f"--offline is set; refusing to download {url}")

    dest_path = os.path.join(dest_dir, "package.download")
    parsed = urlparse(url)

    if parsed.scheme == "file":
        # Local file:// support exists for tests (a locally served fixture
        # tarball) — still honors --offline above, just skips the network stack.
        local_path = url2pathname(parsed.path)
        try:
            size = os.path.getsize(local_path)
        except OSError as e:
            raise DownloadError(f"Could not read local tarball at {local_path}: {e}") from e
        if size > max_size_bytes:
            raise DownloadError(f"Refusing to use {url}: file size {size} bytes exceeds --max-size ({max_size_bytes} bytes).")
        shutil.copyfile(local_path, dest_path)
        return dest_path

    if parsed.scheme not in ("http", "https"):
        raise DownloadError(f"Unsupported URL scheme for download: {url!r}")

    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as resp:
            resp.raise_for_status()
            content_length = resp.headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > max_size_bytes:
                        raise DownloadError(
                            f"Refusing to download {url}: Content-Length {content_length} exceeds --max-size ({max_size_bytes} bytes)."
                        )
                except ValueError:
                    pass
            bytes_written = 0
            with open(dest_path, "wb") as fh:
                for chunk in resp.iter_bytes():
                    bytes_written += len(chunk)
                    if bytes_written > max_size_bytes:
                        raise DownloadError(
                            f"Refusing to continue downloading {url}: exceeded --max-size ({max_size_bytes} bytes) "
                            "while streaming (Content-Length was absent or understated)."
                        )
                    fh.write(chunk)
    except httpx.TimeoutException as e:
        raise DownloadError(f"Download of {url} timed out after {timeout}s (see --timeout).") from e
    except httpx.HTTPStatusError as e:
        raise DownloadError(f"Download of {url} failed: HTTP {e.response.status_code}.") from e
    except httpx.HTTPError as e:
        raise DownloadError(f"Download of {url} failed: {e}") from e

    return dest_path


def safe_extract_tarball(tarball_path: str, dest_dir: str, *, max_size_bytes: int) -> str:
    """
    Extracts tarball_path into dest_dir, refusing: members whose resolved
    path would escape dest_dir (path traversal / "tar slip"), symlink/hardlink
    members pointing outside dest_dir, device/fifo special files, and a
    declared total uncompressed size disproportionate to the (already
    size-capped) compressed download (a bomb guard). Returns the extracted
    package's root directory, unwrapping a single common top-level folder
    (e.g. npm's 'package/', GitHub's '<repo>-<branch>/') if present.
    """
    dest_abs = os.path.abspath(dest_dir)

    try:
        tar = tarfile.open(tarball_path, "r:*")
    except tarfile.TarError as e:
        raise DownloadError(f"Could not open {tarball_path} as a tar archive: {e}") from e

    with tar:
        try:
            members = tar.getmembers()
        except tarfile.TarError as e:
            raise DownloadError(f"Could not read members of {tarball_path}: {e}") from e

        total_declared_size = sum(m.size for m in members if m.isfile())
        if total_declared_size > max_size_bytes * DECOMPRESSED_SIZE_MULTIPLIER:
            raise DownloadError(
                f"Refusing to extract {tarball_path}: declared uncompressed size ({total_declared_size} bytes) "
                f"is disproportionate to the download size cap (--max-size, x{DECOMPRESSED_SIZE_MULTIPLIER})."
            )

        for member in members:
            member_path = os.path.abspath(os.path.join(dest_dir, member.name))
            if not (member_path == dest_abs or member_path.startswith(dest_abs + os.sep)):
                raise DownloadError(f"Refusing to extract {tarball_path}: member '{member.name}' would escape the extraction directory.")
            if member.issym() or member.islnk():
                link_target = os.path.abspath(os.path.join(dest_dir, member.linkname))
                if not (link_target == dest_abs or link_target.startswith(dest_abs + os.sep)):
                    raise DownloadError(f"Refusing to extract {tarball_path}: link member '{member.name}' points outside the extraction directory.")
            if member.isdev():
                raise DownloadError(f"Refusing to extract {tarball_path}: member '{member.name}' is a device/fifo special file.")

        try:
            tar.extractall(dest_dir, members=members, filter="data")  # Python 3.12+: extra defense-in-depth
        except TypeError:
            tar.extractall(dest_dir, members=members)  # Python 3.10/3.11: no 'filter' kwarg — manual checks above already covered it

    entries = [e for e in os.listdir(dest_dir) if e != os.path.basename(tarball_path)]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest_dir, entries[0])):
        return os.path.join(dest_dir, entries[0])
    return dest_dir


def _relocate_finding(f: Finding, extracted_dir: str, reference_label: str) -> Finding:
    """
    Rewrites a static/auth-posture finding's location from an absolute path
    inside the (about to be deleted) temp extraction directory to a path
    relative to the package root, namespaced by the resolved reference — e.g.
    'npm:some-pkg@1.2.3#src/server.py'. Without this, the CLI verdict and the
    persisted JSON/SARIF reports would point at a directory that no longer
    exists by the time anyone reads them.
    """
    try:
        rel = os.path.relpath(f.location, extracted_dir)
    except ValueError:
        return f  # different drive on Windows or similar — leave the original location as-is
    if rel.startswith(".."):
        return f
    rel = rel.replace(os.sep, "/")
    f.location = reference_label if rel == "." else f"{reference_label}#{rel}"
    return f


def run_preinstall_scan(reference: str, *, timeout: float, max_size_bytes: int, offline: bool) -> PreinstallScanResult:
    metadata = resolve_reference(reference, timeout=timeout, offline=offline)
    reference_label = f"{metadata.ecosystem}:{metadata.package_name}@{metadata.resolved_version}"

    tmp_dir = tempfile.mkdtemp(prefix="trustmcp-check-")
    try:
        tarball_path = download_tarball(metadata.download_url, tmp_dir, timeout=timeout, max_size_bytes=max_size_bytes, offline=offline)
        extracted_dir = safe_extract_tarball(tarball_path, tmp_dir, max_size_bytes=max_size_bytes)
        try:
            os.remove(tarball_path)
        except OSError:
            pass

        findings: list[Finding] = []
        static_result = scan_directory(extracted_dir)
        findings.extend(_relocate_finding(f, extracted_dir, reference_label) for f in static_result.findings)
        auth_result = analyze_auth_posture(extracted_dir)
        findings.extend(_relocate_finding(f, extracted_dir, reference_label) for f in auth_result.findings)
        findings.extend(assess_supply_chain(metadata, timeout=timeout, offline=offline))

        return PreinstallScanResult(
            reference=reference, metadata=metadata,
            files_scanned=static_result.files_scanned, findings=findings,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def build_verdict(score_report: ScoreReport) -> str:
    """One clear line aimed at the install decision, e.g. 'Grade D. Do not install without reviewing tools/exec.py:44 first.'"""
    if not score_report.findings:
        return f"Grade {score_report.grade}. No blocking findings."

    worst = max(score_report.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0))
    if SEVERITY_RANK.get(worst.severity, 0) >= SEVERITY_RANK[Severity.HIGH]:
        location = f"{worst.location}:{worst.line}" if worst.line else worst.location
        return f"Grade {score_report.grade}. Do not install without reviewing {location} first."
    return f"Grade {score_report.grade}. No blocking findings, but review the report below before installing."
