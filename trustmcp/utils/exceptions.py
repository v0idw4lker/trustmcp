"""
Custom exception hierarchy for predictable, user-facing error handling.

The CLI entrypoint catches ScannerError specifically and prints a clean,
actionable message instead of a raw Python traceback. Unexpected exceptions
are deliberately left to propagate — silently swallowing them would hide
real bugs instead of surfacing them.
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for all expected, user-facing scanner errors."""


class InvalidTargetError(ScannerError):
    """Raised when a --target value cannot be parsed or is malformed."""


class ReportWriteError(ScannerError):
    """Raised when a report file cannot be written to disk."""


class OfflineModeError(ScannerError):
    """Raised when --offline is set and an operation would require network access."""


class RegistryResolutionError(ScannerError):
    """Raised when a `check` reference cannot be resolved to a downloadable package (bad reference, 404, malformed manifest, ...)."""


class DownloadError(ScannerError):
    """Raised when downloading or safely extracting a package tarball fails (timeout, too large, path traversal, ...)."""
