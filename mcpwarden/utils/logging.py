"""
Central console/logging setup for the CLI.

Every module prints through the single Console instance created here so
output formatting (colors, width, forced terminal rendering for CI logs) is
consistent across the whole tool, rather than each module constructing its
own rich.Console() with slightly different defaults.
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
        force=True,
    )
    logger = logging.getLogger("mcpwarden")
    logger.setLevel(level)
    return logger


logger = setup_logging()
