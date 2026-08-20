"""
Extension point for premium analysis modules — core.plugins.

This free-tier package ships no implementation behind this interface.
Semantic (LLM) analysis and cross-server toxic-flow detection are reserved
for the paid SaaS tier. A premium module, if installed locally, registers
itself here at import time (see the local, gitignored `premium/` package in
this repository for a working reference implementation); the CLI queries
the registry after core free-tier analysis to merge its Finding objects
into the unified report/score, and prints a short note for any catalogued
capability that is NOT currently registered.

Because every module — free or premium — emits the same core.models.Finding
objects, a registered premium module needs no special-casing anywhere else
in the codebase: not in scoring, not in any reporter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .dynamic_client import DynamicScanResult
from .models import Finding


class AnalysisModule(Protocol):
    """Interface a premium analysis module must implement to plug into the pipeline."""

    key: str  # stable identifier, e.g. "semantic" or "toxic-flow"

    def run(self, *, target_directory: str, dynamic_results: list[DynamicScanResult]) -> list[Finding]:
        """Runs the module's analysis and returns Finding objects to merge into the report."""
        ...


@dataclass(frozen=True)
class PremiumModuleInfo:
    key: str
    display_name: str
    description: str


# Catalog of premium capabilities this free tier is aware of, so the CLI can
# advertise them even when none happen to be installed locally.
KNOWN_PREMIUM_MODULES: tuple[PremiumModuleInfo, ...] = (
    PremiumModuleInfo(
        key="semantic",
        display_name="Semantic (LLM) Analysis",
        description="Detects hidden instructions, scope overreach, and model-manipulation language in tool/resource/prompt descriptions using an LLM rubric.",
    ),
    PremiumModuleInfo(
        key="toxic-flow",
        display_name="Cross-Server Toxic-Flow Detection",
        description="Flags dangerous capability combinations across multiple simultaneously connected MCP servers.",
    ),
)

_REGISTRY: dict[str, AnalysisModule] = {}


def register(module: AnalysisModule) -> None:
    """Called by a premium module at import time to register itself."""
    _REGISTRY[module.key] = module


def get_registered() -> dict[str, AnalysisModule]:
    return dict(_REGISTRY)


def run_registered(*, target_directory: str, dynamic_results: list[DynamicScanResult]) -> list[Finding]:
    findings: list[Finding] = []
    for module in _REGISTRY.values():
        findings.extend(module.run(target_directory=target_directory, dynamic_results=dynamic_results))
    return findings


def unregistered_known_modules() -> tuple[PremiumModuleInfo, ...]:
    return tuple(m for m in KNOWN_PREMIUM_MODULES if m.key not in _REGISTRY)
