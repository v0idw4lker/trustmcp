"""
Shared finding model used by every analysis module (static, dynamic, auth
posture — and, if installed locally, a premium module) and consumed
uniformly by every reporter (CLI, JSON, SARIF).

Design note: the original prototype had each module produce its own finding
shape (static used "issue", dynamic used "check", semantic used "category"),
which forced scoring and every reporter to special-case each module
individually and made the OWASP mapping brittle (it matched on free-text
titles, so rewording a message silently broke the mapping). A single
contract here removes both problems: adding a new analysis module is just a
matter of emitting Finding objects with a stable rule_id — no reporter or
scoring changes required.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Higher = more severe. Used for sorting and for picking the worst severity
# when the same remediation text is produced by findings of different severity.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

# Score deduction per finding, by severity. Shared by core.scoring so every
# module is penalized on the same scale.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}


@dataclass
class Finding:
    """A single, normalized security finding from any analysis module."""

    module: str                    # "static" | "dynamic" | "auth-posture" | a premium module's key
    rule_id: str                   # stable machine-readable id, e.g. "static.dangerous-eval-exec"
    title: str
    description: str
    severity: Severity
    confidence: int                # 0-100, heuristic prior — see CONFIDENCE_DISCLAIMER in static_analyzer
    location: str                  # file path, or "stdio:<command>" / URL for a live target
    line: int = 1
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: str = ""
    code_snippet: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        return d
