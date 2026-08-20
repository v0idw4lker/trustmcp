"""
Shared text-safety helpers used by both the static analyzer (source code on
disk) and the dynamic client (tool/resource/prompt descriptions actually
served by a live MCP server).

Keeping this in exactly one place matters: the whole point of running the
same check in two places is to compare what the code SAYS against what the
server actually SERVES at runtime and catch drift (a server that behaves
differently from its own source — see dynamic_client.py). If the two paths
used different character sets, that comparison would be meaningless.
"""

from __future__ import annotations

import re
import unicodedata

# Covers three distinct obfuscation techniques, not just simple zero-width
# spacing:
#   - Classic zero-width / BOM characters (invisible, used to hide text).
#   - Bidirectional control characters — the "Trojan Source" attack class
#     (CVE-2021-42574): they reorder how text/code visually renders versus
#     how it actually executes or parses.
#   - The Unicode Tag block (U+E0000-U+E007F) — invisible characters used
#     for "ASCII smuggling" to hide instructions from/for LLMs inside
#     otherwise normal-looking text, since most fonts render them as nothing.
HIDDEN_UNICODE_PATTERN = re.compile(
    "[​‌‍﻿⁠᠎"
    "‪-‮⁦-⁩"
    "\U000e0000-\U000e007f]"
)


def find_hidden_unicode(text: str) -> list[str]:
    """Returns the Unicode character names of any hidden/obfuscation characters found in text."""
    if not text:
        return []
    names = []
    for ch in HIDDEN_UNICODE_PATTERN.findall(text):
        try:
            names.append(unicodedata.name(ch))
        except ValueError:
            names.append(f"U+{ord(ch):04X}")
    return names
