"""
Regression tests for four rule bugs found by running the scanner against its
own repo and synthetic test cases (see project memory / PR description):

1. Known-vulnerable dependency check fired on safe version ranges because it
   only looked at `==` constraints.
2. dependency-weak-constraint contradicted its own printed snippet for
   bounded ranges like `>=2.0.0,<3.0.0`.
3. The path-traversal open() rule ignored the file mode, so open(path, "w")
   was reported as an arbitrary-file-READ risk.
4. No way to suppress a finding inline, so a working-tree copy of trustmcp's
   own source produces noise about its own detection signatures.
"""

import os

from trustmcp.core.static_analyzer import (
    _scan_package_json_file,
    _scan_requirements_txt_file,
    scan_python_file,
)


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# --- FIX 1: known-vulnerable dependency version parsing ---------------------


def test_requirements_range_above_fixed_version_does_not_fire(tmp_path):
    # requests' advisory is fixed in 2.20.0; the constraint's lowest possible
    # resolution (2.19.2) is already past that, so this must not fire at all.
    path = _write(tmp_path, "requirements.txt", "requests>=2.19.2,<3.0.0\n")
    findings = _scan_requirements_txt_file(path)
    assert "static.dependency-known-vulnerable" not in _rule_ids(findings)


def test_requirements_range_permitting_vulnerable_version_fires_honestly(tmp_path):
    # This is the exact case from the bug report: requests>=2.0.0 permits
    # (but does not confirm) a version at/below the vulnerable 2.19.1.
    path = _write(tmp_path, "requirements.txt", "requests>=2.0.0,<3.0.0\n")
    findings = _scan_requirements_txt_file(path)
    hits = [f for f in findings if f.rule_id == "static.dependency-known-vulnerable"]
    assert len(hits) == 1
    assert "permit" in hits[0].description.lower()
    assert "permit" in hits[0].title.lower()
    # Weaker claim than a confirmed hit -> lower confidence than the old
    # unconditional 75, and the exact-pin case below.
    assert hits[0].confidence < 75
    # No exact pin proves the resolved version is actually vulnerable (pip
    # resolves to the newest version a constraint permits), so this must not
    # carry the same severity as a confirmed hit.
    assert hits[0].severity.value == "LOW"


def test_requirements_exact_vulnerable_pin_still_fires_at_full_confidence(tmp_path):
    path = _write(tmp_path, "requirements.txt", "django==3.2.10\n")
    findings = _scan_requirements_txt_file(path)
    hits = [f for f in findings if f.rule_id == "static.dependency-known-vulnerable"]
    assert len(hits) == 1
    assert hits[0].confidence == 75
    assert hits[0].severity.value == "HIGH"


def test_requirements_undeterminable_version_fires_low_only(tmp_path):
    # No version specifier at all for a package with a curated advisory.
    path = _write(tmp_path, "requirements.txt", "pyyaml\n")
    findings = _scan_requirements_txt_file(path)
    hits = [f for f in findings if f.rule_id == "static.dependency-known-vulnerable"]
    assert len(hits) == 1
    assert hits[0].severity.value == "LOW"
    assert "could not be determined" in hits[0].description.lower()


def test_package_json_range_above_fixed_version_does_not_fire(tmp_path):
    path = _write(tmp_path, "package.json", '{"dependencies": {"axios": "^0.22.0"}}')
    findings = _scan_package_json_file(path)
    assert "static.dependency-known-vulnerable" not in _rule_ids(findings)


def test_package_json_exact_vulnerable_pin_fires_confirmed(tmp_path):
    path = _write(tmp_path, "package.json", '{"dependencies": {"minimist": "1.2.3"}}')
    findings = _scan_package_json_file(path)
    hits = [f for f in findings if f.rule_id == "static.dependency-known-vulnerable"]
    assert len(hits) == 1
    assert hits[0].confidence == 70
    assert hits[0].severity.value == "HIGH"


def test_package_json_range_permitting_vulnerable_version_fires_low(tmp_path):
    # Same idiom as the pip case: "^"/">=" only establishes a lower bound,
    # npm resolves to the newest version the range permits, so this must not
    # carry the same severity as a confirmed (exact-pin) hit.
    path = _write(tmp_path, "package.json", '{"dependencies": {"minimist": ">=1.0.0"}}')
    findings = _scan_package_json_file(path)
    hits = [f for f in findings if f.rule_id == "static.dependency-known-vulnerable"]
    assert len(hits) == 1
    assert "permit" in hits[0].description.lower()
    assert hits[0].severity.value == "LOW"
    assert hits[0].confidence < 70


# --- FIX 2: dependency-weak-constraint must not contradict its own snippet --


def test_unbounded_weak_constraint_still_fires(tmp_path):
    path = _write(tmp_path, "requirements.txt", "somepkg>=2.0.0\n")
    findings = _scan_requirements_txt_file(path)
    assert "static.dependency-weak-constraint" in _rule_ids(findings)


def test_bounded_range_does_not_fire_weak_constraint(tmp_path):
    # The exact case from the bug report: the snippet clearly shows an upper
    # bound, so claiming "no ... upper-bounded pin" is a contradiction.
    path = _write(tmp_path, "requirements.txt", "mcp[cli]>=2.0.0,<3.0.0\n")
    findings = _scan_requirements_txt_file(path)
    assert "static.dependency-weak-constraint" not in _rule_ids(findings)


def test_upper_bound_only_still_fires_weak_constraint(tmp_path):
    # Unbounded BELOW is just as much an unpinned-range problem; must not be
    # mistaken for a "bounded range" just because some upper-bound operator
    # is present.
    path = _write(tmp_path, "requirements.txt", "somepkg<1.20\n")
    findings = _scan_requirements_txt_file(path)
    assert "static.dependency-weak-constraint" in _rule_ids(findings)


# --- FIX 3: open() mode awareness in the path-traversal rule -----------------


def test_open_write_mode_is_not_reported_as_arbitrary_read(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def save(path, data):\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(data)\n"
    ))
    findings = scan_python_file(path)
    hits = [f for f in findings if f.rule_id == "static.path-traversal-open-param"]
    assert len(hits) == 1
    assert hits[0].severity.value == "LOW"
    assert "read" not in hits[0].description.lower().split("write")[0]  # no leftover "reading" claim
    assert "writ" in hits[0].description.lower()


def test_open_read_mode_still_reported_as_arbitrary_read(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def load(path):\n"
        "    with open(path, 'r') as f:\n"
        "        return f.read()\n"
    ))
    findings = scan_python_file(path)
    hits = [f for f in findings if f.rule_id == "static.path-traversal-open-param"]
    assert len(hits) == 1
    assert hits[0].severity.value == "MEDIUM"
    assert "reading arbitrary files" in hits[0].description.lower()


def test_open_no_mode_defaults_to_read_behaviour(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def load(path):\n"
        "    with open(path) as f:\n"
        "        return f.read()\n"
    ))
    findings = scan_python_file(path)
    hits = [f for f in findings if f.rule_id == "static.path-traversal-open-param"]
    assert len(hits) == 1
    assert hits[0].severity.value == "MEDIUM"


def test_open_variable_mode_keeps_current_behaviour(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def load(path, mode):\n"
        "    with open(path, mode) as f:\n"
        "        return f.read()\n"
    ))
    findings = scan_python_file(path)
    hits = [f for f in findings if f.rule_id == "static.path-traversal-open-param"]
    assert len(hits) == 1
    assert hits[0].severity.value == "MEDIUM"


# --- FIX 4: inline `# trustmcp: ignore` suppression comments ----------------


def test_suppression_blanket_ignore_on_same_line(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def run(cmd):\n"
        "    os.system(cmd)  # trustmcp: ignore\n"
    ))
    findings = scan_python_file(path)
    assert findings == []


def test_suppression_specific_rule_on_line_above(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def run(cmd):\n"
        "    # trustmcp: ignore[static.os-system]\n"
        "    os.system(cmd)\n"
    ))
    findings = scan_python_file(path)
    assert findings == []


def test_suppression_specific_rule_does_not_suppress_other_rules(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def run(cmd):\n"
        "    os.system(cmd)  # trustmcp: ignore[static.dangerous-eval-exec]\n"
    ))
    findings = scan_python_file(path)
    # os-system fired the finding, but the directive names a different rule.
    assert "static.os-system" in _rule_ids(findings)


def test_no_suppression_comment_still_fires(tmp_path):
    path = _write(tmp_path, "server.py", (
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    ))
    findings = scan_python_file(path)
    assert "static.os-system" in _rule_ids(findings)


def test_suppression_works_on_requirements_txt(tmp_path):
    path = _write(tmp_path, "requirements.txt", "django==3.2.10  # trustmcp: ignore[static.dependency-known-vulnerable]\n")
    findings = _scan_requirements_txt_file(path)
    assert "static.dependency-known-vulnerable" not in _rule_ids(findings)


def test_suppression_works_on_package_json_and_preserves_valid_json(tmp_path):
    content = (
        '{\n'
        '  "dependencies": {\n'
        '    "minimist": "1.2.3"  # trustmcp: ignore[static.dependency-known-vulnerable]\n'
        '  }\n'
        '}\n'
    )
    path = _write(tmp_path, "package.json", content)
    findings = _scan_package_json_file(path)
    assert "static.package-json-invalid" not in _rule_ids(findings)
    assert "static.dependency-known-vulnerable" not in _rule_ids(findings)


def test_text_safety_own_pattern_is_suppressed_when_scanned_as_a_copy():
    """
    core/text_safety.py's HIDDEN_UNICODE_PATTERN literally contains the
    characters it detects. scan_directory() normally excludes the running
    package, but a separate working-tree copy (e.g. trustmcp installed
    elsewhere scanning this repo) would hit this file directly — the inline
    suppression comments on the pattern are what keep that scan clean.
    """
    text_safety_path = os.path.join(
        os.path.dirname(__file__), "..", "trustmcp", "core", "text_safety.py"
    )
    findings = scan_python_file(text_safety_path)
    assert "static.hidden-unicode" not in _rule_ids(findings)
