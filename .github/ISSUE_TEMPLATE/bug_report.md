---
name: Bug report
about: Report incorrect, missing, or crashing behavior in trustmcp
title: ""
labels: bug
assignees: ""
---

**Describe the bug**
A clear description of what's wrong — a false positive, a missed detection, a crash,
incorrect SARIF/JSON output, etc.

**Command run**

```
trustmcp scan --path ... --mode ... --sarif-output ...
```

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened. Include the full terminal output if relevant, and the
generated SARIF/JSON snippet if the bug is about a specific finding.

**Environment**
- trustmcp version: (`trustmcp --version` or `pip show trustmcp`)
- Python version:
- OS:
- Installed via: (pip / uvx / GitHub Action / source checkout)

**Target being scanned**
If possible, a minimal code snippet or a link to a public repo that reproduces the
issue. If the target is private or sensitive, describe the shape of the code that
triggers it instead of pasting it.

**Additional context**
Anything else relevant — e.g. whether this is a false positive/negative against a
specific rule ID (`static.*` / `dynamic.*` / `auth.*`).
