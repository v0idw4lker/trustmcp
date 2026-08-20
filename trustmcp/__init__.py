"""
trustmcp — security scanner for MCP (Model Context Protocol) servers.

Free tier (this package): static (SAST) analysis, live dynamic analysis,
authentication posture assessment, unified A-F scoring, and CLI/JSON/SARIF
reporting.

Semantic (LLM-based) analysis and cross-server toxic-flow detection are
premium capabilities reserved for the paid SaaS tier. They are not
implemented in this package; core.plugins defines the extension point a
premium module registers against, so the free-tier pipeline can pick them
up automatically if one is installed locally.
"""

__version__ = "0.1.0"
