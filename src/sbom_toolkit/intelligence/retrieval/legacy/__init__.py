"""
Legacy retrieval systems for SBOM toolkit.

.. deprecated::
    This module contains older retrieval approaches that are maintained for
    comparison purposes only. Use the MCP system in
    ``sbom_toolkit.intelligence.retrieval.mcp_system_refactored`` for new code.
"""

import warnings

from .rag import RAGSystem

warnings.warn(
    "sbom_toolkit.intelligence.retrieval.legacy is deprecated. "
    "Use the MCP system (mcp_system_refactored) for new development.",
    DeprecationWarning,
    stacklevel=2,
)


__all__ = ["RAGSystem"]
