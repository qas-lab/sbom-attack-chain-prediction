"""
Stub for GNN prediction functionality.

This module provides a stub implementation for GNN prediction
when the full ML dependencies are not available.
"""

from pathlib import Path
from typing import Any


def predict_sbom(
    sbom_path: str | Path, model_path: str | Path = "best_model.pt"
) -> dict[str, Any] | None:
    """
    Stub function for SBOM prediction using GNN.

    Args:
        sbom_path: Path to the SBOM file
        model_path: Path to the trained model

    Returns:
        None (stub implementation)
    """
    return None
