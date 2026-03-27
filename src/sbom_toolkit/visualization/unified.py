"""
Unified visualization entry point for SBOM toolkit.

This module provides the main entry point for creating unified SBOM visualizations
that combine multiple layout types in a single interactive interface.
"""

import logging
from pathlib import Path
from typing import Any

from .core.unified_visualizer import UnifiedVisualizer


def create_unified_visualization(
    sbom_path: str | Path,
    output_path: str | Path,
    layout_types: list[str] | None = None,
    gnn_predictions: dict[str, Any] | None = None,
) -> Path:
    """Create unified SBOM visualization with multiple layout options.

    This is the main entry point for creating unified visualizations that replace
    the legacy separate visualization functions.

    Args:
        sbom_path: Path to SBOM JSON file
        output_path: Output HTML file path
        layout_types: List of layout types to include (default: all available)
        gnn_predictions: Optional GNN predictions data

    Returns:
        Path to generated HTML file

    Raises:
        ValueError: If SBOM file is invalid or layout types are invalid
        RuntimeError: If visualization generation fails

    Example:
        >>> from sbom_toolkit.visualization import create_unified_visualization
        >>> html_path = create_unified_visualization(
        ...     sbom_path="my_sbom.json",
        ...     output_path="visualization.html",
        ...     layout_types=["force-directed", "hierarchical"]
        ... )
        >>> print(f"Visualization created: {html_path}")
    """
    # Convert to Path objects
    sbom_path = Path(sbom_path)
    output_path = Path(output_path)

    # Validate SBOM file exists
    if not sbom_path.exists():
        raise ValueError(f"SBOM file not found: {sbom_path}")

    # Create visualizer and generate
    visualizer = UnifiedVisualizer()

    # Validate SBOM file
    if not visualizer.validate_sbom_file(sbom_path):
        raise ValueError(f"Invalid SBOM file: {sbom_path}")

    # Create visualization
    return visualizer.create_visualization(
        sbom_path=sbom_path,
        output_path=output_path,
        layout_types=layout_types,
        gnn_predictions=gnn_predictions,
    )


def get_available_layouts() -> list[str]:
    """Get list of available visualization layout types.

    Returns:
        List of layout type names
    """
    visualizer = UnifiedVisualizer()
    return visualizer.get_available_layouts()


def validate_sbom_file(sbom_path: str | Path) -> bool:
    """Validate that an SBOM file is compatible with visualization.

    Args:
        sbom_path: Path to SBOM JSON file

    Returns:
        True if valid, False otherwise
    """
    visualizer = UnifiedVisualizer()
    return visualizer.validate_sbom_file(Path(sbom_path))


# Backward compatibility functions
def create_d3_visualization(
    sbom_path: Path,
    output_path: Path,
    layout_type: str = "force-directed",
    gnn_predictions: dict[str, Any] | None = None,
) -> Path:
    """Create D3.js SBOM visualization (updated for OutputManager compatibility).

    This function maintains backward compatibility with the CLI interface
    while using the new unified visualization system.

    Args:
        sbom_path: Path to SBOM JSON file
        output_path: Output path for HTML file
        layout_type: Layout type (force-directed, hierarchical, circular)
        gnn_predictions: Optional GNN predictions

    Returns:
        Path to generated HTML file
    """
    logger = logging.getLogger(__name__)
    logger.info("Creating visualization using unified system (organized output mode)")

    # Map old layout names to new names
    layout_mapping = {
        "force-directed": "force-directed",
        "hierarchical": "hierarchical",
        "circular": "circular",
    }

    mapped_layout = layout_mapping.get(layout_type, layout_type)

    # Create unified visualization with single layout
    return create_unified_visualization(
        sbom_path=sbom_path,
        output_path=output_path,
        layout_types=[mapped_layout],
        gnn_predictions=gnn_predictions,
    )


# Export main functions
__all__ = [
    "create_unified_visualization",
    "get_available_layouts",
    "validate_sbom_file",
    "create_d3_visualization",  # For backward compatibility
]
