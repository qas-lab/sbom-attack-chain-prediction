"""
SBOM Visualization Module

This module provides unified interactive visualization capabilities for Software Bill of Materials (SBOM)
data with multiple layout types, ML prediction integration, and a modern interface with sidebar controls.

Features:
- Force-directed and hierarchical graph layouts
- HGAT vulnerability predictions integration
- MLP cascade (attack chain) predictions integration
- Interactive node details with ML prediction display
- Clickable nodes for component information
"""

# Unified visualization system
# Core components
from .core import (
    PredictionLoader,
    SBOMDataTransformer,
    UnifiedVisualizer,
    load_predictions_for_visualization,
)
from .engines import ForceDirectedEngine, HierarchicalEngine
from .unified import (
    create_d3_visualization,  # Backward compatibility
    create_unified_visualization,
    get_available_layouts,
    validate_sbom_file,
)

__all__ = [
    # Primary unified interface
    "create_unified_visualization",
    "get_available_layouts",
    "validate_sbom_file",
    # Core components
    "UnifiedVisualizer",
    "SBOMDataTransformer",
    "PredictionLoader",
    "load_predictions_for_visualization",
    # Engines
    "ForceDirectedEngine",
    "HierarchicalEngine",
    # Backward compatibility
    "create_d3_visualization",
]
