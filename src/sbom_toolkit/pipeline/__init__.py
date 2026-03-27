"""
Pipeline module for SBOM generation, scanning, and data processing.

Contains SBOM generation, filtering, vulnerability scanning, and infrastructure
components for the data processing pipeline.
"""

from .environment import (
    cleanup_environment,
    get_available_backends,
    install_dependencies,
    setup_environment,
)
from .repository import RepositoryHandler
from .sbom import SBOMFilterProcessor, SBOMProcessor
from .security import VulnerabilityProcessor
from .tools import (
    generate_sbom,
    get_available_sbom_generators,
    get_available_vulnerability_scanners,
    get_best_sbom_generator,
    get_best_vulnerability_scanner,
    scan_for_vulnerabilities,
)

__all__ = [
    # SBOM operations
    "SBOMProcessor",
    "SBOMFilterProcessor",
    # Security operations
    "VulnerabilityProcessor",
    # Repository handling
    "RepositoryHandler",
    # Tools
    "get_available_sbom_generators",
    "get_available_vulnerability_scanners",
    "get_best_sbom_generator",
    "get_best_vulnerability_scanner",
    "generate_sbom",
    "scan_for_vulnerabilities",
    # Environment
    "get_available_backends",
    "setup_environment",
    "install_dependencies",
    "cleanup_environment",
]
