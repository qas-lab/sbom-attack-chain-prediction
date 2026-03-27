"""
SBOM Toolkit - A comprehensive toolkit for Software Bill of Materials operations.

This toolkit provides functionality for:
- SBOM generation from various package managers and repositories
- Vulnerability scanning and security analysis
- Knowledge graph building and AI-powered analysis
- Interactive visualization of SBOM data
- Machine learning for vulnerability prediction
"""

from typing import Any

__version__ = "0.1.0"

# Weakly import foundational modules to avoid forcing optional dependencies at
# package import time. Downstream code can import submodules directly if needed.

# These are typed as Any to avoid complex conditional type handling
SBOMToolkitError: Any = None
ProcessingConfig: Any = None
RepositoryInfo: Any = None
RepositoryMetadata: Any = None
OutputManager: Any = None
output_manager: Any = None
SBOMProcessor: Any = None
SBOMFilterProcessor: Any = None
VulnerabilityProcessor: Any = None

try:
    from .shared.exceptions import SBOMToolkitError
except Exception:  # pragma: no cover - optional import guard
    pass

try:
    from .shared.models import ProcessingConfig, RepositoryInfo, RepositoryMetadata
except Exception:  # pragma: no cover - optional import guard
    pass

try:
    from .shared.output import OutputManager, output_manager
except Exception:  # pragma: no cover - optional import guard
    pass

# Pipeline operations depend on optional third-party libraries (e.g., requests,
# git). Import them lazily and tolerate environments focused only on ML eval.
try:
    from .pipeline import SBOMFilterProcessor, SBOMProcessor, VulnerabilityProcessor
except Exception:  # pragma: no cover - optional import guard
    pass

__all__: list[str] = []

if ProcessingConfig is not None:
    __all__.append("ProcessingConfig")
if RepositoryInfo is not None:
    __all__.append("RepositoryInfo")
if RepositoryMetadata is not None:
    __all__.append("RepositoryMetadata")
if SBOMToolkitError is not None:
    __all__.append("SBOMToolkitError")
if SBOMProcessor is not None:
    __all__.append("SBOMProcessor")
if SBOMFilterProcessor is not None:
    __all__.append("SBOMFilterProcessor")
if VulnerabilityProcessor is not None:
    __all__.append("VulnerabilityProcessor")
if OutputManager is not None:
    __all__.append("OutputManager")
if output_manager is not None:
    __all__.append("output_manager")
