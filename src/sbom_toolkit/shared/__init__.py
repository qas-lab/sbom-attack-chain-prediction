"""
Shared module for core functionality.

Contains core models, exceptions, utilities, caching, logging,
and output management functionality shared across the toolkit.
"""

from .caching import CacheManager
from .exceptions import (
    EnvironmentError,
    InvalidRepositoryURLError,
    ProcessingError,
    RepositoryCloneError,
    RepositoryError,
    RepositoryNotFoundError,
    SBOMError,
    SBOMGenerationError,
    SBOMToolkitError,
    VulnerabilityError,
    VulnerabilityScanError,
    create_error_context,
    wrap_external_error,
)
from .logging import get_logger, setup_logging
from .models import (
    ComponentModel,
    ProcessingConfig,
    RepositoryInfo,
    RepositoryMetadata,
    SBOMModel,
    SeverityLevel,
    VulnerabilityModel,
)
from .output import OutputManager, output_manager
from .version import detect_python_version

__all__ = [
    # Core models
    "RepositoryMetadata",
    "RepositoryInfo",
    "VulnerabilityModel",
    "ComponentModel",
    "SBOMModel",
    "ProcessingConfig",
    "SeverityLevel",
    # Core exceptions
    "SBOMToolkitError",
    "RepositoryError",
    "RepositoryCloneError",
    "RepositoryNotFoundError",
    "InvalidRepositoryURLError",
    "EnvironmentError",
    "SBOMError",
    "SBOMGenerationError",
    "VulnerabilityError",
    "VulnerabilityScanError",
    "ProcessingError",
    "wrap_external_error",
    "create_error_context",
    # Management
    "OutputManager",
    "output_manager",
    # Utils
    "CacheManager",
    "setup_logging",
    "get_logger",
    "detect_python_version",
]
