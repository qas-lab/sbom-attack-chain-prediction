"""
Custom exception hierarchy for SBOM toolkit.
"""

from typing import Any


class SBOMToolkitError(Exception):
    """Base exception for all SBOM toolkit errors."""

    def __init__(self, message: str, context: dict[str, Any] | None = None):
        """Initialize with message and optional context.

        Args:
            message: Error message
            context: Additional context information
        """
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def __str__(self) -> str:
        """String representation with context."""
        if self.context:
            context_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{self.message} (Context: {context_str})"
        return self.message


# Repository-related exceptions
class RepositoryError(SBOMToolkitError):
    """Base exception for repository operations."""

    pass


class RepositoryCloneError(RepositoryError):
    """Error occurred during repository cloning."""

    pass


class RepositoryNotFoundError(RepositoryError):
    """Repository not found or inaccessible."""

    pass


class InvalidRepositoryURLError(RepositoryError):
    """Invalid repository URL format."""

    pass


# Environment-related exceptions
class EnvironmentError(SBOMToolkitError):
    """Base exception for environment management."""

    pass


# SBOM-related exceptions
class SBOMError(SBOMToolkitError):
    """Base exception for SBOM operations."""

    pass


class SBOMGenerationError(SBOMError):
    """Error occurred during SBOM generation."""

    pass


# Vulnerability scanning exceptions
class VulnerabilityError(SBOMToolkitError):
    """Base exception for vulnerability operations."""

    pass


class VulnerabilityScanError(VulnerabilityError):
    """Error occurred during vulnerability scanning."""

    pass


# Processing exceptions
class ProcessingError(SBOMToolkitError):
    """Base exception for processing operations."""

    pass


# Utility functions for error handling
def wrap_external_error(
    error: Exception, context: dict[str, Any] | None = None
) -> SBOMToolkitError:
    """Wrap external exceptions in our custom exception hierarchy.

    Args:
        error: External exception to wrap
        context: Additional context information

    Returns:
        Appropriate SBOMToolkitError subclass
    """
    error_message = str(error)
    error_context = context or {}
    error_context["original_error"] = type(error).__name__

    # Map common external errors to our hierarchy
    if isinstance(error, FileNotFoundError):
        if "repository" in error_message.lower():
            return RepositoryNotFoundError(error_message, error_context)
        return SBOMToolkitError(f"File not found: {error_message}", error_context)

    elif isinstance(error, PermissionError):
        return SBOMToolkitError(f"Permission denied: {error_message}", error_context)

    elif isinstance(error, TimeoutError):
        return ProcessingError(f"Operation timed out: {error_message}", error_context)

    elif isinstance(error, ConnectionError):
        return VulnerabilityError(f"Network connection error: {error_message}", error_context)

    elif isinstance(error, ValueError | TypeError):
        return SBOMToolkitError(f"Data validation error: {error_message}", error_context)

    else:
        # Generic wrapper for unknown errors
        return SBOMToolkitError(f"Unexpected error: {error_message}", error_context)


def create_error_context(**kwargs) -> dict[str, Any]:
    """Create error context dictionary with standardized keys.

    Args:
        **kwargs: Context key-value pairs

    Returns:
        Context dictionary
    """
    context = {}

    for key, value in kwargs.items():
        if value is not None:
            context[key] = value

    return context
