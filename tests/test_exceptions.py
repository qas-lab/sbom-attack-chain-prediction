"""
Tests for custom exception hierarchy.
"""

import pytest

from sbom_toolkit.shared.exceptions import (
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


class TestSBOMToolkitError:
    """Tests for base exception class."""

    def test_basic_creation(self) -> None:
        """Test creating exception with just a message."""
        error = SBOMToolkitError("Test error message")
        assert error.message == "Test error message"
        assert error.context == {}
        assert str(error) == "Test error message"

    def test_creation_with_context(self) -> None:
        """Test creating exception with context."""
        context = {"file": "test.json", "line": 42}
        error = SBOMToolkitError("Test error", context=context)
        assert error.context == context
        assert "file=test.json" in str(error)
        assert "line=42" in str(error)

    def test_str_representation(self) -> None:
        """Test string representation includes context."""
        error = SBOMToolkitError("Error", context={"key": "value"})
        result = str(error)
        assert "Error" in result
        assert "(Context:" in result
        assert "key=value" in result


class TestRepositoryExceptions:
    """Tests for repository-related exceptions."""

    def test_repository_error_inheritance(self) -> None:
        """Test RepositoryError inherits from SBOMToolkitError."""
        error = RepositoryError("Repo error")
        assert isinstance(error, SBOMToolkitError)

    def test_repository_clone_error(self) -> None:
        """Test RepositoryCloneError."""
        error = RepositoryCloneError("Failed to clone", context={"url": "https://github.com/test"})
        assert isinstance(error, RepositoryError)
        assert "Failed to clone" in str(error)

    def test_repository_not_found_error(self) -> None:
        """Test RepositoryNotFoundError."""
        error = RepositoryNotFoundError("Repository not found")
        assert isinstance(error, RepositoryError)

    def test_invalid_repository_url_error(self) -> None:
        """Test InvalidRepositoryURLError."""
        error = InvalidRepositoryURLError("Invalid URL format")
        assert isinstance(error, RepositoryError)


class TestSBOMExceptions:
    """Tests for SBOM-related exceptions."""

    def test_sbom_error_inheritance(self) -> None:
        """Test SBOMError inherits from SBOMToolkitError."""
        error = SBOMError("SBOM error")
        assert isinstance(error, SBOMToolkitError)

    def test_sbom_generation_error(self) -> None:
        """Test SBOMGenerationError."""
        error = SBOMGenerationError("Generation failed", context={"generator": "syft"})
        assert isinstance(error, SBOMError)
        assert "generator=syft" in str(error)


class TestVulnerabilityExceptions:
    """Tests for vulnerability-related exceptions."""

    def test_vulnerability_error_inheritance(self) -> None:
        """Test VulnerabilityError inherits from SBOMToolkitError."""
        error = VulnerabilityError("Vulnerability error")
        assert isinstance(error, SBOMToolkitError)

    def test_vulnerability_scan_error(self) -> None:
        """Test VulnerabilityScanError."""
        error = VulnerabilityScanError("Scan failed", context={"scanner": "grype"})
        assert isinstance(error, VulnerabilityError)
        assert "scanner=grype" in str(error)


class TestProcessingError:
    """Tests for ProcessingError."""

    def test_processing_error(self) -> None:
        """Test ProcessingError creation."""
        error = ProcessingError("Processing failed")
        assert isinstance(error, SBOMToolkitError)


class TestWrapExternalError:
    """Tests for wrap_external_error utility."""

    def test_wrap_file_not_found_error(self) -> None:
        """Test wrapping FileNotFoundError."""
        original = FileNotFoundError("file.txt not found")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, SBOMToolkitError)
        assert "File not found" in str(wrapped)
        assert wrapped.context["original_error"] == "FileNotFoundError"

    def test_wrap_file_not_found_repository(self) -> None:
        """Test wrapping FileNotFoundError with 'repository' in message."""
        original = FileNotFoundError("repository not found")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, RepositoryNotFoundError)

    def test_wrap_permission_error(self) -> None:
        """Test wrapping PermissionError."""
        original = PermissionError("Access denied")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, SBOMToolkitError)
        assert "Permission denied" in str(wrapped)

    def test_wrap_timeout_error(self) -> None:
        """Test wrapping TimeoutError."""
        original = TimeoutError("Operation timed out")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, ProcessingError)

    def test_wrap_connection_error(self) -> None:
        """Test wrapping ConnectionError."""
        original = ConnectionError("Connection refused")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, VulnerabilityError)
        assert "Network connection error" in str(wrapped)

    def test_wrap_value_error(self) -> None:
        """Test wrapping ValueError."""
        original = ValueError("Invalid value")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, SBOMToolkitError)
        assert "Data validation error" in str(wrapped)

    def test_wrap_type_error(self) -> None:
        """Test wrapping TypeError."""
        original = TypeError("Wrong type")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, SBOMToolkitError)
        assert "Data validation error" in str(wrapped)

    def test_wrap_unknown_error(self) -> None:
        """Test wrapping unknown error type."""
        original = RuntimeError("Unknown error")
        wrapped = wrap_external_error(original)
        assert isinstance(wrapped, SBOMToolkitError)
        assert "Unexpected error" in str(wrapped)

    def test_wrap_with_context(self) -> None:
        """Test wrapping error with additional context."""
        original = ValueError("Bad value")
        context = {"field": "name", "value": None}
        wrapped = wrap_external_error(original, context=context)
        assert wrapped.context["field"] == "name"
        assert wrapped.context["value"] is None
        assert wrapped.context["original_error"] == "ValueError"


class TestCreateErrorContext:
    """Tests for create_error_context utility."""

    def test_empty_context(self) -> None:
        """Test creating empty context."""
        context = create_error_context()
        assert context == {}

    def test_with_values(self) -> None:
        """Test creating context with values."""
        context = create_error_context(file="test.json", line=42, column=10)
        assert context["file"] == "test.json"
        assert context["line"] == 42
        assert context["column"] == 10

    def test_filters_none_values(self) -> None:
        """Test that None values are filtered out."""
        context = create_error_context(file="test.json", line=None, column=10)
        assert "file" in context
        assert "line" not in context
        assert "column" in context


class TestExceptionHierarchy:
    """Tests for exception hierarchy relationships."""

    def test_all_inherit_from_base(self) -> None:
        """Test all exceptions inherit from SBOMToolkitError."""
        exceptions = [
            RepositoryError("test"),
            RepositoryCloneError("test"),
            RepositoryNotFoundError("test"),
            InvalidRepositoryURLError("test"),
            SBOMError("test"),
            SBOMGenerationError("test"),
            VulnerabilityError("test"),
            VulnerabilityScanError("test"),
            ProcessingError("test"),
        ]
        for exc in exceptions:
            assert isinstance(exc, SBOMToolkitError)
            assert isinstance(exc, Exception)

    def test_can_catch_by_base_class(self) -> None:
        """Test exceptions can be caught by base class."""
        with pytest.raises(SBOMToolkitError):
            raise RepositoryCloneError("Clone failed")

        with pytest.raises(RepositoryError):
            raise RepositoryNotFoundError("Not found")

        with pytest.raises(SBOMError):
            raise SBOMGenerationError("Generation failed")

        with pytest.raises(VulnerabilityError):
            raise VulnerabilityScanError("Scan failed")
