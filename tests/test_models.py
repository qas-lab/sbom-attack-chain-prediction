"""
Tests for shared data models.
"""

from datetime import datetime
from pathlib import Path

from sbom_toolkit.shared.models import (
    ComponentModel,
    PerformanceComparison,
    ProcessingConfig,
    RepositoryInfo,
    RepositoryMetadata,
    RepositoryOptimizationLevel,
    SBOMModel,
    SeverityLevel,
    TestCase,
    TestResult,
    VulnerabilityModel,
)


class TestSeverityLevel:
    """Tests for SeverityLevel enum."""

    def test_severity_values(self) -> None:
        """Test that all severity levels are defined."""
        assert SeverityLevel.NONE == "NONE"
        assert SeverityLevel.LOW == "LOW"
        assert SeverityLevel.MEDIUM == "MEDIUM"
        assert SeverityLevel.HIGH == "HIGH"
        assert SeverityLevel.CRITICAL == "CRITICAL"

    def test_severity_is_string_enum(self) -> None:
        """Test that severity levels can be used as strings."""
        severity = SeverityLevel.HIGH
        assert isinstance(severity, str)
        assert severity == "HIGH"


class TestRepositoryOptimizationLevel:
    """Tests for RepositoryOptimizationLevel enum."""

    def test_optimization_levels(self) -> None:
        """Test all optimization levels are defined."""
        assert RepositoryOptimizationLevel.BALANCED == "balanced"
        assert RepositoryOptimizationLevel.FASTEST == "fastest"
        assert RepositoryOptimizationLevel.MINIMAL == "minimal"
        assert RepositoryOptimizationLevel.COMPLETE == "complete"


class TestRepositoryMetadata:
    """Tests for RepositoryMetadata dataclass."""

    def test_minimal_creation(self) -> None:
        """Test creating metadata with minimal required fields."""
        metadata = RepositoryMetadata(
            url="https://github.com/owner/repo",
            owner="owner",
            name="repo",
        )
        assert metadata.url == "https://github.com/owner/repo"
        assert metadata.owner == "owner"
        assert metadata.name == "repo"
        assert metadata.branch == "main"
        assert metadata.commit_hash is None
        assert metadata.latest_tag is None
        assert metadata.acquired_at is None

    def test_full_creation(self) -> None:
        """Test creating metadata with all fields."""
        now = datetime.now()
        metadata = RepositoryMetadata(
            url="https://github.com/owner/repo",
            owner="owner",
            name="repo",
            branch="develop",
            commit_hash="abc123",
            latest_tag="v1.0.0",
            acquired_at=now,
        )
        assert metadata.branch == "develop"
        assert metadata.commit_hash == "abc123"
        assert metadata.latest_tag == "v1.0.0"
        assert metadata.acquired_at == now


class TestRepositoryInfo:
    """Tests for RepositoryInfo dataclass."""

    def test_creation(self) -> None:
        """Test creating repository info."""
        metadata = RepositoryMetadata(
            url="https://github.com/owner/repo",
            owner="owner",
            name="repo",
        )
        info = RepositoryInfo(
            path=Path("/tmp/repo"),
            metadata=metadata,
        )
        assert info.path == Path("/tmp/repo")
        assert info.metadata == metadata
        assert info.method == "full_clone"

    def test_custom_method(self) -> None:
        """Test repository info with custom acquisition method."""
        metadata = RepositoryMetadata(
            url="https://github.com/owner/repo",
            owner="owner",
            name="repo",
        )
        info = RepositoryInfo(
            path=Path("/tmp/repo"),
            metadata=metadata,
            method="tarball",
        )
        assert info.method == "tarball"


class TestProcessingConfig:
    """Tests for ProcessingConfig dataclass."""

    def test_minimal_creation(self) -> None:
        """Test creating config with minimal required fields."""
        config = ProcessingConfig(output_dir=Path("/tmp/output"))
        assert config.output_dir == Path("/tmp/output")
        assert config.cache_enabled is True
        assert config.max_retries == 3
        assert config.timeout_seconds == 300

    def test_default_optimization_level(self) -> None:
        """Test default repository optimization level."""
        config = ProcessingConfig(output_dir=Path("/tmp/output"))
        assert config.repo_optimization_level == RepositoryOptimizationLevel.BALANCED

    def test_custom_settings(self) -> None:
        """Test creating config with custom settings."""
        config = ProcessingConfig(
            output_dir=Path("/tmp/output"),
            cache_enabled=False,
            max_retries=5,
            timeout_seconds=600,
            repo_optimization_level=RepositoryOptimizationLevel.FASTEST,
            parallel_downloads=True,
        )
        assert config.cache_enabled is False
        assert config.max_retries == 5
        assert config.timeout_seconds == 600
        assert config.repo_optimization_level == RepositoryOptimizationLevel.FASTEST
        assert config.parallel_downloads is True


class TestVulnerabilityModel:
    """Tests for VulnerabilityModel dataclass."""

    def test_minimal_creation(self) -> None:
        """Test creating vulnerability with minimal fields."""
        vuln = VulnerabilityModel(id="VULN-001")
        assert vuln.id == "VULN-001"
        assert vuln.cve_id is None
        assert vuln.summary == ""
        assert vuln.severity is None
        assert vuln.cvss_score is None
        assert vuln.references == []
        assert vuln.aliases == []

    def test_full_creation(self) -> None:
        """Test creating vulnerability with all fields."""
        vuln = VulnerabilityModel(
            id="VULN-001",
            cve_id="CVE-2023-12345",
            summary="Test vulnerability",
            description="A detailed description",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            cvss_version="3.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_severity="HIGH",
            published_date="2023-01-15",
            references=["https://example.com"],
            aliases=["GHSA-xxxx"],
        )
        assert vuln.cve_id == "CVE-2023-12345"
        assert vuln.severity == SeverityLevel.HIGH
        assert vuln.cvss_score == 7.5
        assert vuln.cvss_version == "3.1"
        assert len(vuln.references) == 1
        assert len(vuln.aliases) == 1


class TestComponentModel:
    """Tests for ComponentModel dataclass."""

    def test_minimal_creation(self) -> None:
        """Test creating component with minimal fields."""
        comp = ComponentModel()
        assert comp.bom_ref is None
        assert comp.name == ""
        assert comp.version is None
        assert comp.type == "library"
        assert comp.licenses == []
        assert comp.vulnerabilities == []

    def test_full_creation(self) -> None:
        """Test creating component with all fields."""
        vuln = VulnerabilityModel(id="VULN-001")
        comp = ComponentModel(
            bom_ref="pkg:pypi/requests@2.31.0",
            name="requests",
            version="2.31.0",
            purl="pkg:pypi/requests@2.31.0",
            type="library",
            licenses=[{"license": {"id": "Apache-2.0"}}],
            vulnerabilities=[vuln],
        )
        assert comp.name == "requests"
        assert comp.version == "2.31.0"
        assert len(comp.vulnerabilities) == 1


class TestSBOMModel:
    """Tests for SBOMModel dataclass."""

    def test_default_creation(self) -> None:
        """Test creating SBOM with defaults."""
        sbom = SBOMModel()
        assert sbom.bomFormat == "CycloneDX"
        assert sbom.specVersion == "1.4"
        assert sbom.version == 1
        assert sbom.components == []
        assert sbom.metadata == {}

    def test_with_components(self) -> None:
        """Test creating SBOM with components."""
        comp = ComponentModel(name="test", version="1.0.0")
        sbom = SBOMModel(
            serialNumber="urn:uuid:test-1234",
            components=[comp],
            metadata={"timestamp": "2024-01-01T00:00:00Z"},
        )
        assert sbom.serialNumber == "urn:uuid:test-1234"
        assert len(sbom.components) == 1
        assert sbom.components[0].name == "test"


class TestTestCase:
    """Tests for TestCase dataclass."""

    def test_minimal_creation(self) -> None:
        """Test creating test case with minimal fields."""
        tc = TestCase(question="What vulnerabilities exist?")
        assert tc.question == "What vulnerabilities exist?"
        assert tc.category == "general"
        assert tc.difficulty == "medium"
        assert tc.expected_cve_ids == []

    def test_full_creation(self) -> None:
        """Test creating test case with all fields."""
        tc = TestCase(
            question="What vulnerabilities exist in requests?",
            category="vulnerability_analysis",
            difficulty="hard",
            id="TC-001",
            context="Analyzing Python dependencies",
            expected_cve_ids=["CVE-2023-12345"],
            expected_cwe_ids=["CWE-79"],
            expected_component_names=["requests"],
        )
        assert tc.category == "vulnerability_analysis"
        assert tc.difficulty == "hard"
        assert len(tc.expected_cve_ids) == 1


class TestTestResult:
    """Tests for TestResult dataclass."""

    def test_creation(self) -> None:
        """Test creating test result."""
        tc = TestCase(question="Test question")
        result = TestResult(
            test_case=tc,
            system_name="test_system",
            response="Test response",
            response_time=1.5,
            tokens_used=100,
        )
        assert result.test_case == tc
        assert result.system_name == "test_system"
        assert result.response_time == 1.5
        assert result.tokens_used == 100
        assert result.precision == 0.0
        assert result.recall == 0.0
        assert result.f1_score == 0.0
        assert result.passed is False


class TestPerformanceComparison:
    """Tests for PerformanceComparison dataclass."""

    def test_creation(self) -> None:
        """Test creating performance comparison."""
        comparison = PerformanceComparison(
            test_session_id="session-001",
            timestamp="2024-01-01T00:00:00Z",
            repository_url="https://github.com/test/repo",
            total_test_cases=10,
            kg_enhanced_results=[],
            legacy_rag_results=[],
            standalone_results=[],
        )
        assert comparison.test_session_id == "session-001"
        assert comparison.total_test_cases == 10
        assert comparison.summary_stats == {}
        assert comparison.test_metadata == {}
