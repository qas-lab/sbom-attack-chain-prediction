"""
Core data models for SBOM toolkit using simple dataclasses.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class SeverityLevel(str, Enum):
    """CVSS severity levels."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RepositoryOptimizationLevel(str, Enum):
    """Repository optimization levels."""

    BALANCED = "balanced"  # Shallow clone with caching
    FASTEST = "fastest"  # Tarball download, minimal caching
    MINIMAL = "minimal"  # Sparse checkout, aggressive caching
    COMPLETE = "complete"  # Full clone, no optimizations


@dataclass
class RepositoryMetadata:
    """Metadata about a repository."""

    url: str
    owner: str
    name: str
    branch: str = "main"
    commit_hash: str | None = None
    latest_tag: str | None = None
    acquired_at: datetime | None = None


@dataclass
class RepositoryInfo:
    """Information about a repository acquisition."""

    path: Path
    metadata: RepositoryMetadata
    method: str = "full_clone"


@dataclass
class ProcessingConfig:
    """Configuration for SBOM processing."""

    output_dir: Path
    cache_enabled: bool = True
    max_retries: int = 3
    timeout_seconds: int = 300
    conda_env_prefix: str = "sbom_"
    temp_dir_prefix: str = "sbomgen-temp-"

    # Repository optimization settings
    repo_cache_enabled: bool = True
    repo_optimization_level: RepositoryOptimizationLevel = RepositoryOptimizationLevel.BALANCED
    max_cached_repos: int = 10  # Maximum number of repos to cache per project
    cache_max_age_hours: int = 24  # Auto-cleanup cache entries older than this

    # Performance settings
    parallel_downloads: bool = False  # Enable parallel repository downloads
    download_timeout_seconds: int = 600  # Timeout for repository downloads


@dataclass
class VulnerabilityModel:
    """Enhanced vulnerability model with version-aware CVSS support."""

    id: str
    cve_id: str | None = None
    summary: str = ""
    description: str = ""
    severity: SeverityLevel | None = None
    cvss_score: float | None = None  # Selected highest version score
    cvss_version: str | None = None  # Version used for score (e.g., "4.0", "3.1")
    cvss_vector: str | None = None  # Vector string for selected version
    cvss_severity: str | None = None  # Severity rating for selected version
    published_date: str | None = None
    modified_date: str | None = None
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    all_cvss_metrics: dict[str, Any] = field(
        default_factory=dict
    )  # All CVSS versions for debugging


@dataclass
class ComponentModel:
    """Simple component model for basic data storage."""

    bom_ref: str | None = None
    name: str = ""
    version: str | None = None
    purl: str | None = None
    type: str = "library"
    licenses: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityModel] = field(default_factory=list)


@dataclass
class SBOMModel:
    """Simple SBOM model for basic data storage."""

    bomFormat: str = "CycloneDX"
    specVersion: str = "1.4"
    serialNumber: str | None = None
    version: int = 1
    components: list[ComponentModel] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestCase:
    """Represents a single test case for the performance comparison."""

    question: str
    category: str = "general"
    difficulty: str = "medium"
    id: str = ""
    context: str = ""
    expected_elements: list[str] = field(default_factory=list)
    repository_context: str = ""
    expected_cve_ids: list[str] = field(default_factory=list)
    expected_cwe_ids: list[str] = field(default_factory=list)
    expected_capec_ids: list[str] = field(default_factory=list)
    expected_component_names: list[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Represents the result of a test case evaluation."""

    test_case: TestCase
    system_name: str
    response: str
    response_time: float
    tokens_used: int
    citation_metrics: dict[str, Any] = field(default_factory=dict)
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0  # F1 score (beta=1.0) for balanced comparison
    f1_5_score: float = 0.0  # F-1.5 score (beta=1.5) for recall-focused evaluation
    passed: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class PerformanceComparison:
    """Complete performance comparison between systems."""

    test_session_id: str
    timestamp: str
    repository_url: str
    total_test_cases: int
    kg_enhanced_results: list[TestResult]  # MCP-enhanced system results
    legacy_rag_results: list[TestResult]  # Legacy RAG system results
    standalone_results: list[TestResult]  # Standalone LLM system results
    summary_stats: dict[str, Any] = field(default_factory=dict)
    test_metadata: dict[str, Any] = field(default_factory=dict)  # Additional test metadata
