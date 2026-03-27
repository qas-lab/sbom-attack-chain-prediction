"""
Pytest configuration and shared fixtures for SBOM Toolkit tests.
"""

import json
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_sbom_data() -> dict[str, Any]:
    """Return sample SBOM data in CycloneDX format."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:test-1234",
        "version": 1,
        "metadata": {
            "timestamp": "2024-01-01T00:00:00Z",
            "tools": [{"name": "test-tool", "version": "1.0.0"}],
        },
        "components": [
            {
                "bom-ref": "pkg:pypi/requests@2.31.0",
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
            {
                "bom-ref": "pkg:pypi/urllib3@2.0.0",
                "type": "library",
                "name": "urllib3",
                "version": "2.0.0",
                "purl": "pkg:pypi/urllib3@2.0.0",
            },
            {
                "bom-ref": "pkg:pypi/certifi@2023.7.22",
                "type": "library",
                "name": "certifi",
                "version": "2023.7.22",
                "purl": "pkg:pypi/certifi@2023.7.22",
            },
        ],
        "dependencies": [
            {
                "ref": "pkg:pypi/requests@2.31.0",
                "dependsOn": ["pkg:pypi/urllib3@2.0.0", "pkg:pypi/certifi@2023.7.22"],
            }
        ],
    }


@pytest.fixture
def sample_sbom_file(temp_dir: Path, sample_sbom_data: dict[str, Any]) -> Path:
    """Create a sample SBOM file and return its path."""
    sbom_path = temp_dir / "test_sbom.json"
    with open(sbom_path, "w") as f:
        json.dump(sample_sbom_data, f)
    return sbom_path


@pytest.fixture
def sample_enriched_sbom_data() -> dict[str, Any]:
    """Return sample enriched SBOM data with vulnerabilities."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:test-enriched-1234",
        "version": 1,
        "components": [
            {
                "bom-ref": "pkg:pypi/vulnerable-lib@1.0.0",
                "type": "library",
                "name": "vulnerable-lib",
                "version": "1.0.0",
                "purl": "pkg:pypi/vulnerable-lib@1.0.0",
                "vulnerabilities": [
                    {
                        "source_id": "GHSA-xxxx-xxxx-xxxx",
                        "cve_id": "CVE-2023-12345",
                        "description": "Test vulnerability description",
                        "cvss_score": 7.5,
                        "cvss_version": "3.1",
                        "cvss_severity": "HIGH",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "references": ["https://example.com/vuln"],
                        "cwe_ids": ["CWE-79"],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def sample_cve_data() -> list[dict[str, Any]]:
    """Return sample CVE data from NVD format."""
    return [
        {
            "id": "CVE-2023-12345",
            "description": "A test vulnerability in test-package",
            "published": "2023-01-15T00:00:00.000",
            "lastModified": "2023-01-20T00:00:00.000",
            "vulnStatus": "Analyzed",
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-89"}]}],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"}],
        }
    ]


@pytest.fixture
def sample_cwe_data() -> list[dict[str, Any]]:
    """Return sample CWE data."""
    return [
        {
            "id": "CWE-79",
            "name": "Improper Neutralization of Input During Web Page Generation",
            "description": "Cross-site scripting (XSS) vulnerability",
            "extended_description": "The software does not neutralize user input...",
            "related_weaknesses": ["CWE-74", "CWE-116"],
        },
        {
            "id": "CWE-89",
            "name": "SQL Injection",
            "description": "SQL injection vulnerability",
            "extended_description": "The software constructs SQL commands...",
            "related_weaknesses": ["CWE-74"],
        },
    ]


@pytest.fixture
def sample_capec_data() -> list[dict[str, Any]]:
    """Return sample CAPEC data."""
    return [
        {
            "id": "CAPEC-86",
            "name": "XSS Through HTTP Headers",
            "description": "An attacker injects malicious content...",
            "related_weaknesses": ["CWE-79"],
            "prerequisites": ["Target application accepts HTTP headers"],
        }
    ]


@pytest.fixture
def sample_knowledge_graph() -> dict[str, Any]:
    """Return sample knowledge graph data."""
    return {
        "nodes": [
            {"id": "CVE-2023-12345", "type": "cve", "description": "Test CVE"},
            {"id": "CWE-79", "type": "cwe", "name": "XSS"},
            {"id": "pkg:pypi/test@1.0.0", "type": "component", "name": "test"},
        ],
        "edges": [
            {
                "source_id": "CVE-2023-12345",
                "source_type": "cve",
                "target_id": "CWE-79",
                "target_type": "cwe",
                "type": "HAS_CWE",
            },
            {
                "source_id": "pkg:pypi/test@1.0.0",
                "source_type": "component",
                "target_id": "CVE-2023-12345",
                "target_type": "cve",
                "type": "HAS_VULNERABILITY",
            },
        ],
    }
