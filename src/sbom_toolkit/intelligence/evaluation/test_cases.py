"""
Test cases for evaluating citation validity and accuracy across LLM systems.

These test cases focus on factual consistency and proper citation behavior
rather than complex multi-hop reasoning, making them suitable for comparing
standalone vs RAG vs MCP systems on citation accuracy.
"""

from typing import Any

from ...shared.models import TestCase


def load_citation_focused_test_cases(
    repository_url: str, sbom_data: dict[str, Any]
) -> list[TestCase]:
    """
    Load streamlined test cases that demonstrate clear MCP advantages.

    These 10 strategic test cases are designed to:
    1. Test each MCP tool capability (get_sbom_overview, analyze_component, etc.)
    2. Show measurable improvements over standalone/RAG systems
    3. Focus on comprehensive, citation-rich responses
    4. Provide reproducible, quantifiable results
    """
    test_cases = []

    # TEST 1: SBOM Overview (tests get_sbom_overview tool)
    # MCP should excel with comprehensive, structured overview
    test_cases.append(
        TestCase(
            id="sbom_overview_comprehensive",
            question="Provide a comprehensive overview of this SBOM including total components, vulnerability distribution, highest risk components, and overall security assessment.",
            category="sbom_overview",
            difficulty="intermediate",
            expected_elements=[
                "total components",
                "vulnerability distribution",
                "severity breakdown",
                "highest risk components",
                "security assessment",
                "specific statistics",
            ],
            repository_context=repository_url,
        )
    )

    # TEST 2: Critical Vulnerability Analysis (tests analyze_security_comprehensive)
    # MCP should provide more comprehensive analysis with CWE/CAPEC details
    test_cases.append(
        TestCase(
            id="critical_vulnerabilities_comprehensive",
            question="Analyze all critical severity vulnerabilities in this SBOM. Include CVE details, affected components, CWE categories, and potential attack patterns.",
            category="security_analysis",
            difficulty="intermediate",
            expected_elements=[
                "critical CVEs",
                "CVSS scores",
                "affected components",
                "CWE categories",
                "attack patterns",
                "comprehensive analysis",
            ],
            repository_context=repository_url,
        )
    )

    # TEST 3: Component Risk Ranking (tests get_vulnerable_components)
    # MCP should provide better filtering and ranking capabilities
    test_cases.append(
        TestCase(
            id="component_risk_ranking",
            question="Rank all vulnerable components by risk level. Include vulnerability counts, maximum CVSS scores, and justify the risk ranking.",
            category="component_risk",
            difficulty="intermediate",
            expected_elements=[
                "component ranking",
                "vulnerability counts",
                "CVSS scores",
                "risk justification",
                "quantitative metrics",
            ],
            repository_context=repository_url,
        )
    )

    # TEST 4: Highest Severity CVE Details (tests get_cve_details)
    # MCP should provide richer CVE analysis with related vulnerabilities
    test_cases.append(
        TestCase(
            id="highest_severity_cve_analysis",
            question="What is the highest severity CVE in this SBOM? Provide comprehensive details including description, affected components, related weaknesses, and potential attack scenarios.",
            category="cve_analysis",
            difficulty="intermediate",
            expected_elements=[
                "CVE ID",
                "CVSS score",
                "vulnerability description",
                "affected components",
                "CWE mappings",
                "attack scenarios",
            ],
            repository_context=repository_url,
        )
    )

    # TEST 5: Security Pattern Analysis (tests analyze_security_comprehensive with patterns focus)
    # MCP should excel at pattern recognition and attack chain analysis
    test_cases.append(
        TestCase(
            id="security_patterns_analysis",
            question="Identify common security patterns and attack chains in this SBOM. What CWE categories are most prevalent and what CAPEC attack patterns could exploit them?",
            category="pattern_analysis",
            difficulty="advanced",
            expected_elements=[
                "common CWE patterns",
                "attack chains",
                "CAPEC patterns",
                "pattern prevalence",
                "exploitation scenarios",
            ],
            repository_context=repository_url,
        )
    )

    return test_cases


def get_baseline_test_cases(repository_url: str) -> list[TestCase]:
    """
    Get focused baseline test cases for system validation.
    These test basic system functionality without requiring specific SBOM content.
    """
    return [
        TestCase(
            id="system_capability_validation",
            question="What security analysis capabilities do you have for software components and SBOMs?",
            category="system_validation",
            difficulty="basic",
            expected_elements=[
                "analysis capabilities",
                "SBOM processing",
                "vulnerability analysis",
                "component assessment",
            ],
            repository_context=repository_url,
        ),
    ]
