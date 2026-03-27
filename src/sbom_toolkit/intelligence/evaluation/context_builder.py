"""
SBOM context building module for performance tests.

This module handles creation of standardized SBOM contexts that provide
fair testing conditions across all systems.
"""

from textwrap import dedent
from typing import Any


class SBOMContextBuilder:
    """Builds standardized SBOM contexts for performance testing."""

    def create_sbom_context(
        self,
        sbom_data: dict[str, Any],
        kg_data: dict[str, Any] | None = None,
        max_tokens: int = 15000,
    ) -> str:
        """Create a fair SBOM context using raw SBOM data only - no vulnerability information.

        This ensures all systems (Standalone, MCP, Legacy RAG) start with the same minimal
        information and must discover vulnerabilities through their respective methods.
        """
        all_components = sbom_data.get("components", [])

        # Filter for actual library components (no vulnerability filtering since raw SBOM has none)
        library_components = [
            c
            for c in all_components
            if c.get("type") == "library"
            and c.get("purl", "").startswith("pkg:pypi/")
            and c.get("name") not in ["Simple Launcher"]
        ]

        # Create context with ONLY basic component information from raw SBOM
        context = (
            dedent(
                f"""
            # Raw SBOM Component Inventory

            Repository: {sbom_data.get("metadata", {}).get("repository", {}).get("url", "Unknown")}
            Scan Date: {sbom_data.get("metadata", {}).get("timestamp", "Unknown")}
            Total Library Components: {len(library_components)}
        """
            ).strip()
            + "\n"
        )

        context += "\n## Library Components:\n"

        # Include only basic component information from raw SBOM
        components_included = 0
        remaining_budget = (max_tokens * 4) - len(context)  # Rough token estimate

        for comp in library_components:
            comp_name = comp.get("name", "unknown")
            comp_version = comp.get("version", "unknown")
            comp_purl = comp.get("purl", "N/A")
            comp_type = comp.get("type", "library")

            comp_entry = f"\n### {comp_name} v{comp_version}\n"
            comp_entry += f"- Package URL: {comp_purl}\n"
            comp_entry += f"- Type: {comp_type}\n"

            # Add license info if available
            if comp.get("licenses"):
                licenses = [
                    lic.get("license", {}).get("name", "Unknown")
                    for lic in comp.get("licenses", [])
                ]
                comp_entry += f"- Licenses: {', '.join(licenses[:3])}\n"  # Limit to 3 licenses

            comp_entry += "\n"

            # Check if we have budget for this component
            if len(comp_entry) < remaining_budget:
                context += comp_entry
                remaining_budget -= len(comp_entry)
                components_included += 1
            else:
                break

        if components_included < len(library_components):
            context += f"... and {len(library_components) - components_included} more components\n"

        # Add analysis instructions that encourage discovery
        context += dedent(
            """

        ## Security Analysis Task:
        Your task is to analyze these components for potential security vulnerabilities and risks.
        Consider:
        - Known vulnerabilities in these specific component versions
        - Common vulnerability patterns for these types of components
        - Dependency relationships and potential attack chains
        - Supply chain risks and trust factors
        - Security best practices and recommendations

        Use your knowledge sources to identify CVE IDs, CWE weakness types, CAPEC attack patterns,
        and other security identifiers relevant to these components.
        Provide specific, actionable security analysis with proper citations.
        """
        ).strip()

        return context

    def _add_security_intelligence_section(
        self, kg_data: dict[str, Any], vulnerable_components: list[dict]
    ) -> str:
        """Add comprehensive security intelligence section equivalent to KG system capabilities."""
        section = "\n## Security Intelligence Database:\n"

        # Build KG node lookup for efficiency
        kg_nodes = {node["id"]: node for node in kg_data.get("nodes", [])}
        kg_edges = kg_data.get("edges", [])

        # CVE-CWE-CAPEC mappings
        section += "\n### CVE-CWE-CAPEC Attack Pattern Mappings:\n"
        cve_mappings = []

        # Extract all CVEs from vulnerable components
        all_cves = set()
        for comp in vulnerable_components:
            for vuln in comp.get("vulnerabilities", []):
                cve_id = vuln.get("id", "")
                if cve_id and cve_id != "N/A":
                    all_cves.add(cve_id)

        # Find CWE and CAPEC mappings for each CVE
        for cve_id in sorted(all_cves):
            if cve_id in kg_nodes:
                # Find CWE mappings
                cwes = []
                capecs = []

                for edge in kg_edges:
                    if edge.get("source_id") == cve_id and edge.get("type") == "HAS_CWE":
                        cwe_id = edge.get("target_id", "")
                        if cwe_id in kg_nodes:
                            cwe_node = kg_nodes[cwe_id]
                            cwes.append(f"{cwe_id} ({cwe_node.get('name', 'Unknown')})")

                            # Find CAPEC patterns for this CWE
                            for cwe_edge in kg_edges:
                                if (
                                    cwe_edge.get("source_id") == cwe_id
                                    and cwe_edge.get("type") == "EXPLOITS_CWE"
                                ):
                                    capec_id = cwe_edge.get("target_id", "")
                                    if capec_id in kg_nodes:
                                        capec_node = kg_nodes[capec_id]
                                        capecs.append(
                                            f"{capec_id} ({capec_node.get('name', 'Unknown')})"
                                        )

                if cwes:
                    cwe_str = " | ".join(cwes[:2])  # Limit to 2 CWEs for brevity
                    capec_str = " | ".join(capecs[:2]) if capecs else "No attack patterns mapped"
                    cve_mappings.append(f"{cve_id} -> {cwe_str} -> {capec_str}")

        for mapping in cve_mappings[:10]:  # Limit to 10 mappings to manage token usage
            section += f"- {mapping}\n"

        # Vulnerability severity distribution
        section += "\n### Vulnerability Risk Distribution:\n"
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_vulns = 0

        for comp in vulnerable_components:
            for vuln in comp.get("vulnerabilities", []):
                total_vulns += 1
                ratings = vuln.get("ratings", [])
                max_score = 0
                for rating in ratings:
                    score = rating.get("score", 0)
                    if isinstance(score, int | float) and score > max_score:
                        max_score = score

                if max_score >= 9.0:
                    severity_counts["CRITICAL"] += 1
                elif max_score >= 7.0:
                    severity_counts["HIGH"] += 1
                elif max_score >= 4.0:
                    severity_counts["MEDIUM"] += 1
                else:
                    severity_counts["LOW"] += 1

        section += f"- Total Vulnerabilities: {total_vulns}\n"
        for severity, count in severity_counts.items():
            if count > 0:
                section += f"- {severity}: {count} vulnerabilities\n"

        return section
