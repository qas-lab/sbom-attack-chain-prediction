from typing import Any

from ....shared.cvss_utils import CVSSVersionHandler
from ..schema import KGNodeType, KGRelationshipType
from .base_processor import BaseProcessor


class NVDProcessor(BaseProcessor):
    """Processor for NVD CVE data."""

    def process(self, data: Any, *args: Any, **kwargs: Any) -> dict[str, int]:
        """Builds graph components from a list of parsed NVD CVE data.

        Args:
            data: List of parsed CVE data from NVD

        Returns:
            Statistics about processed data
        """
        cve_data_list = data
        cve_count = 0
        cwe_count = 0

        for cve_data in cve_data_list:
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            # Enhance CVE data with version-aware CVSS processing
            enhanced_cve_data = self._enhance_cve_with_cvss(cve_data)

            # Add CVE node with enhanced data
            self.add_node(KGNodeType.CVE, cve_id, enhanced_cve_data)
            cve_count += 1

            # Add CWE nodes and relationships
            cwe_count += self._process_cve_weaknesses(cve_data, cve_id)

            # Extract and add component/version information (simplified for now)
            self._process_cve_components(cve_data, cve_id)

        return {"cve_count": cve_count, "cwe_count": cwe_count}

    def _process_cve_weaknesses(self, cve_data: dict[str, Any], cve_id: str) -> int:
        """Process CWE weaknesses for a CVE."""
        cwe_count = 0

        for weakness in cve_data.get("weaknesses", []):
            # Handle different weakness formats from NVD
            if isinstance(weakness, dict):
                descriptions = weakness.get("description", [])
                for desc in descriptions:
                    if isinstance(desc, dict):
                        weakness_description = desc.get("value", "")
                    else:
                        weakness_description = str(desc)

                    # Extract CWE ID from description
                    if "CWE-" in weakness_description:
                        # Look for pattern like "CWE-345" or "CWE-345: Description"
                        import re

                        cwe_match = re.search(r"CWE-\d+", weakness_description)
                        if cwe_match:
                            cwe_id = cwe_match.group(0)
                            self.add_node(
                                KGNodeType.CWE,
                                cwe_id,
                                {"description": weakness_description},
                            )
                            self.add_edge(
                                KGNodeType.CVE,
                                cve_id,
                                KGNodeType.CWE,
                                cwe_id,
                                KGRelationshipType.HAS_CWE,
                            )
                            cwe_count += 1
            elif isinstance(weakness, str):
                # Handle simple string format
                if "CWE-" in weakness:
                    import re

                    cwe_match = re.search(r"CWE-\d+", weakness)
                    if cwe_match:
                        cwe_id = cwe_match.group(0)
                        self.add_node(KGNodeType.CWE, cwe_id, {"description": weakness})
                        self.add_edge(
                            KGNodeType.CVE,
                            cve_id,
                            KGNodeType.CWE,
                            cwe_id,
                            KGRelationshipType.HAS_CWE,
                        )
                        cwe_count += 1

        return cwe_count

    def _process_cve_components(self, cve_data: dict[str, Any], cve_id: str):
        """Extract and add component/version information (simplified for now)."""
        # This part needs more sophisticated parsing of configurations/CPEs
        # For demonstration, let's just look for product names in descriptions
        for description_obj in cve_data.get("descriptions", []):
            description = description_obj.get("value", "")
            if "linux kernel" in description.lower():
                self.add_node(KGNodeType.COMPONENT, "Linux Kernel")
                self.add_edge(
                    KGNodeType.CVE,
                    cve_id,
                    KGNodeType.COMPONENT,
                    "Linux Kernel",
                    KGRelationshipType.AFFECTS_COMPONENT,
                )

    def _enhance_cve_with_cvss(self, cve_data: dict[str, Any]) -> dict[str, Any]:
        """Enhance CVE data with version-aware CVSS processing."""
        enhanced_data = cve_data.copy()

        # Extract CVSS metrics from NVD format
        metrics = cve_data.get("metrics", {})
        if not metrics:
            return enhanced_data

        # Parse NVD CVSS format into version-keyed dictionary
        all_cvss_data = CVSSVersionHandler.parse_nvd_cvss(metrics)

        # Select best CVSS version
        best_cvss = CVSSVersionHandler.select_best_cvss(all_cvss_data)

        # Add version-aware CVSS fields to enhanced data
        enhanced_data.update(
            {
                "cvss_score": best_cvss["cvss_score"],
                "cvss_version": best_cvss["cvss_version"],
                "cvss_vector": best_cvss["cvss_vector"],
                "cvss_severity": best_cvss["cvss_severity"],
                "all_cvss_metrics": best_cvss["all_cvss_metrics"],
            }
        )

        return enhanced_data
