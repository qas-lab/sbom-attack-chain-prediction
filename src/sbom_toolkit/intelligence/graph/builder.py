import logging
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .processors import (
    AttackProcessor,
    CAPECProcessor,
    CWEProcessor,
    NVDProcessor,
    SBOMProcessor,
    SelectiveDataBuilder,
)
from .schema import (
    KGNodeSchema,
    KGNodeType,
    KGRelationshipType,
)


class KnowledgeGraphBuilder:
    """Builds a knowledge graph from parsed cybersecurity data."""

    def __init__(self):
        self.nodes = defaultdict(dict)
        self.edges = defaultdict(list)
        self.logger = logging.getLogger(__name__)

        # Initialize processors
        self.nvd_processor = NVDProcessor(self)
        self.cwe_processor = CWEProcessor(self)
        self.capec_processor = CAPECProcessor(self)
        self.attack_processor = AttackProcessor(self)
        self.sbom_processor = SBOMProcessor(self)
        self.selective_builder = SelectiveDataBuilder(self, self.sbom_processor)

    def add_node(
        self,
        node_type: KGNodeType,
        node_id: str,
        properties: dict[str, Any] | None = None,
    ):
        """Adds a node to the graph with schema validation."""
        if node_id not in self.nodes[node_type]:
            schema = KGNodeSchema.get_node_schema(node_type)
            node_data = {"id": node_id, "type": node_type.value}

            if properties:
                # Validate required fields are present
                for required_field in schema["required"]:
                    if required_field not in properties and required_field != "id":
                        self.logger.warning(
                            f"Missing required field '{required_field}' for {node_type.value} node '{node_id}'"
                        )

                node_data.update(properties)

            self.nodes[node_type][node_id] = node_data
        else:
            # Handle merging for VERSION nodes to combine vulnerability data from duplicates
            if node_type == KGNodeType.VERSION and properties:
                self._merge_version_node(node_id, properties)

    def _merge_version_node(self, version_id: str, new_properties: dict[str, Any]):
        """Merge vulnerability data from duplicate version nodes."""
        existing_node = self.nodes[KGNodeType.VERSION][version_id]

        # Get vulnerability counts
        existing_vuln_count = existing_node.get("vulnerability_count", 0)
        new_vuln_count = new_properties.get("vulnerability_count", 0)

        # Get CVSS scores
        existing_cvss = existing_node.get("max_cvss_score", 0) or 0
        new_cvss = new_properties.get("max_cvss_score", 0) or 0

        # Merge vulnerability data - take the higher counts and CVSS scores
        if new_vuln_count > existing_vuln_count:
            existing_node["vulnerability_count"] = new_vuln_count
            existing_node["is_vulnerable"] = new_properties.get("is_vulnerable", False)

        if new_cvss > existing_cvss:
            existing_node["max_cvss_score"] = new_cvss

        # Update other fields if they're missing or better in the new version
        for key, value in new_properties.items():
            if key not in existing_node or (not existing_node[key] and value):
                existing_node[key] = value

        # Log the merge for debugging
        self.logger.debug(
            f"Merged duplicate version node {version_id}: "
            f"vulns {existing_vuln_count} -> {existing_node.get('vulnerability_count')}, "
            f"CVSS {existing_cvss} -> {existing_node.get('max_cvss_score')}"
        )

    def add_edge(
        self,
        source_type: KGNodeType,
        source_id: str,
        target_type: KGNodeType,
        target_id: str,
        relationship_type: KGRelationshipType,
        properties: dict[str, Any] | None = None,
    ):
        """Adds an edge (relationship) between two nodes."""
        # Ensure nodes exist before adding an edge
        if source_id not in self.nodes[source_type]:
            self.add_node(source_type, source_id)
        if target_id not in self.nodes[target_type]:
            self.add_node(target_type, target_id)

        edge = {
            "source_id": source_id,
            "source_type": source_type.value,
            "target_id": target_id,
            "target_type": target_type.value,
            "type": relationship_type.value,
        }
        if properties:
            edge.update(properties)
        self.edges[relationship_type].append(edge)

    def build_from_nvd_data(self, cve_data_list: list[dict[str, Any]]) -> dict[str, int]:
        """Builds graph components from a list of parsed NVD CVE data."""
        return self.nvd_processor.process(cve_data_list)

    def build_from_cwe_data(self, cwe_data_list: list[dict[str, Any]]) -> dict[str, int]:
        """Builds graph components from a list of parsed CWE data."""
        return self.cwe_processor.process(cwe_data_list)

    def build_from_capec_data(self, capec_data_list: list[dict[str, Any]]) -> dict[str, int]:
        """Builds graph components from a list of parsed CAPEC data."""
        return self.capec_processor.process(capec_data_list)

    def build_from_attack_data(
        self, attack_data: dict[str, list[dict[str, Any]]]
    ) -> dict[str, int]:
        """Builds graph components from MITRE ATT&CK data."""
        return self.attack_processor.process(attack_data)

    def get_graph_data(self) -> dict[str, Any]:
        """Returns the accumulated graph data (nodes and edges)."""
        # Flatten nodes from defaultdict of dicts to a single list of dicts
        all_nodes = []
        for node_type_dict in self.nodes.values():
            all_nodes.extend(node_type_dict.values())

        # Flatten edges from defaultdict of lists to a single list of dicts
        all_edges = []
        for edge_list in self.edges.values():
            all_edges.extend(edge_list)

        return {"nodes": all_nodes, "edges": all_edges}

    def build_from_sbom_data(self, sbom_data: dict[str, Any], sbom_id: str | None = None) -> str:
        """Builds graph components from SBOM data.

        Args:
            sbom_data: SBOM data in CycloneDX format
            sbom_id: Optional SBOM identifier, if not provided will generate one

        Returns:
            The SBOM ID that was used
        """
        return self.sbom_processor.process(sbom_data, sbom_id)

    def build_selective_cwe_capec_from_sbom(
        self, sbom_data: dict[str, Any], fallback_to_all: bool = False
    ) -> dict[str, int]:
        """Selectively build CWE and CAPEC data based on CVEs found in the SBOM.

        This method:
        1. Extracts all CVE IDs from the SBOM vulnerability data
        2. Fetches detailed CVE information to get associated CWEs
        3. Only adds those specific CWEs to the knowledge graph
        4. Only adds CAPECs that are related to those CWEs

        Args:
            sbom_data: The enriched SBOM data containing vulnerability information
            fallback_to_all: If True, fall back to loading all CWEs/CAPECs if no specific ones found

        Returns:
            Dictionary with counts of added nodes: {'cwe_count': int, 'capec_count': int}
        """
        return self.selective_builder.process(sbom_data, fallback_to_all)

    def build_parallel_from_multiple_sources(
        self,
        nvd_data: list[dict[str, Any]] | None = None,
        cwe_data: list[dict[str, Any]] | None = None,
        capec_data: list[dict[str, Any]] | None = None,
        attack_data: dict[str, list[dict[str, Any]]] | None = None,
    ) -> dict[str, dict[str, int]]:
        """Build knowledge graph from multiple data sources in parallel.

        This method leverages Python 3.13 free-threading to process different
        data sources concurrently, providing significant speedup.

        Args:
            nvd_data: List of parsed NVD CVE data
            cwe_data: List of parsed CWE data
            capec_data: List of parsed CAPEC data
            attack_data: MITRE ATT&CK data dictionary

        Returns:
            Dictionary mapping data source to processing statistics
        """
        # Check if free-threading is available (Python 3.13+ only)
        try:
            gil_enabled = sys._is_gil_enabled()  # type: ignore[attr-defined]
            max_workers = 4 if not gil_enabled else 1
        except AttributeError:
            # Fall back to single worker if _is_gil_enabled is not available
            max_workers = 1

        results = {}
        tasks = []

        # Prepare tasks
        if nvd_data is not None:
            tasks.append(("nvd", self.build_from_nvd_data, nvd_data))
        if cwe_data is not None:
            tasks.append(("cwe", self.build_from_cwe_data, cwe_data))
        if capec_data is not None:
            tasks.append(("capec", self.build_from_capec_data, capec_data))
        if attack_data is not None:
            tasks.append(("attack", self.build_from_attack_data, attack_data))

        if not tasks:
            return results

        # Process tasks in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(func, data): (name, func, data) for name, func, data in tasks
            }

            # Collect results as they complete
            for future in as_completed(future_to_task):
                name, func, data = future_to_task[future]
                try:
                    result = future.result()
                    results[name] = result
                    self.logger.debug(f"Parallel KG build completed for {name}: {result}")
                except Exception as e:
                    self.logger.error(f"Failed to build KG for {name}: {e}")
                    results[name] = {"error": str(e)}

        return results

    def build_from_batch_processors(
        self,
        processor_batches: list[tuple[str, Any, list[dict[str, Any]]]],
        batch_size: int = 100,
    ) -> dict[str, Any]:
        """Process large datasets in parallel batches.

        This method is useful for processing very large datasets by splitting
        them into smaller batches and processing them in parallel.

        Args:
            processor_batches: List of (processor_name, processor_func, data) tuples
            batch_size: Size of each batch for parallel processing

        Returns:
            Combined results from all processors
        """
        # Check if free-threading is available (Python 3.13+ only)
        try:
            gil_enabled = sys._is_gil_enabled()  # type: ignore[attr-defined]
            max_workers = 4 if not gil_enabled else 1
        except AttributeError:
            # Fall back to single worker if _is_gil_enabled is not available
            max_workers = 1
        all_results = {}

        for processor_name, processor_func, data in processor_batches:
            # Split data into batches
            batches = [data[i : i + batch_size] for i in range(0, len(data), batch_size)]
            batch_results = []

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Process batches in parallel
                future_to_batch = {
                    executor.submit(processor_func, batch): batch_idx
                    for batch_idx, batch in enumerate(batches)
                }

                for future in as_completed(future_to_batch):
                    batch_idx = future_to_batch[future]
                    try:
                        result = future.result()
                        batch_results.append(result)
                    except Exception as e:
                        self.logger.error(f"Batch {batch_idx} failed for {processor_name}: {e}")

            # Combine batch results
            combined = {}
            for result in batch_results:
                for key, value in result.items():
                    if key in combined:
                        combined[key] += value
                    else:
                        combined[key] = value

            all_results[processor_name] = combined

        return all_results

    def validate_kg_data_integrity(self) -> dict[str, Any]:
        """Validate knowledge graph data integrity by checking consistency between
        vulnerability counts and actual CVE edges.

        Returns:
            Dictionary with validation results and any inconsistencies found
        """
        integrity_issues: list[dict[str, Any]] = []
        validation_results: dict[str, Any] = {
            "total_version_nodes": 0,
            "nodes_with_vulnerabilities": 0,
            "integrity_issues": integrity_issues,
            "summary": "PASSED",
        }

        # Get all edges for quick lookup
        vulnerability_edges = {}
        for edge_list in self.edges.values():
            for edge in edge_list:
                if edge.get("type") == "HAS_VULNERABILITY":
                    source_id = edge.get("source_id")
                    if source_id not in vulnerability_edges:
                        vulnerability_edges[source_id] = []
                    vulnerability_edges[source_id].append(edge.get("target_id"))

        # Check each VERSION node
        for version_id, version_node in self.nodes[KGNodeType.VERSION].items():
            validation_results["total_version_nodes"] += 1

            # Get reported vulnerability count
            reported_count = version_node.get("vulnerability_count", 0)
            is_vulnerable = version_node.get("is_vulnerable", False)

            # Count actual CVE edges
            actual_cve_edges = vulnerability_edges.get(version_id, [])
            actual_count = len(actual_cve_edges)

            if reported_count > 0 or is_vulnerable:
                validation_results["nodes_with_vulnerabilities"] += 1

            # Check for inconsistencies
            if reported_count != actual_count:
                issue: dict[str, Any] = {
                    "node_id": version_id,
                    "issue_type": "count_mismatch",
                    "reported_count": reported_count,
                    "actual_count": actual_count,
                    "is_vulnerable_flag": is_vulnerable,
                    "cve_edges": actual_cve_edges,
                }
                integrity_issues.append(issue)

            # Check is_vulnerable flag consistency
            if (actual_count > 0) != is_vulnerable:
                issue: dict[str, Any] = {
                    "node_id": version_id,
                    "issue_type": "vulnerable_flag_mismatch",
                    "actual_count": actual_count,
                    "is_vulnerable_flag": is_vulnerable,
                    "expected_vulnerable": actual_count > 0,
                }
                integrity_issues.append(issue)

        # Set overall status
        if integrity_issues:
            validation_results["summary"] = "FAILED"
            self.logger.error(
                f"Knowledge graph validation FAILED: {len(integrity_issues)} issues found"
            )
            for issue in integrity_issues:
                self.logger.error(f"  - {issue['node_id']}: {issue['issue_type']}")
        else:
            validation_results["summary"] = "PASSED"
            self.logger.debug(
                f"Knowledge graph validation PASSED: {validation_results['total_version_nodes']} nodes checked"
            )

        return validation_results


if __name__ == "__main__":
    # Example Usage (requires NVD_API_KEY environment variable to be set)
    import os

    from sbom_toolkit.intelligence.data_processing.capec_parser import CAPECParser
    from sbom_toolkit.intelligence.data_processing.cwe_parser import CWEParser
    from sbom_toolkit.intelligence.data_processing.nvd_parser import NVDParser

    if not os.getenv("NVD_API_KEY"):
        print("Please set your NVD_API_KEY environment variable to run this example.")
        print("You can get one from: https://nvd.nist.gov/developers/request-api-key")
    else:
        print("Fetching NVD data...")
        nvd_parser = NVDParser()
        cwe_parser = CWEParser()
        capec_parser = CAPECParser()
        try:
            # Fetch a small batch of CVEs for demonstration
            cve_data = nvd_parser.get_cves(results_per_page=10, start_index=0)
            print(f"Fetched {len(cve_data)} CVEs.")

            print("Fetching CWE data...")
            cwe_data = cwe_parser.get_cwe_data()
            print(f"Fetched {len(cwe_data)} CWEs.")

            print("Fetching CAPEC data...")
            capec_data = capec_parser.get_capec_data()
            print(f"Fetched {len(capec_data)} CAPECs.")

            print("Building knowledge graph...")
            kg_builder = KnowledgeGraphBuilder()
            kg_builder.build_from_nvd_data(cve_data)
            kg_builder.build_from_cwe_data(cwe_data)
            kg_builder.build_from_capec_data(capec_data)

            graph = kg_builder.get_graph_data()
            print(
                f"\nGenerated graph with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges."
            )

            # Print a sample of nodes and edges
            print("\nSample Nodes:")
            for _i, node in enumerate(graph["nodes"][:5]):
                print(f"  {node}")

            print("\nSample Edges:")
            for _i, edge in enumerate(graph["edges"][:5]):
                print(f"  {edge}")

        except Exception as e:
            print(f"An error occurred: {e}")
