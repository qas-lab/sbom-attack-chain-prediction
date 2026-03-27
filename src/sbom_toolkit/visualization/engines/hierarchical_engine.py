"""
Hierarchical layout engine for SBOM visualization.

This engine creates tree-like visualizations that show clear parent-child
relationships and dependency hierarchies in the SBOM structure.

Supports integration of ML predictions:
- HGAT predictions: Component vulnerability predictions with confidence scores
- Cascade predictions: CVE attack chain predictions shown as cross-links
"""

import logging
from typing import Any

import networkx as nx

from ..core.graph_processors import HierarchicalGraphProcessor
from ..core.prediction_loader import PredictionLoader


class HierarchicalEngine:
    """Engine for creating hierarchical tree visualizations with ML predictions."""

    def __init__(self) -> None:
        """Initialize the hierarchical engine."""
        self.logger = logging.getLogger(__name__)
        self.graph_processor = HierarchicalGraphProcessor()
        self._prediction_loader: PredictionLoader | None = None

    def process_sbom_data(
        self,
        sbom_data: dict[str, Any],
        hgat_predictions: dict[str, dict[str, str | float]] | None = None,
        cascade_predictions: list[tuple[str, str, float]] | None = None,
    ) -> dict[str, Any]:
        """Process SBOM data into hierarchical visualization format.

        Args:
            sbom_data: Transformed SBOM data
            hgat_predictions: Optional HGAT predictions mapping component IDs to predictions
            cascade_predictions: Optional cascade predictions as (cve1, cve2, probability) tuples

        Returns:
            Hierarchical tree structure for D3.js tree layout
        """
        # Set up prediction loader if we have predictions
        if hgat_predictions or cascade_predictions:
            self._prediction_loader = PredictionLoader()
            if hgat_predictions:
                self._prediction_loader.load_hgat_predictions(hgat_predictions)
            if cascade_predictions:
                self._prediction_loader.load_cascade_predictions(cascade_predictions)
        else:
            self._prediction_loader = None

        # Create directed graph
        graph = self.graph_processor.create_hierarchy_from_sbom(sbom_data)

        # Convert to hierarchical JSON structure
        hierarchy_data = self._convert_to_hierarchy_format(graph, sbom_data)

        return hierarchy_data

    def _convert_to_hierarchy_format(
        self, graph: nx.DiGraph, sbom_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Convert directed graph to hierarchical tree format.

        Args:
            graph: NetworkX directed graph
            sbom_data: Original SBOM data for context

        Returns:
            Hierarchical tree structure
        """
        # Mark vulnerable nodes and propagate vulnerability status
        self._mark_vulnerable_nodes(graph)
        self._propagate_vulnerability_status(graph)

        # Find root node(s)
        root_nodes = self._find_root_nodes(graph)

        if len(root_nodes) == 1:
            # Single root case
            root_json = self._build_hierarchy_recursive(graph, root_nodes[0], set())
        elif len(root_nodes) > 1:
            # Multiple roots - create virtual root
            root_json = self._create_virtual_root(graph, root_nodes)
        else:
            # No clear root found
            raise ValueError("Cannot determine root node for hierarchical layout")

        self.logger.info(
            f"Created hierarchical structure with root: {root_json.get('id', 'virtual')}"
        )

        return root_json

    def _mark_vulnerable_nodes(self, graph: nx.DiGraph):
        """Mark nodes as vulnerable based on their vulnerability data.

        Args:
            graph: NetworkX directed graph
        """
        for _node_id, attrs in graph.nodes(data=True):
            if attrs.get("status") == "VULN" and attrs.get("type") != "LICENSE":
                attrs["isVulnerable"] = True
            else:
                attrs["isVulnerable"] = False

    def _propagate_vulnerability_status(self, graph: nx.DiGraph):
        """Propagate vulnerability status to dependent nodes.

        Args:
            graph: NetworkX directed graph
        """
        vulnerable_nodes = {
            node for node, attrs in graph.nodes(data=True) if attrs.get("isVulnerable", False)
        }

        # Find all ancestors of vulnerable nodes
        all_ancestors = set()
        for vuln_node in vulnerable_nodes:
            try:
                ancestors = nx.ancestors(graph, vuln_node)
                all_ancestors.update(ancestors)
            except nx.NetworkXError:
                continue

        # Mark dependent nodes
        dependent_count = 0
        for node_id in all_ancestors:
            if node_id not in vulnerable_nodes:
                attrs = graph.nodes[node_id]
                if attrs.get("type") != "LICENSE":
                    attrs["isDependentOnVulnerable"] = True
                    dependent_count += 1
                    # Update visual properties
                    if not attrs.get("isVulnerable"):
                        attrs["color"] = "#FFA500"  # Orange for dependent

        self.logger.info(f"Marked {dependent_count} nodes as dependent on vulnerable components")

    def _find_root_nodes(self, graph: nx.DiGraph) -> list[str]:
        """Find root nodes in the directed graph.

        Args:
            graph: NetworkX directed graph

        Returns:
            List of root node identifiers
        """
        # Look for explicitly marked root
        for node, attrs in graph.nodes(data=True):
            if attrs.get("is_root", False):
                return [node]

        # Find nodes with no library predecessors
        potential_roots = []
        for node in graph.nodes():
            if graph.nodes[node].get("type") == "LICENSE":
                continue

            has_library_predecessor = any(
                graph.nodes[pred].get("type") == "LIBRARY" for pred in graph.predecessors(node)
            )

            if not has_library_predecessor:
                potential_roots.append(node)

        if not potential_roots:
            # Fallback: find nodes with minimum in-degree
            min_degree = min(
                int(graph.in_degree(node))  # type: ignore[arg-type]
                for node in graph.nodes()
                if graph.nodes[node].get("type") == "LIBRARY"
            )
            potential_roots = [
                node
                for node in graph.nodes()
                if (
                    graph.nodes[node].get("type") == "LIBRARY"
                    and graph.in_degree(node) == min_degree
                )
            ]

        return potential_roots

    def _create_virtual_root(self, graph: nx.DiGraph, root_nodes: list[str]) -> dict[str, Any]:
        """Create a virtual root node for multiple root scenarios.

        Args:
            graph: NetworkX directed graph
            root_nodes: List of root node identifiers

        Returns:
            Virtual root node structure
        """
        virtual_root = {
            "id": "VIRTUAL_ROOT",
            "name": "Project Dependencies",
            "fullLabel": "Project Dependencies",
            "label": "Project",
            "type": "SBOM",
            "status": "DEFAULT",
            "color": "#808080",
            "size": 80,
            "description": "Virtual root for multiple components",
            "isVulnerable": False,
            "isDependentOnVulnerable": False,
            "vulnerabilities": [],
            "licenses": [],
            "children": [
                self._build_hierarchy_recursive(graph, root, set()) for root in root_nodes
            ],
            # ML prediction fields (not applicable for virtual root)
            "mlPrediction": "Unknown",
            "mlConfidence": 0.0,
            "cascadePredictions": [],
        }

        return virtual_root

    def _build_hierarchy_recursive(
        self, graph: nx.DiGraph, node_id: str, visited: set[str]
    ) -> dict[str, Any]:
        """Recursively build hierarchical structure.

        Args:
            graph: NetworkX directed graph
            node_id: Current node identifier
            visited: Set of already visited nodes (cycle detection)

        Returns:
            Node structure with children
        """
        if node_id in visited:
            # Cycle detected - return reference node
            attrs = graph.nodes[node_id]
            ml_prediction, ml_confidence = self._get_ml_prediction(str(node_id))
            return {
                "id": str(node_id),
                "name": attrs.get("abbreviated_label", str(node_id)),
                "fullLabel": attrs.get("full_label", str(node_id)),
                "label": attrs.get("abbreviated_label", str(node_id)),
                "type": attrs.get("type", "LIBRARY"),
                "status": attrs.get("status", "DEFAULT"),
                "color": attrs.get("color", "#808080"),
                "size": attrs.get("size", 40),
                "description": attrs.get("description", ""),
                "isVulnerable": attrs.get("isVulnerable", False),
                "isDependentOnVulnerable": attrs.get("isDependentOnVulnerable", False),
                "vulnerabilities": [],
                "children": [],
                "isCycleReference": True,
                "mlPrediction": ml_prediction,
                "mlConfidence": ml_confidence,
                "cascadePredictions": [],
            }

        visited.add(node_id)
        attrs = graph.nodes[node_id]

        # Separate children by type
        child_dependencies = []
        child_licenses = []

        for successor in graph.successors(node_id):
            successor_attrs = graph.nodes[successor]
            if successor_attrs.get("type") == "LICENSE":
                child_licenses.append(
                    {
                        "id": str(successor),
                        "name": successor_attrs.get("abbreviated_label", str(successor)),
                        "fullLabel": successor_attrs.get("full_label", str(successor)),
                        "type": "LICENSE",
                        "color": successor_attrs.get("color", "#800080"),
                        "size": successor_attrs.get("size", 25),
                    }
                )
            else:
                # Recursively build dependency children
                child_node = self._build_hierarchy_recursive(graph, successor, visited.copy())
                if child_node:
                    child_dependencies.append(child_node)

        # Get vulnerability information
        vulnerability_info = self._get_vulnerability_info(node_id, attrs)

        # Get ML predictions for this node
        ml_prediction, ml_confidence = self._get_ml_prediction(str(node_id))
        cascade_info = self._get_cascade_predictions(vulnerability_info)

        # Build node structure
        node_data = {
            "id": str(node_id),
            "name": attrs.get("abbreviated_label", str(node_id)),
            "fullLabel": attrs.get("full_label", str(node_id)),
            "label": attrs.get("abbreviated_label", str(node_id)),
            "type": attrs.get("type", "LIBRARY"),
            "status": attrs.get("status", "DEFAULT"),
            "color": attrs.get("color", "#808080"),
            "size": attrs.get("size", 40),
            "description": attrs.get("description", ""),
            "isVulnerable": attrs.get("isVulnerable", False),
            "isDependentOnVulnerable": attrs.get("isDependentOnVulnerable", False),
            "vulnerabilities": vulnerability_info,
            "licenses": child_licenses,
            "children": child_dependencies,
            # ML prediction data
            "mlPrediction": ml_prediction,
            "mlConfidence": ml_confidence,
            "cascadePredictions": cascade_info,
        }

        return node_data

    def _get_ml_prediction(self, node_id: str) -> tuple[str, float]:
        """Get ML prediction for a node.

        Args:
            node_id: Node identifier

        Returns:
            Tuple of (prediction_label, confidence)
        """
        if not self._prediction_loader:
            return "Unknown", 0.0

        pred = self._prediction_loader.get_component_prediction(node_id)
        if pred:
            return str(pred.get("prediction", "Unknown")), float(pred.get("confidence", 0.0))
        return "Unknown", 0.0

    def _get_cascade_predictions(
        self, vulnerability_info: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Get cascade predictions for vulnerabilities.

        Args:
            vulnerability_info: List of vulnerability information

        Returns:
            List of cascade prediction information
        """
        if not self._prediction_loader or not self._prediction_loader.has_cascade_predictions():
            return []

        cascade_info: list[dict[str, Any]] = []
        for vuln in vulnerability_info:
            cve_id = vuln.get("cve_id") or vuln.get("id", "")
            if cve_id and cve_id != "Unknown":
                cascades = self._prediction_loader.get_all_cascades_for_cve(cve_id)
                for c in cascades:
                    cascade_info.append(
                        {
                            "sourceCve": c[0],
                            "targetCve": c[1],
                            "probability": c[2],
                        }
                    )
        return cascade_info

    def _get_vulnerability_info(self, node_id: str, attrs: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract vulnerability information for a node.

        Args:
            node_id: Node identifier
            attrs: Node attributes

        Returns:
            List of vulnerability information
        """
        vulnerability_info = []

        if attrs.get("isVulnerable") and "vulnerabilities" in attrs:
            for vuln in attrs["vulnerabilities"]:
                vuln_info = {
                    "id": vuln.get("id", "Unknown"),
                    "cve_id": vuln.get("cve_id", "Unknown"),
                    "description": vuln.get("description", "No description available"),
                    "cvss_score": vuln.get("cvss_score"),
                    "cvss_severity": vuln.get("cvss_severity", "Unknown"),
                    "cvss_vector": vuln.get("cvss_vector", "N/A"),
                    "references": vuln.get("references", []),
                }
                vulnerability_info.append(vuln_info)

        return vulnerability_info

    def get_layout_config(self) -> dict[str, Any]:
        """Get D3.js tree layout configuration.

        Returns:
            Configuration dictionary for D3.js tree layout
        """
        return {
            "layout": "hierarchical",
            "tree": {
                "nodeSize": [120, 40],
                "separationSiblings": 1,
                "separationNonSiblings": 2,
                "nodeSpacing": 200,
                "levelSpacing": 150,
                "orientation": "horizontal",
            },
            "node_settings": {
                "min_radius": 8,
                "max_radius": 20,
                "stroke_width": 2,
                "text_offset": 15,
                "vulnerable_color": "#FF5252",
                "dependent_color": "#FFA500",
                "default_color": "#4169E1",
            },
            "link_settings": {
                "stroke_width": 2,
                "opacity": 0.6,
                "curve": "curveStepBefore",
            },
            "ml_settings": {
                "show_predictions": True,
                "high_confidence_threshold": 0.8,
                "prediction_indicator_size": 6,
            },
        }
