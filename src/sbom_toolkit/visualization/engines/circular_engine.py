"""
Circular layout engine for SBOM visualization.

This engine creates circular/radial visualizations where nodes are arranged
in concentric circles or arcs, providing a unique perspective on relationships.
"""

import logging
import math
from typing import Any

import networkx as nx

from ..core.graph_processors import NetworkGraphProcessor


class CircularEngine:
    """Engine for creating circular/radial network visualizations."""

    def __init__(self):
        """Initialize the circular engine."""
        self.logger = logging.getLogger(__name__)
        self.graph_processor = NetworkGraphProcessor()

    def process_sbom_data(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Process SBOM data into circular visualization format.

        Args:
            sbom_data: Transformed SBOM data

        Returns:
            Dictionary with nodes and links positioned for circular layout
        """
        # Create NetworkX graph
        graph = self.graph_processor.create_graph_from_sbom(sbom_data)

        # Calculate circular positions
        positioned_data = self._create_circular_layout(graph, sbom_data)

        return positioned_data

    def _create_circular_layout(self, graph: nx.Graph, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Create circular layout with nodes positioned in concentric circles.

        Args:
            graph: NetworkX graph
            sbom_data: Original SBOM data for context

        Returns:
            Dictionary with positioned nodes and links
        """
        # Group nodes by type and vulnerability status
        node_groups = self._group_nodes_by_type_and_status(graph)

        # Assign nodes to circular layers
        layer_assignments = self._assign_nodes_to_layers(node_groups)

        # Calculate positions for each layer
        positioned_nodes = self._calculate_circular_positions(layer_assignments)

        # Build links with proper references
        links = self._build_circular_links(graph, positioned_nodes)

        # Add vulnerability and metadata information
        enhanced_nodes = self._enhance_nodes_with_metadata(positioned_nodes, graph, sbom_data)

        self.logger.info(
            f"Created circular layout: {len(enhanced_nodes)} nodes in {len(layer_assignments)} layers"
        )

        return {
            "nodes": enhanced_nodes,
            "links": links,
            "layout": "circular",
            "layers": list(layer_assignments.keys()),
            "statistics": self._calculate_statistics(enhanced_nodes, links),
        }

    def _group_nodes_by_type_and_status(self, graph: nx.Graph) -> dict[str, list[str]]:
        """Group nodes by type and vulnerability status.

        Args:
            graph: NetworkX graph

        Returns:
            Dictionary of grouped node lists
        """
        groups = {
            "root": [],
            "vulnerable": [],
            "dependent": [],
            "safe": [],
            "licenses": [],
        }

        for node_id, attrs in graph.nodes(data=True):
            if attrs.get("is_root", False):
                groups["root"].append(node_id)
            elif attrs.get("type") == "LICENSE":
                groups["licenses"].append(node_id)
            elif attrs.get("status") == "VULN":
                groups["vulnerable"].append(node_id)
            elif attrs.get("status") == "WEAK":
                groups["dependent"].append(node_id)
            else:
                groups["safe"].append(node_id)

        return groups

    def _assign_nodes_to_layers(self, node_groups: dict[str, list[str]]) -> dict[int, list[str]]:
        """Assign nodes to circular layers (concentric circles).

        Args:
            node_groups: Grouped nodes by type/status

        Returns:
            Dictionary mapping layer index to node list
        """
        layer_assignments = {}

        # Layer 0: Root nodes (center)
        if node_groups["root"]:
            layer_assignments[0] = node_groups["root"]

        # Layer 1: Vulnerable components (inner ring)
        if node_groups["vulnerable"]:
            layer_assignments[1] = node_groups["vulnerable"]

        # Layer 2: Dependent components (middle ring)
        if node_groups["dependent"]:
            layer_assignments[2] = node_groups["dependent"]

        # Layer 3: Safe components (outer ring)
        if node_groups["safe"]:
            layer_assignments[3] = node_groups["safe"]

        # Layer 4: Licenses (outermost ring)
        if node_groups["licenses"]:
            layer_assignments[4] = node_groups["licenses"]

        # Remove empty layers and reindex
        non_empty_layers = {i: nodes for i, nodes in layer_assignments.items() if nodes}
        reindexed_layers = {i: nodes for i, (_, nodes) in enumerate(non_empty_layers.items())}

        return reindexed_layers

    def _calculate_circular_positions(
        self, layer_assignments: dict[int, list[str]]
    ) -> list[dict[str, Any]]:
        """Calculate x,y positions for nodes in circular layout.

        Args:
            layer_assignments: Nodes assigned to circular layers

        Returns:
            List of node dictionaries with position information
        """
        positioned_nodes = []

        # Layout parameters
        center_x, center_y = 400, 300  # Canvas center
        base_radius = 50  # Starting radius for layer 0
        radius_increment = 80  # Radius increase per layer

        for layer_index, node_list in layer_assignments.items():
            if layer_index == 0:
                # Center position for root nodes
                radius = 0
            else:
                radius = base_radius + (layer_index - 1) * radius_increment

            node_count = len(node_list)

            for i, node_id in enumerate(node_list):
                angle = 0  # Default angle for center nodes
                if radius == 0:
                    # Center position
                    x, y = center_x, center_y
                else:
                    # Circular position
                    angle = (2 * math.pi * i) / node_count
                    x = center_x + radius * math.cos(angle)
                    y = center_y + radius * math.sin(angle)

                positioned_nodes.append(
                    {
                        "id": str(node_id),
                        "x": x,
                        "y": y,
                        "layer": layer_index,
                        "radius": radius,
                        "angle": angle,
                        "layer_position": i,
                        "layer_total": node_count,
                    }
                )

        return positioned_nodes

    def _build_circular_links(
        self, graph: nx.Graph, positioned_nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Build links array for circular layout.

        Args:
            graph: NetworkX graph
            positioned_nodes: Nodes with position information

        Returns:
            List of link dictionaries
        """
        # Create lookup for node positions
        node_positions = {node["id"]: node for node in positioned_nodes}

        # Identify connection types
        vulnerable_nodes = {
            node for node, attrs in graph.nodes(data=True) if attrs.get("status") == "VULN"
        }
        dependent_nodes = {
            node for node, attrs in graph.nodes(data=True) if attrs.get("status") == "WEAK"
        }

        links = []

        for source, target, attrs in graph.edges(data=True):
            source_str = str(source)
            target_str = str(target)

            # Skip if nodes not in position data
            if source_str not in node_positions or target_str not in node_positions:
                continue

            # Determine link properties
            source_layer = node_positions[source_str]["layer"]
            target_layer = node_positions[target_str]["layer"]

            # Color and style based on connection type
            is_vulnerable_connection = (
                source in vulnerable_nodes and target not in vulnerable_nodes
            ) or (target in vulnerable_nodes and source not in vulnerable_nodes)
            is_dependent_connection = (
                source in dependent_nodes and target in vulnerable_nodes
            ) or (target in dependent_nodes and source in vulnerable_nodes)

            if is_vulnerable_connection:
                color = "#FF5252"  # Red
                width = 3
            elif is_dependent_connection:
                color = "#FFA500"  # Orange
                width = 2
            elif attrs.get("relationship") == "license":
                color = "#90EE90"  # Light green
                width = 1
            else:
                color = "#a8a8a8"  # Gray
                width = 1

            link_data = {
                "source": source_str,
                "target": target_str,
                "sourceLayer": source_layer,
                "targetLayer": target_layer,
                "color": color,
                "width": width,
                "relationship": attrs.get("relationship", "unknown"),
                "weight": attrs.get("weight", 1),
                "isVulnerableConnection": is_vulnerable_connection,
                "isDependentConnection": is_dependent_connection,
                "isCrossLayer": source_layer != target_layer,
            }

            links.append(link_data)

        return links

    def _enhance_nodes_with_metadata(
        self,
        positioned_nodes: list[dict[str, Any]],
        graph: nx.Graph,
        sbom_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Enhance positioned nodes with full metadata.

        Args:
            positioned_nodes: Nodes with position data
            graph: NetworkX graph with attributes
            sbom_data: Original SBOM data

        Returns:
            Enhanced node list with complete metadata
        """
        enhanced_nodes = []

        for pos_node in positioned_nodes:
            node_id = pos_node["id"]

            # Get attributes from graph
            if graph.has_node(node_id):
                attrs = graph.nodes[node_id]
            else:
                attrs = {}

            # Get vulnerability information
            vulnerability_info = attrs.get("vulnerabilities", [])
            if not vulnerability_info and attrs.get("status") == "VULN":
                vulnerability_info = self._extract_vulnerability_info(node_id, sbom_data)

            # Build enhanced node
            enhanced_node = {
                **pos_node,  # Include position data
                "fullLabel": attrs.get("full_label", node_id),
                "label": attrs.get("abbreviated_label", node_id),
                "type": attrs.get("type", "LIBRARY"),
                "status": attrs.get("status", "DEFAULT"),
                "color": attrs.get("color", "#808080"),
                "size": attrs.get("size", 40),
                "description": attrs.get("description", ""),
                "isVulnerable": attrs.get("status") == "VULN",
                "isDependent": attrs.get("status") == "WEAK",
                "isRoot": attrs.get("is_root", False),
                "vulnerabilities": vulnerability_info,
            }

            enhanced_nodes.append(enhanced_node)

        return enhanced_nodes

    def _extract_vulnerability_info(
        self, node_id: str, sbom_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract vulnerability information for a node.

        Args:
            node_id: Node identifier
            sbom_data: SBOM data

        Returns:
            List of vulnerability information
        """
        vulnerability_info = []

        # Check component vulnerabilities
        for component in sbom_data.get("components", []):
            comp_id = component.get(
                "bom-ref", f"{component.get('name')}=={component.get('version')}"
            )
            if comp_id == node_id:
                for vuln in component.get("vulnerabilities", []):
                    vulnerability_info.append(
                        {
                            "id": vuln.get("id", vuln.get("cve_id", "Unknown")),
                            "cve_id": vuln.get("cve_id", "Unknown"),
                            "description": vuln.get("description", "No description available"),
                            "cvss_score": vuln.get("cvss_score"),
                            "cvss_severity": vuln.get("cvss_severity", "Unknown"),
                            "cvss_vector": vuln.get("cvss_vector", "N/A"),
                            "references": vuln.get("references", []),
                        }
                    )
                break

        return vulnerability_info

    def _calculate_statistics(
        self, nodes: list[dict[str, Any]], links: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Calculate statistics for the circular layout.

        Args:
            nodes: Enhanced node list
            links: Link list

        Returns:
            Statistics dictionary
        """
        stats = {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "vulnerable_nodes": sum(1 for node in nodes if node.get("isVulnerable", False)),
            "dependent_nodes": sum(1 for node in nodes if node.get("isDependent", False)),
            "safe_nodes": sum(
                1
                for node in nodes
                if not node.get("isVulnerable", False)
                and not node.get("isDependent", False)
                and node.get("type") == "LIBRARY"
            ),
            "license_nodes": sum(1 for node in nodes if node.get("type") == "LICENSE"),
            "cross_layer_links": sum(1 for link in links if link.get("isCrossLayer", False)),
            "layers": len({node.get("layer", 0) for node in nodes}),
        }

        return stats

    def get_layout_config(self) -> dict[str, Any]:
        """Get circular layout configuration.

        Returns:
            Configuration dictionary for circular layout
        """
        return {
            "layout": {
                "center": [400, 300],
                "base_radius": 50,
                "radius_increment": 80,
                "min_node_spacing": 30,
            },
            "animation": {"duration": 1000, "ease": "easeInOutCubic", "stagger": 50},
            "node_settings": {
                "min_radius": 6,
                "max_radius": 18,
                "stroke_width": 2,
                "opacity": 0.9,
            },
            "link_settings": {
                "min_width": 1,
                "max_width": 4,
                "opacity": 0.6,
                "curve": "curveBundle",
            },
        }
