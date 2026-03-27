from collections import defaultdict
from typing import Any


class KnowledgeGraphManager:
    """
    Manages knowledge graph data, indexing, and provides efficient access patterns
    for querying nodes and relationships.
    """

    def __init__(self):
        """Initialize empty knowledge graph structures."""
        self.kg_nodes: dict[str, dict[str, Any]] = {}
        self.kg_edges: list[dict[str, Any]] = []

        # Build node type indices for faster lookups
        self.kg_nodes_by_type: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

        # Build edge indices for graph traversal
        self.kg_edges_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.kg_edges_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def load_knowledge_graph(self, graph_data: dict[str, Any]) -> None:
        """Load a knowledge graph into the system.

        Args:
            graph_data: Dictionary containing 'nodes' and 'edges' of the knowledge graph
        """
        self.kg_nodes = {node["id"]: node for node in graph_data.get("nodes", [])}
        self.kg_edges = graph_data.get("edges", [])

        # Build node type indices for faster lookups
        self.kg_nodes_by_type.clear()
        for node_id, node in self.kg_nodes.items():
            node_type = node.get("type", "unknown")
            self.kg_nodes_by_type[node_type][node_id] = node

        # Build edge indices for graph traversal
        self.kg_edges_by_source.clear()
        self.kg_edges_by_target.clear()
        for edge in self.kg_edges:
            source_id = edge.get("source_id")
            target_id = edge.get("target_id")
            if source_id:
                self.kg_edges_by_source[source_id].append(edge)
            if target_id:
                self.kg_edges_by_target[target_id].append(edge)

        print(
            f"KG Manager: Loaded knowledge graph with {len(self.kg_nodes)} nodes and {len(self.kg_edges)} edges."
        )
        print(f"Node types: {list(self.kg_nodes_by_type.keys())}")

    def is_loaded(self) -> bool:
        """Check if a knowledge graph has been loaded."""
        return bool(self.kg_nodes)

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        """Get a specific node by ID."""
        return self.kg_nodes.get(node_id)

    def get_nodes_by_type(self, node_type: str) -> dict[str, dict[str, Any]]:
        """Get all nodes of a specific type."""
        return self.kg_nodes_by_type.get(node_type, {})

    def get_edges_by_source(self, source_id: str) -> list[dict[str, Any]]:
        """Get all edges originating from a specific node."""
        return self.kg_edges_by_source.get(source_id, [])

    def get_edges_by_target(self, target_id: str) -> list[dict[str, Any]]:
        """Get all edges pointing to a specific node."""
        return self.kg_edges_by_target.get(target_id, [])

    def get_available_component_names(self) -> list[str]:
        """Get list of available component names from the knowledge graph."""
        component_names = []
        for node_id, node in self.kg_nodes_by_type.get("Version", {}).items():
            if "component_id" in node:
                component_names.append(node["component_id"])
            elif "@" in node_id:
                component_names.append(node_id.split("@")[0])
        return list(set(component_names))[:10]  # Return first 10 unique names

    def get_available_cve_ids(self) -> list[str]:
        """Get list of available CVE IDs from the knowledge graph."""
        cve_ids = []
        for node_id, _node in self.kg_nodes_by_type.get("CVE", {}).items():
            if node_id.startswith("CVE-"):
                cve_ids.append(node_id)
        return cve_ids[:10]  # Return first 10 CVE IDs

    def debug_kg_structure(self, show_sample_data: bool = True) -> dict[str, Any]:
        """Debug function to inspect the knowledge graph structure and available data."""
        node_types: dict[str, int] = {}
        edge_types: dict[str, int] = {}
        sample_data: dict[str, Any] = {}
        debug_info: dict[str, Any] = {
            "total_nodes": len(self.kg_nodes),
            "total_edges": len(self.kg_edges),
            "node_types": node_types,
            "edge_types": edge_types,
            "sample_data": sample_data,
        }

        # Count node types
        for _node_id, node in self.kg_nodes.items():
            node_type = str(node.get("type", "unknown"))
            if node_type not in node_types:
                node_types[node_type] = 0
            node_types[node_type] += 1

        # Count edge types
        for edge in self.kg_edges:
            edge_type = str(edge.get("type", "unknown"))
            if edge_type not in edge_types:
                edge_types[edge_type] = 0
            edge_types[edge_type] += 1

        # Sample data from each node type
        if show_sample_data:
            for node_type, nodes in self.kg_nodes_by_type.items():
                if nodes:
                    sample_node_id = list(nodes.keys())[0]
                    sample_node = nodes[sample_node_id]
                    sample_data[node_type] = {
                        "sample_id": sample_node_id,
                        "sample_keys": list(sample_node.keys()),
                        "sample_values": {
                            k: str(v)[:100] + "..." if len(str(v)) > 100 else v
                            for k, v in sample_node.items()
                        },
                    }

        return debug_info
