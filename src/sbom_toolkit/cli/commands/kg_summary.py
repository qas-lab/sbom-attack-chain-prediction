#!/usr/bin/env python3
"""
Knowledge Graph Summary Generator

This module provides functionality to generate high-level summaries of knowledge graphs,
including node type counts, edge type counts, and optional visualizations.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import click

from sbom_toolkit.shared.exceptions import SBOMToolkitError
from sbom_toolkit.shared.logging import get_logger

logger = get_logger(__name__)


class KnowledgeGraphSummary:
    """Generates comprehensive summaries of knowledge graph structure and content."""

    def __init__(self, kg_data: dict[str, Any]):
        """Initialize with knowledge graph data.

        Args:
            kg_data: Dictionary containing 'nodes' and 'edges' of the knowledge graph
        """
        self.kg_data = kg_data
        self.nodes = kg_data.get("nodes", [])
        self.edges = kg_data.get("edges", [])

        # Build indices for analysis
        self.nodes_by_type = defaultdict(list)
        self.edges_by_type = defaultdict(list)
        self.node_type_lookup = {}

        for node in self.nodes:
            node_type = node.get("type", "unknown")
            node_id = node.get("id", "unknown")
            self.nodes_by_type[node_type].append(node)
            self.node_type_lookup[node_id] = node_type

        for edge in self.edges:
            edge_type = edge.get("type", "unknown")
            self.edges_by_type[edge_type].append(edge)

    def generate_summary(self, show_details: bool = False) -> dict[str, Any]:
        """Generate a comprehensive knowledge graph summary.

        Args:
            show_details: Whether to include detailed breakdowns

        Returns:
            Dictionary containing the summary information
        """
        nodes_summary: dict[str, dict[str, Any]] = {}
        edges_summary: dict[str, dict[str, Any]] = {}
        summary: dict[str, Any] = {
            "overview": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_types": len(self.nodes_by_type),
                "edge_types": len(self.edges_by_type),
            },
            "nodes": nodes_summary,
            "edges": edges_summary,
            "edge_patterns": {},
        }

        # Node type counts
        for node_type, nodes in self.nodes_by_type.items():
            nodes_summary[node_type] = {
                "count": len(nodes),
                "percentage": (len(nodes) / len(self.nodes)) * 100 if self.nodes else 0,
            }

            if show_details:
                nodes_summary[node_type]["examples"] = [
                    node.get("id", "unknown")
                    for node in nodes[:3]  # Show first 3 examples
                ]

        # Edge type counts
        for edge_type, edges in self.edges_by_type.items():
            edges_summary[edge_type] = {
                "count": len(edges),
                "percentage": (len(edges) / len(self.edges)) * 100 if self.edges else 0,
            }

            if show_details:
                # Show some example connections
                examples = []
                for edge in edges[:3]:
                    source = edge.get("source_id", "unknown")
                    target = edge.get("target_id", "unknown")
                    examples.append(f"{source} -> {target}")
                edges_summary[edge_type]["examples"] = examples

        # Analyze edge patterns (source node type -> target node type)
        summary["edge_patterns"] = self._analyze_edge_patterns(show_details)

        return summary

    def print_summary(self, show_details: bool = False) -> None:
        """Print a formatted summary to stdout."""
        summary = self.generate_summary(show_details)

        print("Knowledge Graph Summary")
        print("=" * 50)
        print(f"Total Nodes: {summary['overview']['total_nodes']:,}")
        print(f"Total Edges: {summary['overview']['total_edges']:,}")
        print(f"Node Types: {summary['overview']['node_types']}")
        print(f"Edge Types: {summary['overview']['edge_types']}")
        print()

        # Print node breakdown
        print("Nodes:")
        for node_type, info in sorted(
            summary["nodes"].items(), key=lambda x: x[1]["count"], reverse=True
        ):
            percentage = info["percentage"]
            print(f"- {node_type}: {info['count']:,} nodes ({percentage:.1f}%)")
            if show_details and "examples" in info:
                print(f"  Examples: {', '.join(info['examples'])}")
        print()

        # Print edge breakdown
        print("Edges:")
        for edge_type, info in sorted(
            summary["edges"].items(), key=lambda x: x[1]["count"], reverse=True
        ):
            percentage = info["percentage"]
            print(f"- {edge_type}: {info['count']:,} edges ({percentage:.1f}%)")
            if show_details and "examples" in info:
                print(f"  Examples: {', '.join(info['examples'])}")
        print()

        # Print edge patterns
        print("Edge Patterns (Node Type Connections):")
        for edge_type, patterns in sorted(
            summary["edge_patterns"].items(),
            key=lambda x: sum(p["count"] for p in x[1]),
            reverse=True,
        ):
            print(f"- {edge_type}:")
            for pattern in sorted(patterns, key=lambda x: x["count"], reverse=True):
                source_type = pattern["source_type"]
                target_type = pattern["target_type"]
                count = pattern["count"]
                percentage = pattern["percentage"]
                print(f"  {source_type} -> {target_type}: {count:,} edges ({percentage:.1f}%)")
        print()

        # Print some interesting insights
        self._print_insights(summary)

    def _analyze_edge_patterns(self, show_details: bool = False) -> dict[str, list[dict[str, Any]]]:
        """Analyze what node types each edge type connects.

        Args:
            show_details: Whether to include detailed pattern analysis

        Returns:
            Dictionary mapping edge types to lists of connection patterns
        """
        edge_patterns = {}

        for edge_type, edges in self.edges_by_type.items():
            patterns = defaultdict(int)

            for edge in edges:
                source_id = edge.get("source_id", "unknown")
                target_id = edge.get("target_id", "unknown")

                source_type = self.node_type_lookup.get(source_id, "unknown")
                target_type = self.node_type_lookup.get(target_id, "unknown")

                pattern_key = (source_type, target_type)
                patterns[pattern_key] += 1

            # Convert to structured format
            total_edges = len(edges)
            pattern_list = []

            for (source_type, target_type), count in patterns.items():
                pattern_list.append(
                    {
                        "source_type": source_type,
                        "target_type": target_type,
                        "count": count,
                        "percentage": (count / total_edges) * 100 if total_edges > 0 else 0,
                    }
                )

            edge_patterns[edge_type] = pattern_list

        return edge_patterns

    def _print_insights(self, summary: dict[str, Any]) -> None:
        """Print interesting insights about the knowledge graph."""
        print("Insights:")

        # Most common node types
        top_nodes = sorted(summary["nodes"].items(), key=lambda x: x[1]["count"], reverse=True)[:3]
        node_list = ", ".join([f"{name} ({info['count']:,})" for name, info in top_nodes])
        print(f"- Most common node types: {node_list}")

        # Most common edge types
        top_edges = sorted(summary["edges"].items(), key=lambda x: x[1]["count"], reverse=True)[:3]
        edge_list = ", ".join([f"{name} ({info['count']:,})" for name, info in top_edges])
        print(f"- Most common edge types: {edge_list}")

        # Identify heavily connected node types
        vulnerability_nodes = summary["nodes"].get("CVE", {}).get("count", 0)
        component_nodes = summary["nodes"].get("Component", {}).get("count", 0)
        version_nodes = summary["nodes"].get("Version", {}).get("count", 0)

        if vulnerability_nodes > 0:
            print(f"- Security focus: {vulnerability_nodes:,} vulnerability records (CVEs)")
        if component_nodes > 0:
            print(f"- Component coverage: {component_nodes:,} software components")
        if version_nodes > 0:
            print(f"- Version granularity: {version_nodes:,} specific versions tracked")

        # Calculate connectivity
        if self.nodes and self.edges:
            connectivity = len(self.edges) / len(self.nodes)
            print(f"- Graph connectivity: {connectivity:.2f} edges per node")

    def create_visualizations(self, output_dir: Path) -> list[Path]:
        """Create visualizations of the knowledge graph summary.

        Args:
            output_dir: Directory to save visualizations

        Returns:
            List of paths to created visualization files
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        created_files = []

        try:
            import matplotlib.pyplot as plt  # noqa: F401

            # Create node type distribution chart
            node_chart_path = output_dir / "kg_node_distribution.png"
            self._create_node_distribution_chart(node_chart_path)
            created_files.append(node_chart_path)

            # Create edge type distribution chart
            edge_chart_path = output_dir / "kg_edge_distribution.png"
            self._create_edge_distribution_chart(edge_chart_path)
            created_files.append(edge_chart_path)

            # Create combined overview chart
            overview_path = output_dir / "kg_overview.png"
            self._create_overview_chart(overview_path)
            created_files.append(overview_path)

            print(f"Created {len(created_files)} visualizations in {output_dir}")

        except ImportError:
            print("Warning: matplotlib not available, skipping visualizations")
            print("Install with: pip install matplotlib")

        return created_files

    def _create_node_distribution_chart(self, output_path: Path) -> None:
        """Create a bar chart of node type distribution."""
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return

        # Get top 10 node types
        node_counts = {node_type: len(nodes) for node_type, nodes in self.nodes_by_type.items()}
        top_nodes = sorted(node_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        if not top_nodes:
            return

        names, counts = zip(*top_nodes, strict=False)

        plt.figure(figsize=(12, 8))
        bars = plt.bar(names, counts, color="skyblue", edgecolor="navy", alpha=0.7)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height):,}",
                ha="center",
                va="bottom",
            )

        plt.title("Knowledge Graph Node Type Distribution", fontsize=16, fontweight="bold")
        plt.xlabel("Node Type", fontsize=12)
        plt.ylabel("Count", fontsize=12)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.grid(axis="y", alpha=0.3)

        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

    def _create_edge_distribution_chart(self, output_path: Path) -> None:
        """Create a bar chart of edge type distribution."""
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return

        # Get top 10 edge types
        edge_counts = {edge_type: len(edges) for edge_type, edges in self.edges_by_type.items()}
        top_edges = sorted(edge_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        if not top_edges:
            return

        names, counts = zip(*top_edges, strict=False)

        plt.figure(figsize=(12, 8))
        bars = plt.bar(names, counts, color="lightcoral", edgecolor="darkred", alpha=0.7)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height):,}",
                ha="center",
                va="bottom",
            )

        plt.title("Knowledge Graph Edge Type Distribution", fontsize=16, fontweight="bold")
        plt.xlabel("Edge Type", fontsize=12)
        plt.ylabel("Count", fontsize=12)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.grid(axis="y", alpha=0.3)

        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

    def _create_overview_chart(self, output_path: Path) -> None:
        """Create a combined overview chart."""
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        # Node type pie chart
        node_counts = {node_type: len(nodes) for node_type, nodes in self.nodes_by_type.items()}
        top_nodes = sorted(node_counts.items(), key=lambda x: x[1], reverse=True)[:8]

        if top_nodes:
            names, counts = zip(*top_nodes, strict=False)
            ax1.pie(counts, labels=names, autopct="%1.1f%%", startangle=90)
            ax1.set_title("Node Type Distribution", fontsize=14, fontweight="bold")

        # Edge type pie chart
        edge_counts = {edge_type: len(edges) for edge_type, edges in self.edges_by_type.items()}
        top_edges = sorted(edge_counts.items(), key=lambda x: x[1], reverse=True)[:8]

        if top_edges:
            names, counts = zip(*top_edges, strict=False)
            ax2.pie(counts, labels=names, autopct="%1.1f%%", startangle=90)
            ax2.set_title("Edge Type Distribution", fontsize=14, fontweight="bold")

        plt.suptitle("Knowledge Graph Overview", fontsize=16, fontweight="bold")
        plt.tight_layout()

        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()


def load_knowledge_graph(kg_file: Path) -> dict[str, Any]:
    """Load knowledge graph from JSON file.

    Args:
        kg_file: Path to knowledge graph JSON file

    Returns:
        Knowledge graph data

    Raises:
        SBOMToolkitError: If file cannot be loaded
    """
    try:
        with open(kg_file) as f:
            kg_data = json.load(f)

        if not isinstance(kg_data, dict):
            raise SBOMToolkitError(
                f"Invalid knowledge graph format: expected dict, got {type(kg_data)}"
            )

        if "nodes" not in kg_data or "edges" not in kg_data:
            raise SBOMToolkitError("Invalid knowledge graph format: missing 'nodes' or 'edges'")

        return kg_data

    except json.JSONDecodeError as e:
        raise SBOMToolkitError(f"Failed to parse JSON file {kg_file}: {e}") from e
    except FileNotFoundError as e:
        raise SBOMToolkitError(f"Knowledge graph file not found: {kg_file}") from e
    except Exception as e:
        raise SBOMToolkitError(f"Error loading knowledge graph from {kg_file}: {e}") from e


@click.command(name="kg-summary")
@click.argument("kg_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    help="Output directory for visualizations (default: same as kg_file)",
)
@click.option("--details", "-d", is_flag=True, help="Show detailed information including examples")
@click.option(
    "--visualize", "-v", is_flag=True, help="Create visualization charts (requires matplotlib)"
)
@click.option(
    "--json-output", "-j", type=click.Path(path_type=Path), help="Save summary as JSON file"
)
def kg_summary_command(
    kg_file: Path,
    output_dir: Path | None,
    details: bool,
    visualize: bool,
    json_output: Path | None,
) -> None:
    """Generate a high-level summary of a knowledge graph.

    This command analyzes a knowledge graph JSON file and provides:
    - Node type counts and percentages
    - Edge type counts and percentages
    - Connectivity insights
    - Optional visualizations

    Examples:
        sbom kg-summary knowledge_graph.json
        sbom kg-summary kg.json --details --visualize
        sbom kg-summary kg.json --json-output summary.json
    """
    try:
        click.echo(f"Loading knowledge graph from {kg_file}")
        kg_data = load_knowledge_graph(kg_file)

        summary_generator = KnowledgeGraphSummary(kg_data)

        # Print summary to terminal
        summary_generator.print_summary(show_details=details)

        # Save JSON summary if requested
        if json_output:
            summary_data = summary_generator.generate_summary(show_details=details)
            with open(json_output, "w") as f:
                json.dump(summary_data, f, indent=2)
            click.echo(f"Summary saved to {json_output}")

        # Create visualizations if requested
        if visualize:
            if output_dir is None:
                output_dir = kg_file.parent / "visualizations"

            created_files = summary_generator.create_visualizations(output_dir)
            for file_path in created_files:
                click.echo(f"Created visualization: {file_path}")

    except SBOMToolkitError as e:
        logger.error(f"Knowledge graph summary failed: {e}")
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    # Allow running as standalone script
    kg_summary_command()
