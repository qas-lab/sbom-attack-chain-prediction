import json
import os

import click

from sbom_toolkit.intelligence.data_processing.capec_parser import CAPECParser
from sbom_toolkit.intelligence.data_processing.cwe_parser import CWEParser
from sbom_toolkit.intelligence.data_processing.nvd_parser import NVDParser
from sbom_toolkit.intelligence.graph.builder import KnowledgeGraphBuilder


@click.command(name="kg-build")
@click.option(
    "--output",
    "-o",
    type=str,
    default="knowledge_graph.json",
    help="Output file path for the knowledge graph (JSON format).",
)
@click.option(
    "--limit",
    "-l",
    type=int,
    default=10,
    help="Number of CVEs to fetch from NVD for graph building (for testing/demo).",
)
def kg_build_command(output, limit):
    """Builds the knowledge graph from NVD data."""
    print("\nBuilding Knowledge Graph...")

    if not os.getenv("NVD_API_KEY"):
        print("Warning: NVD_API_KEY environment variable not set. NVD API rate limits may apply.")
        print("Get an API key from: https://nvd.nist.gov/developers/request-api-key")

    nvd_parser = NVDParser()
    cwe_parser = CWEParser()
    capec_parser = CAPECParser()
    kg_builder = KnowledgeGraphBuilder()

    try:
        print(f"Fetching {limit} CVEs from NVD...")
        cve_data = nvd_parser.get_cves(results_per_page=50, start_index=0, max_results=limit)
        print(f"Fetched {len(cve_data)} CVEs.")

        print("Fetching CWE data...")
        cwe_data = cwe_parser.get_cwe_data()
        print(f"Fetched {len(cwe_data)} CWEs.")

        print("Fetching CAPEC data...")
        capec_data = capec_parser.get_capec_data()
        print(f"Fetched {len(capec_data)} CAPECs.")

        print("Building knowledge graph using parallel processing...")
        # Use the new parallel building method
        results = kg_builder.build_parallel_from_multiple_sources(
            nvd_data=cve_data,
            cwe_data=cwe_data,
            capec_data=capec_data,
            attack_data=None,  # No ATT&CK data in this case
        )

        # Print results
        for source, stats in results.items():
            if "error" not in stats:
                print(f"✓ {source}: processed successfully")

        graph = kg_builder.get_graph_data()
        print(
            f"Knowledge graph built with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges."
        )

        output_path = os.path.abspath(output)
        with open(output_path, "w") as f:
            json.dump(graph, f, indent=2)
        print(f"Knowledge graph saved to: {output_path}")

    except Exception as e:
        print(f"Error building knowledge graph: {e}")
        import traceback

        traceback.print_exc()
