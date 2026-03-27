"""
Scan command for SBOM toolkit CLI.
"""

import sys
from pathlib import Path

from ...pipeline.security.scanning import VulnerabilityProcessor
from ...shared.exceptions import SBOMToolkitError
from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


@click.command()
@click.argument("sbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", "-o", default="out", help="Output directory for enriched SBOM")
@click.option("--output-name", help="Custom output file name (default: auto-generated)")
@click.option("--build-kg", is_flag=True, help="Build knowledge graph from scan results")
@click.option(
    "--kg-output",
    default="knowledge_graph.json",
    help="Output path for knowledge graph (when --build-kg is used)",
)
@click.pass_context
def scan(ctx, sbom_path, output_dir, output_name, build_kg, kg_output):
    """Scan SBOM for vulnerabilities using grype and create enriched version."""
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        click.echo("🔍 Scanning SBOM for vulnerabilities...")

        # Initialize knowledge graph builder if requested
        kg_builder = None
        if build_kg:
            try:
                from ...intelligence.graph.builder import KnowledgeGraphBuilder

                kg_builder = KnowledgeGraphBuilder()
                click.echo("📊 Knowledge graph integration enabled")
            except ImportError as e:
                click.echo(f"⚠️  Warning: Could not initialize knowledge graph: {e}")

        processor = VulnerabilityProcessor(knowledge_graph_builder=kg_builder)

        # Use custom output name if provided
        output_filename_override = Path(output_name) if output_name else None

        enriched_path = processor.process_sbom_with_kg(
            input_path=sbom_path,
            output_dir=output_dir_path,
            output_filename_override=output_filename_override,
        )

        if enriched_path:
            click.echo(f"✓ Enriched SBOM created: {enriched_path}")

            # Count vulnerabilities for summary
            import json

            with open(enriched_path) as f:
                enriched_data = json.load(f)

            vuln_count = 0
            for component in enriched_data.get("components", []):
                vuln_count += len(component.get("vulnerabilities", []))

            click.echo(f"✓ Found {vuln_count} vulnerabilities")

            # Save knowledge graph if it was built
            if build_kg and kg_builder:
                try:
                    import json

                    kg_data = kg_builder.get_graph_data()
                    kg_output_path = Path(kg_output)

                    with open(kg_output_path, "w") as f:
                        json.dump(kg_data, f, indent=2)

                    click.echo(f"📊 Knowledge graph saved: {kg_output_path}")
                    click.echo(f"   - Nodes: {len(kg_data['nodes'])}")
                    click.echo(f"   - Edges: {len(kg_data['edges'])}")

                except Exception as e:
                    click.echo(f"⚠️  Warning: Failed to save knowledge graph: {e}")

            logger.info(f"Vulnerability scan completed for {sbom_path}")
        else:
            click.echo("✗ Failed to create enriched SBOM")
            sys.exit(1)

    except SBOMToolkitError as e:
        logger.error(f"Vulnerability scan failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)
