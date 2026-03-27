"""
Pipeline command for SBOM toolkit CLI.
"""

import sys
from pathlib import Path

from ...pipeline.sbom.generation import SBOMProcessor
from ...shared.exceptions import SBOMToolkitError
from ...shared.models import ProcessingConfig
from ...shared.output import OutputManager
from ..utils import get_cli_flags, get_click

# from ...visualization import create_d3_visualization

click, CLICK_AVAILABLE = get_click()


def _run_core_pipeline(
    ctx, repository_url, output_base, generator, no_cache, build_kg=True, verbose=None
):
    """Core pipeline logic shared between different pipeline commands."""
    logger = ctx.obj["logger"]

    # Determine verbosity from context if not explicitly provided
    if verbose is None:
        # Check Click context for verbosity flags
        # Look up the parent context to find global flags
        parent_ctx = ctx
        while parent_ctx.parent:
            parent_ctx = parent_ctx.parent

        # Default to INFO level (not verbose) unless explicitly verbose
        if hasattr(parent_ctx, "params"):
            verbose = parent_ctx.params.get("verbose", False)
            quiet = parent_ctx.params.get("quiet", False)
            # If quiet mode, suppress verbose output
            if quiet:
                verbose = False
        else:
            verbose = False

    # Initialize output manager with organized structure
    output_manager = OutputManager(Path(output_base))

    if verbose:
        click.echo("🚀 Starting SBOM pipeline...")
        click.echo(f"📁 Organized outputs will be saved to: {output_manager.base_dir}")

    # Step 1: Generate SBOM
    if verbose:
        click.echo("📋 Generating SBOM...")
    config = ProcessingConfig(output_dir=output_manager.base_dir, cache_enabled=not no_cache)

    with SBOMProcessor(config, repo_cache_enabled=not no_cache) as processor:
        if generator:
            processor.preferred_generator = generator

        sbom_path = processor.process_repository(repository_url)
        if verbose:
            click.echo(f"✓ SBOM generated: {sbom_path}")

    # Step 2: Scan for vulnerabilities and create enriched SBOM
    if verbose:
        click.echo("🔍 Scanning for vulnerabilities using grype...")
    from ...pipeline.security.scanning import process_single_sbom

    # Get organized path for enriched SBOM (always use grype now)
    enriched_sbom_path = output_manager.get_scan_path(sbom_path, "grype", no_cache=no_cache)

    # Create enriched SBOM with vulnerability data embedded
    success = process_single_sbom(
        input_path=sbom_path, output_path=enriched_sbom_path, cache_enabled=not no_cache
    )

    if not success:
        raise SBOMToolkitError("Failed to create enriched SBOM with vulnerability data")

    if verbose:
        click.echo(f"✓ Created enriched SBOM: {enriched_sbom_path}")

    # Count vulnerabilities for summary
    import json

    with open(enriched_sbom_path) as f:
        enriched_data = json.load(f)

    vuln_count = 0
    for component in enriched_data.get("components", []):
        vuln_count += len(component.get("vulnerabilities", []))

    if verbose:
        click.echo(f"✓ Found {vuln_count} vulnerabilities embedded in components")

    # Step 3: Knowledge graph generation
    kg_path = None
    if build_kg:
        if verbose:
            click.echo("🧠 Building knowledge graph from SBOM data...")
        try:
            from ...intelligence.graph.builder import KnowledgeGraphBuilder

            # Initialize KG builder
            kg_builder = KnowledgeGraphBuilder()

            # Extract repository name for SBOM ID
            repo_name = output_manager.clean_repo_name(repository_url)
            sbom_id = f"sbom_{repo_name}"

            # Build knowledge graph from SBOM data (this includes all vulnerabilities)
            kg_builder.build_from_sbom_data(enriched_data, sbom_id)

            # Selectively enhance with relevant CWE and CAPEC data
            if verbose:
                click.echo("🧠 Enhancing knowledge graph with relevant CWE and CAPEC data...")
            try:
                # Use selective approach - only fetch CWEs/CAPECs related to found CVEs
                selective_counts = kg_builder.build_selective_cwe_capec_from_sbom(enriched_data)
                if verbose:
                    click.echo(f"✓ Added {selective_counts['cwe_count']} relevant CWE entries")
                    click.echo(f"✓ Added {selective_counts['capec_count']} relevant CAPEC entries")

            except Exception as e:
                if verbose:
                    click.echo(f"⚠️  Could not enhance with CWE/CAPEC data: {e}")
                # Continue without CWE/CAPEC data

            # Get the generated graph data
            graph_data = kg_builder.get_graph_data()

            # Count different node types for summary
            node_counts = {}
            for node in graph_data["nodes"]:
                node_type = node.get("type", "unknown")
                node_counts[node_type] = node_counts.get(node_type, 0) + 1

            if verbose:
                click.echo("✓ Knowledge graph built from SBOM components:")
                for node_type, count in sorted(node_counts.items()):
                    click.echo(f"  - {count} {node_type} nodes")

            # Save knowledge graph using organized path
            kg_path = output_manager.get_kg_path(repo_name, no_cache=no_cache)

            with open(kg_path, "w") as f:
                json.dump(graph_data, f, indent=2)

            if verbose:
                click.echo(f"✓ Knowledge graph saved: {kg_path}")
                click.echo(
                    f"  - Total: {len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges"
                )

        except ImportError as e:
            if verbose:
                click.echo(f"✗ Knowledge graph dependencies not available: {e}")
            build_kg = False
        except Exception as e:
            if verbose:
                click.echo(f"✗ Failed to build knowledge graph: {e}")
            logger.error(f"KG generation failed: {e}")
            build_kg = False

    return {
        "output_manager": output_manager,
        "sbom_path": sbom_path,
        "enriched_sbom_path": enriched_sbom_path,
        "kg_path": kg_path,
        "vuln_count": vuln_count,
        "build_kg": build_kg,
    }


@click.command()
@click.argument("repository_url")
@click.option(
    "--output-base",
    "-o",
    default="outputs",
    help="Base output directory (organized subdirectories will be created)",
)
@click.option(
    "--generator",
    "-g",
    type=click.Choice(["syft", "cdxgen"]),
    help="Preferred SBOM generator",
)
@click.pass_context
def pipeline(ctx, repository_url, output_base, generator):
    """Run focused pipeline: generate SBOM, scan vulnerabilities with grype, build KG and start chat"""
    logger = ctx.obj["logger"]

    # Get no_cache from global flags
    cli_flags = get_cli_flags(ctx)
    no_cache = cli_flags.get("no_cache", False)

    try:
        # Run core pipeline
        results = _run_core_pipeline(
            ctx,
            repository_url,
            output_base,
            generator,
            no_cache,
            build_kg=True,
        )

        # Summary
        click.echo("\n🎉 Pipeline completed successfully!")
        click.echo(f"Files organized in: {results['output_manager'].base_dir}")
        click.echo(f"  - SBOMs: {results['output_manager'].dirs['sboms']}")
        click.echo(f"    - Original: {results['sbom_path'].name}")
        click.echo(f"    - Enriched: {results['enriched_sbom_path'].name}")
        if results["kg_path"]:
            click.echo(
                f"  - Knowledge Graphs: {results['output_manager'].dirs['knowledge_graphs']}"
            )
            click.echo(f"    - {results['kg_path'].name}")

        # Start chat session if KG was built successfully
        if results["kg_path"] and results["build_kg"]:
            click.echo("\n💬 Starting chat session...")
            import os

            if not os.getenv("OPENAI_API_KEY"):
                click.echo("❌ OpenAI API key required for chat features.")
                click.echo("Get one at: https://platform.openai.com/api-keys")

                # Offer to prompt for API key
                if click.confirm("\nWould you like to enter your OpenAI API key now?"):
                    api_key = click.prompt("Enter your OpenAI API key", hide_input=True)
                    if api_key:
                        os.environ["OPENAI_API_KEY"] = api_key
                        click.echo("✓ API key set for this session")
                    else:
                        click.echo("❌ No API key provided")
                        return
                else:
                    click.echo("Please set your OpenAI API key:")
                    click.echo("  export OPENAI_API_KEY='your-api-key-here'")
                    click.echo(
                        f"\n🔗 Alternative: Run chat later with: sbom kg-chat -k {results['kg_path']}"
                    )
                    return
            else:
                try:
                    import json

                    from ...intelligence.retrieval.mcp_system_refactored import MCPSystemRefactored

                    # Load the knowledge graph
                    with open(results["kg_path"]) as f:
                        kg_data = json.load(f)

                    # Initialize Enhanced RAG system (will error if OpenAI not available)
                    try:
                        mcp_system = MCPSystemRefactored(require_openai=True)
                        mcp_system.load_knowledge_graph(kg_data)
                    except Exception as e:
                        click.echo(f"❌ Failed to initialize AI system: {e}")
                        click.echo("Please ensure you have a valid OpenAI API key set.")
                        click.echo("Get one at: https://platform.openai.com/api-keys")
                        return

                    click.echo("✅ MCP system ready - LLM has direct knowledge graph access!")
                    click.echo(
                        "💡 Try asking: 'What vulnerabilities are in this SBOM?' or 'Show me setuptools details'"
                    )
                    click.echo("🔚 Type 'quit', 'exit', or press Ctrl+C to exit\n")

                    # Start interactive chat
                    while True:
                        try:
                            question = input("\nYour question: ").strip()

                            if question.lower() in ["quit", "exit", "q"]:
                                break

                            if not question:
                                click.echo("Please enter a question or type 'quit' to exit.")
                                continue

                            # Use the MCP system with streaming - LLM decides what to query
                            mcp_system.chat_with_kg_access(question, stream=True)
                            # Response is streamed as it's generated, no need to print again

                        except (EOFError, KeyboardInterrupt):
                            click.echo("\nGoodbye!")
                            break
                        except Exception as e:
                            click.echo(f"❌ Error: {e}\n")

                except ImportError:
                    click.echo("❌ Chat dependencies not available. Install with OpenAI support.")
                    click.echo(f"🔗 To chat later, run: sbom kg-chat -k {results['kg_path']}")
                except Exception as e:
                    click.echo(f"❌ Failed to start chat: {e}")
                    click.echo(f"🔗 To chat later, run: sbom kg-chat -k {results['kg_path']}")
        else:
            click.echo(
                "❌ Knowledge graph not available for chat. Try re-running with dependencies installed."
            )

        logger.info(f"Pipeline completed for {repository_url}")

    except SBOMToolkitError as e:
        logger.error(f"Pipeline failed: {e}")
        click.echo(f"✗ Pipeline failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)
