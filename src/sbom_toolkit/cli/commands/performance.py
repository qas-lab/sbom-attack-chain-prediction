"""
CLI command for testing KG-enhanced RAG vs standalone LLM performance.

This is the user interface for the performance testing framework.
The core logic is now in intelligence.evaluation.framework and metrics modules.
"""

import json
import os
import sys
from pathlib import Path

from ...intelligence.evaluation import PerformanceTestFramework
from ...shared.exceptions import SBOMToolkitError
from ...shared.output import OutputManager
from ..utils import get_cli_flags, get_click

click, CLICK_AVAILABLE = get_click()


@click.command(name="test-kg-performance")
@click.argument("repository_url")
@click.option(
    "--output-base",
    "-o",
    default="outputs",
    help="Base output directory for test results",
)
@click.option(
    "--generator",
    "-g",
    type=click.Choice(["syft", "cdxgen"]),
    help="Preferred SBOM generator",
)
@click.option(
    "--scanner",
    "-s",
    type=click.Choice(["grype"]),
    help="Preferred vulnerability scanner",
)
@click.option(
    "--no-save",
    is_flag=True,
    default=False,
    help="Disable saving detailed test outputs (reports and detailed logs are saved by default)",
)
@click.option(
    "--tests",
    type=int,
    default=None,
    help="Number of tests to run (default: run all tests)",
)
@click.pass_context
def test_kg_performance(ctx, repository_url, output_base, generator, scanner, no_save, tests):
    """Test citation accuracy and consistency: MCP-enhanced RAG vs Legacy RAG vs Standalone LLM on factual SBOM analysis questions."""
    logger = ctx.obj["logger"]

    # Get no_cache from global flags
    cli_flags = get_cli_flags(ctx)
    no_cache = cli_flags.get("no_cache", False)

    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        click.echo("❌ OpenAI API key required for performance testing.")
        click.echo("Set OPENAI_API_KEY environment variable.")
        sys.exit(1)

    # Check for NVD API key and provide optimization advice
    if not os.getenv("NVD_API_KEY"):
        click.echo("⚠️  NVD API key not found - CWE/CVE lookups will be slower")
        click.echo(
            "💡 Set NVD_API_KEY for 10x faster processing (get one at: https://nvd.nist.gov/developers/request-api-key)"
        )
    else:
        click.echo("🔑 NVD API key found - using optimized rate limiting")

    # Save is enabled by default, disabled only with --no-save
    save_enabled = not no_save

    try:
        click.echo(
            "🧪 Starting 3-way performance comparison: MCP-enhanced RAG vs Legacy RAG vs Standalone LLM"
        )
        click.echo(f"📁 Repository: {repository_url}")

        if save_enabled:
            click.echo("💾 Detailed results and reports will be saved automatically")
        else:
            click.echo("⚠️  Saving disabled - only terminal output will be shown")

        # Initialize output manager
        output_manager = OutputManager(Path(output_base))

        # Step 1: Generate SBOM and KG (reuse pipeline logic)
        from .pipeline import _run_core_pipeline

        click.echo("📋 Generating SBOM and Knowledge Graph...")
        results = _run_core_pipeline(
            ctx,
            repository_url,
            output_base,
            generator,
            no_cache,
            build_kg=True,
        )

        if not results["kg_path"] or not results["build_kg"]:
            click.echo("❌ Knowledge graph generation failed. Cannot run performance test.")
            sys.exit(1)

        # Load SBOM and KG data
        with open(results["sbom_path"]) as f:  # Use raw SBOM instead of enriched
            sbom_data = json.load(f)

        with open(results["kg_path"]) as f:
            kg_data = json.load(f)

        click.echo(f"✓ Loaded raw SBOM with {len(sbom_data.get('components', []))} components")
        click.echo(f"✓ Loaded KG with {len(kg_data.get('nodes', []))} nodes")

        # Step 2: Run performance comparison using the framework
        click.echo("\n🚀 Running 3-way performance comparison...")
        if no_cache:
            click.echo("⚠️  Caching disabled - all tests will run fresh")
        else:
            click.echo("📦 Caching enabled - will reuse results when possible")

        test_framework = PerformanceTestFramework(
            output_manager=output_manager,
            save_detailed=save_enabled,
            cache_enabled=not no_cache,
        )

        # Display test count information
        if tests is not None:
            click.echo(f"🎯 Running {tests} tests (limited by --tests flag)")
        else:
            click.echo("🎯 Running all available tests")

        comparison = None
        comparison = test_framework.run_performance_comparison(
            repository_url, sbom_data, kg_data, max_tests=tests
        )

        # Step 3: Save results and generate report (even if interrupted, as long as we have comparison data)
        results_file = None
        if comparison is not None:
            if save_enabled:
                results_file = test_framework.save_results(comparison)
                click.echo(f"💾 Results saved to: {results_file}")

                # Generate and save report
                report = test_framework.generate_report(comparison)
                report_file = results_file.parent / f"report_{comparison.test_session_id}.md"

                with open(report_file, "w") as f:
                    f.write(report)

                click.echo(f"📊 Report generated: {report_file}")

                # Save detailed logs if requested
                logs_file = test_framework.save_detailed_logs(
                    comparison.test_session_id, comparison
                )
                if logs_file:
                    click.echo(f"📝 Detailed logs saved: {logs_file}")
                else:
                    click.echo("⚠️  No detailed logs to save")

            # Display comprehensive 3-way summary using the refactored method
            summary_text = test_framework.generate_summary_text(comparison)
            click.echo("\n" + summary_text)

            if save_enabled and results_file is not None:
                click.echo(f"\n📁 Full results in: {results_file.parent}")
            else:
                click.echo("\n📁 To save results, run again without --no-save flag")
        else:
            click.echo("❌ No results to save - test was interrupted before any tests completed")
            sys.exit(1)

        logger.info(f"Performance test completed for {repository_url}")

    except SBOMToolkitError as e:
        logger.error(f"Performance test failed: {e}")
        click.echo(f"✗ Performance test failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)
