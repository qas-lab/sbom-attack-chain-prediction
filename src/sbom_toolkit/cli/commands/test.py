"""
Streamlined test command for SBOM toolkit CLI.

Simple interface: `sbom test` with smart defaults and optional overrides.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

from ...intelligence.evaluation import PerformanceTestFramework
from ...shared.output import OutputManager
from ..output import create_output_manager
from ..utils import get_cli_flags, get_click

click, CLICK_AVAILABLE = get_click()


# Default test repositories with known vulnerabilities
DEFAULT_TEST_REPOS = [
    "https://github.com/vulnerable-apps/Tiredful-API-py3-beta",
    "https://github.com/vulnerable-apps/VAmPI",
    "https://github.com/vulnerable-apps/vulnapi",
]

# Additional vulnerable repos for extended testing
EXTENDED_TEST_REPOS = [
    "https://github.com/vulnerable-apps/django-rev-shell",
    "https://github.com/vulnerable-apps/rest-api-goat",
    "https://github.com/vulnerable-apps/vfapi",
    "https://github.com/vulnerable-apps/log4j-honeypot-flask",
]

# Default focused test questions per SBOM
DEFAULT_QUESTIONS_PER_SBOM = 3

# Default systems to test
DEFAULT_SYSTEMS = ["mcp", "legacy_rag", "standalone"]  # Test all three systems with embedding cache


@click.command()
@click.option(
    "--repos",
    "-r",
    help="Comma-separated list of repository URLs (default: vulnerable-apps sample)",
)
@click.option(
    "--questions",
    "-q",
    type=int,
    default=DEFAULT_QUESTIONS_PER_SBOM,
    help=f"Number of questions per SBOM (default: {DEFAULT_QUESTIONS_PER_SBOM})",
)
@click.option(
    "--model",
    "-m",
    default="gpt-4o",
    help="OpenAI model to use (default: gpt-4o, try: o3-mini)",
)
@click.option(
    "--systems",
    "-s",
    default=",".join(DEFAULT_SYSTEMS),
    help=f"Systems to test: mcp,legacy_rag,standalone (default: {','.join(DEFAULT_SYSTEMS)})",
)
@click.option(
    "--output-dir",
    "-o",
    default="test_results",
    help="Output directory for results (default: test_results)",
)
@click.option(
    "--quick",
    is_flag=True,
    help="Quick test mode: 1 repo, 2 questions, MCP vs Standalone only",
)
@click.option(
    "--cache-only",
    is_flag=True,
    help="Use only cached SBOMs/KGs, skip generation (faster for model comparison)",
)
@click.option(
    "--extended",
    is_flag=True,
    help="Use extended repository list (5 repos instead of 3)",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Disable caching (force fresh tests)",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show detailed output including KG generation, embeddings, etc.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Minimal output - show only progress bars and final results",
)
@click.option(
    "--mock",
    is_flag=True,
    help="Mock mode: Skip API calls, use simulated responses (for testing iteration speed)",
)
@click.pass_context
def test(
    ctx,
    repos,
    questions,
    model,
    systems,
    output_dir,
    quick,
    cache_only,
    extended,
    no_cache,
    verbose,
    quiet,
    mock,
):
    """
    Run MCP accuracy evaluation with smart defaults.

    Default: Tests 3 vulnerable-apps repositories with 3 focused questions each,
    comparing MCP-enhanced vs Standalone LLM for citation accuracy.

    CACHING MODES:
    - Default: Generate and cache SBOMs/KGs, reuse if available
    - --cache-only: Use only cached data (faster for model comparison)
    - --no-cache: Force fresh generation every time

    Quick examples:
        sbom test                          # Run default test suite
        sbom test --quick                  # Fast test: 1 repo, 2 questions
        sbom test --model o3-mini          # Test o3-mini reasoning model
        sbom test --cache-only --model o3-mini  # Fast model comparison using cached data
        sbom test --extended               # Test all 5 repos instead of 3
        sbom test --repos https://github.com/my/repo  # Test specific repo

    WORKFLOW TIP:
    1. First run: `sbom test` (generates and caches SBOMs/KGs)
    2. Model comparison: `sbom test --cache-only --model o3-mini` (fast!)
    3. Compare more models: `sbom test --cache-only --model gemini-2.0-flash-thinking`
    """
    logger = ctx.obj["logger"]

    # Get global flags from context
    cli_flags = get_cli_flags(ctx)
    global_verbose = cli_flags.get("verbose", False)
    global_quiet = cli_flags.get("quiet", False)
    global_no_cache = cli_flags.get("no_cache", False)

    # Local flags take precedence over global flags
    effective_verbose = verbose or global_verbose
    effective_quiet = quiet or global_quiet
    effective_no_cache = no_cache or global_no_cache

    # Create CLI output manager with effective flags
    cli_output = create_output_manager(quiet=effective_quiet, verbose=effective_verbose)

    # Check for OpenAI API key (skip in mock mode)
    if not mock and not os.getenv("OPENAI_API_KEY"):
        cli_output.error("OpenAI API key required. Set OPENAI_API_KEY environment variable.")
        sys.exit(1)

    if mock:
        if effective_verbose:
            click.echo("🎭 Mock mode enabled: Using simulated responses (no API calls)")
        # Override model to indicate mock mode
        model = f"{model}-mock"

    # Handle quick mode overrides
    if quick:
        repos = repos or DEFAULT_TEST_REPOS[0]  # Just first repo
        questions = min(questions, 2)  # Max 2 questions
        # Include all systems with embedding cache - RAG is now fast too!
        if not systems or systems == ",".join(DEFAULT_SYSTEMS):
            systems = "mcp,legacy_rag,standalone"
        if effective_verbose:
            click.echo(
                "🏃 Quick test mode: 1 repo, 2 questions, All 3 systems (with embedding cache)"
            )

    # Parse repositories
    if repos:
        repo_list = [repo.strip() for repo in repos.split(",")]
    else:
        if extended:
            repo_list = DEFAULT_TEST_REPOS + EXTENDED_TEST_REPOS
            if effective_verbose:
                click.echo(
                    f"📋 Using extended vulnerable-apps repositories ({len(repo_list)} repos)"
                )
        else:
            repo_list = DEFAULT_TEST_REPOS
            if effective_verbose:
                click.echo(
                    f"📋 Using default vulnerable-apps repositories ({len(repo_list)} repos)"
                )

    # Handle cache options
    if cache_only and effective_no_cache:
        click.echo("❌ Cannot use both --cache-only and --no-cache")
        sys.exit(1)

    if cache_only:
        if effective_verbose:
            click.echo("📦 Cache-only mode: Will use existing SBOMs/KGs only (no generation)")
    elif no_cache:
        if effective_verbose:
            click.echo("⚠️  Caching disabled - all SBOMs and KGs will be generated fresh")

    # Parse systems to test
    system_list = [s.strip() for s in systems.split(",")]
    valid_systems = {"mcp", "legacy_rag", "standalone"}
    system_list = [s for s in system_list if s in valid_systems]

    if not system_list:
        click.echo("❌ No valid systems specified. Use: mcp,legacy_rag,standalone")
        sys.exit(1)

    if effective_verbose:
        click.echo(f"🧪 Testing systems: {', '.join(system_list)}")
        click.echo(f"🎯 {questions} questions per SBOM")
        click.echo(f"🤖 Using model: {model}")

        if no_cache:
            click.echo("⚠️  Caching disabled - all tests will run fresh")

    # Initialize output manager
    output_manager = OutputManager(Path(output_dir))
    output_manager.base_dir.mkdir(parents=True, exist_ok=True)

    try:
        total_tests = 0
        all_results = []

        # Process each repository
        for i, repo_url in enumerate(repo_list, 1):
            if effective_verbose:
                click.echo(f"\n{'=' * 60}")
                click.echo(f"🔍 Repository {i}/{len(repo_list)}: {repo_url}")
                click.echo(f"{'=' * 60}")

            try:
                # Generate SBOM and KG for this repo
                if not verbose:
                    click.echo(f"📋 Processing repository {i}/{len(repo_list)}...")
                else:
                    click.echo("📋 Generating SBOM and Knowledge Graph...")

                results = _run_pipeline_for_repo(
                    ctx, repo_url, output_manager, effective_no_cache, cache_only, effective_verbose
                )

                if not results:
                    click.echo(f"❌ Skipping {repo_url} - No valid SBOM/KG found")
                    continue

                # Load data
                with open(results["sbom_path"]) as f:
                    sbom_data = json.load(f)
                with open(results["kg_path"]) as f:
                    kg_data = json.load(f)

                # Initialize test framework early
                test_framework = PerformanceTestFramework(
                    output_manager=output_manager,
                    cli_output=cli_output,
                    save_detailed=True,
                    cache_enabled=not effective_no_cache,
                    model_override=model if model != "gpt-4o" else None,  # Pass model override
                    verbose=effective_verbose,  # Pass verbose flag
                    mock_mode=mock,  # Pass mock mode flag
                )

                # Start embedding generation immediately after KG is loaded for all modes
                # This ensures embeddings are ready by the time we reach Phase 3
                if "legacy_rag" in system_list:
                    test_framework._start_background_embedding_generation(kg_data)

                # Run performance test for this SBOM
                if not quiet:
                    if not verbose:
                        cli_output.test_info("Running tests...")
                    else:
                        cli_output.test_info(f"Running {questions} focused test questions...")

                # Use grouped parallel comparison (best performance with embedding caching)
                try:
                    if effective_verbose:
                        click.echo("🚀 Using grouped parallel execution (Standalone → MCP → RAG)")
                    comparison = test_framework.run_performance_comparison_grouped_parallel(
                        repo_url, sbom_data, kg_data, max_tests=questions
                    )
                except AttributeError as e:
                    if effective_verbose:
                        click.echo(f"⚠️  Grouped method not available: {e}")
                        click.echo("🔄 Falling back to parallel execution")
                    # Fall back to parallel if grouped method not available
                    try:
                        comparison = test_framework.run_performance_comparison_parallel(
                            repo_url, sbom_data, kg_data, max_tests=questions
                        )
                    except AttributeError as e2:
                        if effective_verbose:
                            click.echo(f"⚠️  Parallel method not available: {e2}")
                            click.echo("🔄 Falling back to sequential execution")
                        # Fall back to sequential if parallel method not available
                        comparison = test_framework.run_performance_comparison(
                            repo_url, sbom_data, kg_data, max_tests=questions
                        )

                if comparison:
                    all_results.append(
                        {
                            "repo": repo_url,
                            "comparison": comparison,
                            "vuln_count": results.get("vuln_count", 0),
                        }
                    )
                    total_tests += len(comparison.kg_enhanced_results)

                    # Show quick summary for this repo (only in verbose mode)
                    if effective_verbose:
                        _show_repo_summary(comparison, results.get("vuln_count", 0))

            except Exception as e:
                click.echo(f"❌ Error testing {repo_url}: {e}")
                logger.error(f"Repository test failed: {e}")
                continue

        # Final summary across all repositories
        if all_results:
            click.echo(f"\n{'=' * 80}")
            click.echo("📊 FINAL RESULTS ACROSS ALL REPOSITORIES")
            click.echo(f"{'=' * 80}")

            _show_aggregate_summary(all_results, system_list, model)

            # Save comprehensive results
            results_file = _save_aggregate_results(all_results, output_manager, model)
            click.echo(f"\n💾 Detailed results saved to: {results_file}")

        else:
            click.echo("❌ No successful tests completed")
            sys.exit(1)

    except KeyboardInterrupt:
        click.echo("\n\n⚠️  Test interrupted by user")
        click.echo("📊 Partial results may be available in output directory")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test framework error: {e}")
        click.echo(f"❌ Test failed: {e}")
        sys.exit(1)


def _check_cached_files(repo_url, output_manager):
    """Check if cached SBOM and KG files exist for a repository."""
    try:
        # Extract repo name for file paths
        repo_name = output_manager.clean_repo_name(repo_url)

        # Check for SBOM file
        sbom_files = list(output_manager.dirs["sboms"].glob(f"*{repo_name}*.json"))
        if not sbom_files:
            return None, None
        sbom_path = sbom_files[0]  # Use first match

        # Check for KG file
        kg_files = list(output_manager.dirs["knowledge_graphs"].glob(f"*{repo_name}*.json"))
        if not kg_files:
            return sbom_path, None
        kg_path = kg_files[0]  # Use first match

        # Both files exist
        return sbom_path, kg_path

    except Exception as e:
        click.echo(f"⚠️  Error checking cache for {repo_url}: {e}")
        return None, None


def _run_pipeline_for_repo(
    ctx, repo_url, output_manager, no_cache, cache_only=False, verbose=False
):
    """Run SBOM generation and KG building for a single repository."""

    # Check for cached files first
    cached_sbom, cached_kg = _check_cached_files(repo_url, output_manager)

    if cache_only:
        if cached_sbom and cached_kg:
            if verbose:
                click.echo(f"✓ Using cached files for {repo_url}")
            # Count vulnerabilities for summary
            import json

            try:
                with open(cached_sbom) as f:
                    sbom_data = json.load(f)
                vuln_count = 0
                for component in sbom_data.get("components", []):
                    vuln_count += len(component.get("vulnerabilities", []))

                return {
                    "sbom_path": cached_sbom,
                    "kg_path": cached_kg,
                    "vuln_count": vuln_count,
                    "build_kg": True,
                }
            except Exception as e:
                click.echo(f"⚠️  Error reading cached files: {e}")
                return None
        else:
            click.echo(f"❌ No cached files found for {repo_url} (cache-only mode)")
            return None

    # Generate fresh or use existing cache
    from .pipeline import _run_core_pipeline

    # Don't duplicate the message if it was already shown in the caller
    return _run_core_pipeline(
        ctx=ctx,
        repository_url=repo_url,
        output_base=str(output_manager.base_dir),
        generator=None,  # Use default
        no_cache=no_cache,
        build_kg=True,
        verbose=verbose,  # Pass verbose flag to core pipeline
    )


def _show_repo_summary(comparison, vuln_count):
    """Show quick summary for a single repository."""
    mcp_stats = comparison.summary_stats.get("mcp_enhanced", {})
    standalone_stats = comparison.summary_stats.get("standalone", {})

    # Get F1.5 scores as primary metric
    mcp_f15 = mcp_stats.get("avg_accuracy", 0)  # This will be F1.5 from framework.py
    standalone_f15 = standalone_stats.get("avg_accuracy", 0)  # This will be F1.5 from framework.py
    improvement = (mcp_f15 - standalone_f15) * 100

    click.echo(f"  📈 Vulnerabilities found: {vuln_count}")
    click.echo(f"  📈 MCP F1.5 score: {mcp_f15:.1%}")
    click.echo(f"  📈 Standalone F1.5 score: {standalone_f15:.1%}")
    click.echo(f"  📈 MCP improvement: {improvement:+.1f} percentage points")


def _show_aggregate_summary(all_results, system_list, model):
    """Show final aggregate summary across all repositories."""
    total_repos = len(all_results)
    total_vulns = sum(r["vuln_count"] for r in all_results)

    # Calculate micro-averaged metrics across all repos and tests
    avg_stats = {}
    for system in system_list:
        system_key = f"{system}_enhanced" if system == "mcp" else system

        # Collect all individual test results for micro-averaging
        all_precisions = []
        all_recalls = []
        all_f1_scores = []
        all_f1_5_scores = []
        response_times = []
        # success_rates = []
        total_tests = 0

        for result in all_results:
            comparison = result["comparison"]

            # Get the appropriate results list based on system
            if system == "mcp":
                test_results = comparison.kg_enhanced_results
            elif system == "legacy_rag":
                test_results = comparison.legacy_rag_results
            else:  # standalone
                test_results = comparison.standalone_results

            # Collect individual test metrics for micro-averaging
            for test_result in test_results:
                if test_result.precision >= 0:  # Only include valid results
                    all_precisions.append(test_result.precision)
                    all_recalls.append(test_result.recall)
                    all_f1_scores.append(test_result.f1_score)
                    all_f1_5_scores.append(test_result.f1_5_score)
                    total_tests += 1

                if test_result.response_time > 0:
                    response_times.append(test_result.response_time)

            # Also collect repo-level success rate
            stats = comparison.summary_stats.get(system_key, {})
            # success_rate = stats.get("success_rate", 0)
            # if success_rate > 0:
            #     success_rates.append(success_rate)

        # Calculate micro-averaged metrics
        avg_stats[system] = {
            "precision": sum(all_precisions) / len(all_precisions) if all_precisions else 0,
            "recall": sum(all_recalls) / len(all_recalls) if all_recalls else 0,
            "f1_score": sum(all_f1_scores) / len(all_f1_scores) if all_f1_scores else 0,
            "f1_5_score": sum(all_f1_5_scores) / len(all_f1_5_scores) if all_f1_5_scores else 0,
            "response_time": sum(response_times) / len(response_times) if response_times else 0,
            # "success_rate": sum(success_rates) / len(success_rates) if success_rates else 0,
            "tests_completed": total_tests,
        }

    click.echo(f"🎯 Model tested: {model}")
    click.echo(f"📊 Repositories: {total_repos}")
    click.echo(f"🔍 Total vulnerabilities: {total_vulns}")
    click.echo("\n")

    # Show detailed results for each system
    system_names = {
        "standalone": "Standalone LLM",
        "mcp": "MCP-Enhanced",
        "legacy_rag": "Legacy RAG",
    }

    for system in system_list:
        stats = avg_stats[system]
        system_name = system_names.get(system, system.upper())

        click.echo(f"📈 {system_name} Results:")
        click.echo(f"   Precision: {stats['precision']:.1%}")
        click.echo(f"   Recall: {stats['recall']:.1%}")
        click.echo(f"   F1 Score: {stats['f1_score']:.1%}")
        click.echo(f"   F1.5 Score: {stats['f1_5_score']:.1%} (primary metric)")
        click.echo(f"   Average Response Time: {stats['response_time']:.2f}s")
        click.echo(f"   Success Rate: {stats['success_rate']:.1%}")
        click.echo(f"   Tests Completed: {stats['tests_completed']}")
        click.echo("\n")

    # Show relative improvements using F1.5 as primary metric
    if "mcp" in avg_stats and "standalone" in avg_stats:
        mcp_f15 = avg_stats["mcp"]["f1_5_score"]
        standalone_f15 = avg_stats["standalone"]["f1_5_score"]
        improvement = (mcp_f15 - standalone_f15) * 100
        click.echo(f"🚀 MCP vs Standalone: {improvement:+.1f} percentage points F1.5 improvement")

        mcp_time = avg_stats["mcp"]["response_time"]
        standalone_time = avg_stats["standalone"]["response_time"]
        if standalone_time > 0:
            time_diff = ((mcp_time - standalone_time) / standalone_time) * 100
            click.echo(f"⏱️  MCP vs Standalone: {time_diff:+.1f}% response time difference")

    if "legacy_rag" in avg_stats and "standalone" in avg_stats:
        rag_f15 = avg_stats["legacy_rag"]["f1_5_score"]
        standalone_f15 = avg_stats["standalone"]["f1_5_score"]
        improvement = (rag_f15 - standalone_f15) * 100
        click.echo(
            f"🧠 Legacy RAG vs Standalone: {improvement:+.1f} percentage points F1.5 improvement"
        )

        rag_time = avg_stats["legacy_rag"]["response_time"]
        standalone_time = avg_stats["standalone"]["response_time"]
        if standalone_time > 0:
            time_diff = ((rag_time - standalone_time) / standalone_time) * 100
            click.echo(f"⏱️  Legacy RAG vs Standalone: {time_diff:+.1f}% response time difference")

    if "mcp" in avg_stats and "legacy_rag" in avg_stats:
        mcp_f15 = avg_stats["mcp"]["f1_5_score"]
        rag_f15 = avg_stats["legacy_rag"]["f1_5_score"]
        improvement = (mcp_f15 - rag_f15) * 100
        click.echo(f"⚡ MCP vs Legacy RAG: {improvement:+.1f} percentage points F1.5 difference")


def _save_aggregate_results(all_results, output_manager, model):
    """Save comprehensive results across all repositories."""
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = output_manager.base_dir / f"aggregate_results_{model}_{timestamp}.json"

    repository_results: list[dict[str, Any]] = []
    aggregate_data: dict[str, Any] = {
        "model": model,
        "timestamp": datetime.now().isoformat(),
        "total_repositories": len(all_results),
        "repository_results": repository_results,
    }

    for result in all_results:
        repo_data = {
            "repository_url": result["repo"],
            "vulnerability_count": result["vuln_count"],
            "test_session_id": result["comparison"].test_session_id,
            "summary_stats": result["comparison"].summary_stats,
        }
        repository_results.append(repo_data)

    with open(results_file, "w") as f:
        json.dump(aggregate_data, f, indent=2)

    return results_file


@click.command(name="test-cache")
@click.option(
    "--repos",
    "-r",
    help="Comma-separated list of repository URLs (default: vulnerable-apps sample)",
)
@click.option(
    "--extended",
    is_flag=True,
    help="Cache extended repository list (5 repos instead of 3)",
)
@click.option(
    "--output-dir",
    "-o",
    default="test_results",
    help="Output directory for cached data (default: test_results)",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force regeneration even if cache exists",
)
@click.pass_context
def test_cache(ctx, repos, extended, output_dir, force):
    """
    Pre-generate and cache SBOMs and Knowledge Graphs for testing.

    This command generates all the test data upfront so you can run
    fast model comparisons later with `sbom test --cache-only`.

    Examples:
        sbom test-cache                    # Cache default 3 repos
        sbom test-cache --extended         # Cache all 5 repos
        sbom test-cache --force            # Regenerate existing cache
    """
    logger = ctx.obj["logger"]

    # Parse repositories (same logic as test command)
    if repos:
        repo_list = [repo.strip() for repo in repos.split(",")]
    else:
        if extended:
            repo_list = DEFAULT_TEST_REPOS + EXTENDED_TEST_REPOS
            click.echo(f"📋 Caching extended vulnerable-apps repositories ({len(repo_list)} repos)")
        else:
            repo_list = DEFAULT_TEST_REPOS
            click.echo(f"📋 Caching default vulnerable-apps repositories ({len(repo_list)} repos)")

    # Initialize output manager
    output_manager = OutputManager(Path(output_dir))
    output_manager.base_dir.mkdir(parents=True, exist_ok=True)

    try:
        cached_count = 0
        generated_count = 0

        # Process each repository
        for i, repo_url in enumerate(repo_list, 1):
            click.echo(f"\n{'=' * 50}")
            click.echo(f"📦 Repository {i}/{len(repo_list)}: {repo_url}")
            click.echo(f"{'=' * 50}")

            try:
                # Check if already cached
                cached_sbom, cached_kg = _check_cached_files(repo_url, output_manager)

                if cached_sbom and cached_kg and not force:
                    click.echo("✓ Already cached, skipping (use --force to regenerate)")
                    cached_count += 1
                    continue

                # Generate SBOM and KG
                results = _run_pipeline_for_repo(ctx, repo_url, output_manager, no_cache=force)

                if results and results.get("kg_path"):
                    click.echo("✅ Successfully cached SBOM and Knowledge Graph")
                    generated_count += 1
                else:
                    click.echo(f"❌ Failed to cache {repo_url}")

            except Exception as e:
                click.echo(f"❌ Error caching {repo_url}: {e}")
                logger.error(f"Cache generation failed for {repo_url}: {e}")
                continue

        # Summary
        click.echo(f"\n{'=' * 60}")
        click.echo("📊 CACHE GENERATION SUMMARY")
        click.echo(f"{'=' * 60}")
        click.echo(f"✅ Generated: {generated_count} repos")
        click.echo(f"📦 Already cached: {cached_count} repos")
        click.echo(f"💾 Cache location: {output_manager.base_dir}")

        if generated_count > 0:
            click.echo("\n🚀 Ready for fast testing! Try:")
            click.echo("  sbom test --cache-only --model o3-mini")

    except KeyboardInterrupt:
        click.echo("\n⚠️  Cache generation interrupted")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Cache generation error: {e}")
        click.echo(f"❌ Cache generation failed: {e}")
        sys.exit(1)


@click.command(name="test-cache-embeddings")
@click.option(
    "--action",
    "-a",
    type=click.Choice(["status", "clear", "warm"]),
    default="status",
    help="Action to perform on embedding cache (default: status)",
)
@click.option(
    "--repos",
    "-r",
    help="Comma-separated list of repository URLs for warming cache",
)
@click.option(
    "--output-dir",
    "-o",
    default="test_results",
    help="Output directory for cache (default: test_results)",
)
@click.pass_context
def test_cache_embeddings(ctx, action, repos, output_dir):
    """
    Manage embedding cache for RAG system to improve test performance.

    The embedding cache stores pre-computed embeddings to avoid the 30+ second
    delay when testing the Legacy RAG system.

    Examples:
        sbom test-cache-embeddings                    # Show cache status
        sbom test-cache-embeddings --action clear    # Clear all cached embeddings
        sbom test-cache-embeddings --action warm --repos "https://github.com/example/repo"  # Pre-warm cache
    """
    from pathlib import Path

    from ...intelligence.evaluation.test_cache import TestResultCache

    logger = ctx.obj["logger"]

    # Initialize cache manager
    cache_dir = Path(output_dir) / "cache" / "performance_tests"
    cache = TestResultCache(cache_dir, cache_enabled=True)
    embedding_cache = cache.embedding_cache

    if action == "status":
        click.echo("🧠 Embedding Cache Status")
        click.echo("=" * 40)

        stats = embedding_cache.get_cache_stats()

        if not stats.get("enabled"):
            click.echo("❌ Embedding cache is disabled")
            return

        if stats.get("error"):
            click.echo(f"❌ Error getting cache stats: {stats['error']}")
            return

        entry_count = stats.get("entry_count", 0)
        total_size_mb = stats.get("total_size_mb", 0)

        click.echo(f"📊 Cache Entries: {entry_count}")
        click.echo(f"💾 Total Size: {total_size_mb} MB")
        click.echo(f"📁 Cache Directory: {stats.get('cache_dir', 'unknown')}")

        if entry_count > 0:
            click.echo("\n📋 Cached Knowledge Graphs:")
            for i, entry in enumerate(stats.get("entries", []), 1):
                click.echo(f"  {i}. KG Hash: {entry['kg_hash'][:12]}...")
                click.echo(f"     Documents: {entry['document_count']}")
                click.echo(f"     Embedding Dimension: {entry['embedding_dimension']}")
                click.echo(f"     Created: {entry['created_at']}")
                click.echo("\n")

        else:
            click.echo(
                "\n💡 No cached embeddings found. Use 'sbom test-cache' to generate test data,"
            )
            click.echo("   then run tests to populate the embedding cache automatically.")

    elif action == "clear":
        click.echo("🗑️  Clearing embedding cache...")

        try:
            files_removed = embedding_cache.clear_cache()
            click.echo(f"✅ Cleared {files_removed} cache files")

            if files_removed > 0:
                click.echo("💡 Next test run will regenerate embeddings (~30s delay)")
            else:
                click.echo("ℹ️  Cache was already empty")

        except Exception as e:
            click.echo(f"❌ Error clearing cache: {e}")
            logger.error(f"Embedding cache clear failed: {e}")
            sys.exit(1)

    elif action == "warm":
        if not repos:
            click.echo("❌ --repos required for warming cache")
            click.echo(
                "Example: sbom test-cache-embeddings --action warm --repos 'https://github.com/example/repo'"
            )
            sys.exit(1)

        click.echo("🔥 Warming embedding cache...")

        repo_list = [repo.strip() for repo in repos.split(",")]

        # Initialize output manager
        from ...shared.output import OutputManager

        output_manager = OutputManager(Path(output_dir))
        output_manager.base_dir.mkdir(parents=True, exist_ok=True)

        warmed_count = 0
        for repo_url in repo_list:
            click.echo(f"\n📦 Processing: {repo_url}")

            try:
                # Check if KG exists for this repo
                repo_name = output_manager.clean_repo_name(repo_url)
                kg_files = list(output_manager.dirs["knowledge_graphs"].glob(f"*{repo_name}*.json"))

                if not kg_files:
                    click.echo(f"⚠️  No knowledge graph found for {repo_url}")
                    click.echo("   Run 'sbom test-cache' first to generate SBOM and KG")
                    continue

                kg_path = kg_files[0]

                # Load KG data
                import json

                with open(kg_path) as f:
                    kg_data = json.load(f)

                # Check if embeddings are already cached
                if embedding_cache.warm_cache_for_kg(kg_data):
                    click.echo("✓ Embeddings already cached")
                    warmed_count += 1
                else:
                    click.echo("❌ No cached embeddings found")
                    click.echo("   Run a test with this repository to generate embeddings")

            except Exception as e:
                click.echo(f"❌ Error processing {repo_url}: {e}")
                logger.error(f"Cache warming failed for {repo_url}: {e}")
                continue

        click.echo(
            f"\n📊 Cache warming complete: {warmed_count}/{len(repo_list)} repositories have cached embeddings"
        )

        if warmed_count < len(repo_list):
            click.echo("💡 To populate missing embeddings, run:")
            click.echo("   sbom test --repos 'repository_urls'")


@click.command(name="test-kg-performance")
@click.option(
    "--repos",
    "-r",
    help="Comma-separated list of repository URLs (default: vulnerable-apps sample)",
)
@click.option(
    "--iterations",
    "-i",
    type=int,
    default=5,
    help="Number of iterations for performance measurement (default: 5)",
)
@click.option(
    "--output-dir",
    "-o",
    default="test_results",
    help="Output directory for results (default: test_results)",
)
@click.pass_context
def test_kg_performance(ctx, repos, iterations, output_dir):
    """
    Test knowledge graph processing and embedding performance.

    This command benchmarks the time taken for:
    1. Knowledge graph loading and processing
    2. Document creation from KG data
    3. Embedding generation (with and without cache)
    4. Memory usage during embedding operations

    Examples:
        sbom test-kg-performance                              # Test default repos
        sbom test-kg-performance --iterations 10             # More iterations for accuracy
        sbom test-kg-performance --repos "https://github.com/example/repo"  # Specific repo
    """
    import json
    import time
    from pathlib import Path

    from ...intelligence.evaluation.test_cache import TestResultCache
    from ...intelligence.retrieval.legacy.rag import RAGSystem
    from ...shared.output import OutputManager

    logger = ctx.obj["logger"]

    # Parse repositories
    if repos:
        repo_list = [repo.strip() for repo in repos.split(",")]
    else:
        repo_list = DEFAULT_TEST_REPOS[:1]  # Just test one repo by default

    click.echo("⚡ Knowledge Graph Performance Testing")
    click.echo(f"Repositories: {len(repo_list)}")
    click.echo(f"Iterations per repo: {iterations}")
    click.echo("=" * 60)

    # Initialize output manager and cache
    output_manager = OutputManager(Path(output_dir))
    cache_dir = output_manager.base_dir / "cache" / "performance_tests"
    cache = TestResultCache(cache_dir, cache_enabled=True)

    all_results: list[dict[str, Any]] = []

    for repo_url in repo_list:
        click.echo(f"\n📊 Testing: {repo_url}")
        click.echo("-" * 40)

        try:
            # Find KG file for this repo
            repo_name = output_manager.clean_repo_name(repo_url)
            kg_files = list(output_manager.dirs["knowledge_graphs"].glob(f"*{repo_name}*.json"))

            if not kg_files:
                click.echo(f"❌ No knowledge graph found for {repo_url}")
                continue

            kg_path = kg_files[0]

            # Load KG data once
            with open(kg_path) as f:
                kg_data = json.load(f)

            node_count = len(kg_data.get("nodes", []))
            edge_count = len(kg_data.get("edges", []))

            click.echo(f"📈 KG Size: {node_count} nodes, {edge_count} edges")

            timings: list[dict[str, Any]] = []
            repo_results: dict[str, Any] = {
                "repo_url": repo_url,
                "kg_nodes": node_count,
                "kg_edges": edge_count,
                "iterations": iterations,
                "timings": timings,
            }

            # Test with cache cleared first
            click.echo("\n🧹 Clearing embedding cache for accurate timing...")
            cache.embedding_cache.clear_cache()

            for iteration in range(iterations):
                click.echo(f"  Iteration {iteration + 1}/{iterations}...")

                timing: dict[str, Any] = {}

                # Time RAG system initialization
                start_time = time.time()
                rag_system = RAGSystem(require_openai=True, embedding_cache=cache.embedding_cache)
                timing["rag_init"] = time.time() - start_time

                # Time knowledge graph loading
                start_time = time.time()
                rag_system.load_knowledge_graph(kg_data)
                timing["kg_load"] = time.time() - start_time

                doc_count = len(rag_system.documents)
                timing["documents_created"] = doc_count

                # Time embedding generation
                if not rag_system.embeddings:  # Only if not cached
                    start_time = time.time()

                    # Suppress output during timing
                    import contextlib
                    import io

                    with contextlib.redirect_stdout(io.StringIO()):
                        rag_system.generate_embeddings(kg_data)

                    timing["embedding_generation"] = time.time() - start_time
                    timing["embeddings_generated"] = len(rag_system.embeddings)
                else:
                    timing["embedding_generation"] = 0.0  # Cached
                    timing["embeddings_generated"] = len(rag_system.embeddings)
                    timing["cache_hit"] = True

                timing["total_time"] = (
                    timing["rag_init"] + timing["kg_load"] + timing["embedding_generation"]
                )
                timings.append(timing)

                click.echo(f" {timing['total_time']:.2f}s")

                # Clear cache between iterations to measure uncached performance
                if iteration < iterations - 1:
                    cache.embedding_cache.clear_cache()

            all_results.append(repo_results)

            # Calculate and show averages for this repo
            avg_total = sum(float(t.get("total_time", 0.0) or 0.0) for t in timings) / iterations
            avg_kg_load = sum(float(t.get("kg_load", 0.0) or 0.0) for t in timings) / iterations
            avg_embedding = (
                sum(float(t.get("embedding_generation", 0.0) or 0.0) for t in timings) / iterations
            )

            # Get doc_count from the last timing result (should be same for all iterations)
            avg_doc_count = int(timings[-1].get("documents_created", 0) or 0) if timings else 0

            click.echo("\n📊 Average Performance:")
            click.echo(f"   Total Time: {avg_total:.2f}s")
            click.echo(f"   KG Loading: {avg_kg_load:.2f}s")
            click.echo(f"   Embedding Generation: {avg_embedding:.2f}s")
            click.echo(f"   Documents Created: {avg_doc_count}")

        except Exception as e:
            click.echo(f"❌ Error testing {repo_url}: {e}")
            logger.error(f"Performance test failed for {repo_url}: {e}")
            continue

    # Save detailed results
    if all_results:
        timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = output_manager.base_dir / f"kg_performance_results_{timestamp}.json"

        with open(results_file, "w") as f:
            json.dump(
                {
                    "test_type": "kg_performance",
                    "timestamp": timestamp,
                    "iterations_per_repo": iterations,
                    "results": all_results,
                },
                f,
                indent=2,
            )

        click.echo(f"\n💾 Detailed results saved to: {results_file}")

        # Overall summary
        total_repos = len(all_results)
        total_iterations = sum(r["iterations"] for r in all_results)

        click.echo("\n🎯 Overall Summary:")
        click.echo(f"   Repositories tested: {total_repos}")
        click.echo(f"   Total iterations: {total_iterations}")

        if total_repos > 0:
            avg_nodes = sum(r["kg_nodes"] for r in all_results) / total_repos
            avg_docs = (
                sum(
                    sum(t["documents_created"] for t in r["timings"]) / len(r["timings"])
                    for r in all_results
                )
                / total_repos
            )

            click.echo(f"   Average KG size: {avg_nodes:.0f} nodes")
            click.echo(f"   Average documents: {avg_docs:.0f} per repo")
    else:
        click.echo("❌ No successful performance tests completed")
