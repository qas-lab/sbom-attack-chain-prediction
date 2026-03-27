"""
Modern CLI interface for SBOM toolkit using Click with organized command groups.
"""

import sys
from typing import Any

from ..shared.logging import get_logger, setup_logging
from .utils import CLICK_AVAILABLE, get_click

click, _ = get_click()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--quiet", "-q", is_flag=True, help="Enable quiet mode")
@click.option("--no-cache", is_flag=True, help="Disable caching globally")
@click.pass_context
def cli(ctx: Any, verbose: bool, quiet: bool, no_cache: bool) -> None:
    """SBOM Toolkit - Generate, scan, and visualize Software Bills of Materials."""
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Store global flags in context for easy access by subcommands
    ctx.obj["global_flags"] = {"verbose": verbose, "quiet": quiet, "no_cache": no_cache}

    # Setup logging
    if quiet:
        log_level = "WARNING"
    elif verbose:
        log_level = "DEBUG"
    else:
        log_level = "INFO"

    setup_logging(log_level)
    ctx.obj["logger"] = get_logger()


def _register_commands() -> None:
    """Register all CLI commands. Separated for cleaner typing."""
    # Core pipeline commands
    # Health & diagnostics commands
    # Maintenance commands
    from .commands.cleanup import cleanup, status
    from .commands.generate import generate

    # Intelligence & analysis commands
    from .commands.kg_build import kg_build_command
    from .commands.kg_chat import mcp_chat_command
    from .commands.kg_summary import kg_summary_command

    # ML commands
    from .commands.ml import ml_group

    # Testing & performance commands
    from .commands.performance import test_kg_performance
    from .commands.pipeline import pipeline
    from .commands.scan import scan
    from .commands.test import test, test_cache

    # Visualization commands
    from .commands.visualize import unified_viz, visualize
    from .tools.health import check
    from .tools.tools import tools

    # Create command groups for better organization
    @cli.group(name="core")
    def core_group() -> None:
        """Core SBOM pipeline commands: generate, pipeline, scan."""
        pass

    @cli.group(name="intelligence")
    def intelligence_group() -> None:
        """AI analysis and KG operations: kg-build, mcp-chat, kg-summary."""
        pass

    @cli.group(name="visualization")
    def viz_group() -> None:
        """Visualization and reporting: visualize, unified-viz."""
        pass

    @cli.group(name="health")
    def health_group() -> None:
        """Health checks and diagnostics: check, tools, status."""
        pass

    @cli.group(name="testing")
    def testing_group() -> None:
        """Performance testing and evaluation: test, test-cache, test-kg-performance."""
        pass

    @cli.group(name="maintenance")
    def maintenance_group() -> None:
        """File management and cleanup utilities: cleanup."""
        pass

    # Register commands to groups
    # Core pipeline commands (also available at top level)
    cli.add_command(pipeline)
    cli.add_command(generate)
    cli.add_command(scan)

    core_group.add_command(pipeline)
    core_group.add_command(generate)
    core_group.add_command(scan)

    # Intelligence & analysis
    intelligence_group.add_command(kg_build_command)
    intelligence_group.add_command(mcp_chat_command)
    intelligence_group.add_command(kg_summary_command)

    # ML commands (top-level group)
    cli.add_command(ml_group)

    # Visualization
    viz_group.add_command(unified_viz)
    viz_group.add_command(visualize)

    # Health & diagnostics
    health_group.add_command(check)
    health_group.add_command(tools)
    health_group.add_command(status)

    # Testing & performance
    testing_group.add_command(test_kg_performance)
    testing_group.add_command(test)
    testing_group.add_command(test_cache)

    # Maintenance
    maintenance_group.add_command(cleanup)


# Import and register commands
if CLICK_AVAILABLE:
    _register_commands()


def main():
    """Entry point for CLI."""
    if not CLICK_AVAILABLE:
        print("Error: Click is required for the CLI. Install with: pip install click")
        sys.exit(1)

    # When Click is available, call the CLI properly
    try:
        cli()
    except SystemExit:
        # Click may raise SystemExit, which is normal
        pass


if __name__ == "__main__":
    main()
