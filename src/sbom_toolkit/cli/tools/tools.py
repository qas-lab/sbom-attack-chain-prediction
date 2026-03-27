"""
Tools command for SBOM toolkit CLI - shows available external tools.
"""

import shutil
import sys

from ...pipeline.tools import get_available_sbom_generators, get_available_vulnerability_scanners
from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


@click.command()
@click.pass_context
def tools(ctx):
    """Show available external tools and their status."""
    logger = ctx.obj["logger"]

    click.echo("=== SBOM Toolkit - External Tools Status ===")
    click.echo("")

    # SBOM Generators
    click.echo("📋 SBOM Generators:")

    # Get available generators from actual implementation
    available_generators = get_available_sbom_generators()
    all_generators = ["syft", "cdxgen"]

    for gen in all_generators:
        available = gen in available_generators
        priority = " (primary)" if gen == "syft" else " (fallback)" if gen == "cdxgen" else ""
        status = "✓ Available" if available else "✗ Not installed"
        click.echo(f"  {gen}{priority}: {status}")

    if not available_generators:
        click.echo("  ⚠️  No SBOM generators available! Please install at least one.")
        click.echo("     • syft: https://github.com/anchore/syft")
        click.echo("     • cdxgen: npm install -g @cyclonedx/cdxgen")

    click.echo("")

    # Vulnerability Scanners
    click.echo("🔍 Vulnerability Scanners:")

    # Get available scanners from actual implementation
    available_scanners = get_available_vulnerability_scanners()
    all_scanners = ["grype"]

    for scanner in all_scanners:
        available = scanner in available_scanners
        status = "✓ Available" if available else "✗ Not installed"
        click.echo(f"  {scanner}: {status}")

    if not available_scanners:
        click.echo("  ⚠️  No vulnerability scanners available!")
        click.echo("     • grype: https://github.com/anchore/grype")

    click.echo("")

    # Environment Backends
    click.echo("🐍 Environment Backends:")

    backends = {
        "uv": shutil.which("uv") is not None,
        "venv": True,  # Always available
    }

    for backend, available in backends.items():
        priority = " (primary)" if backend == "uv" else " (fallback)" if backend == "venv" else ""
        status = "✓ Available" if available else "✗ Not installed"
        click.echo(f"  {backend}{priority}: {status}")

    click.echo("")

    # Docker support (archived)
    docker_available = shutil.which("docker") is not None
    docker_status = "📦 Archived" if docker_available else "📦 Archived (not installed)"
    click.echo(f"🐳 Docker: {docker_status}")
    click.echo("     • Docker-based generation has been archived for future development")
    click.echo("     • See src/sbom_toolkit/pipeline/archived/docker_tools.py")

    click.echo("")

    # Summary
    total_tools = len(available_generators) + len(available_scanners)
    if total_tools == 0:
        click.echo("❌ No tools available! Please install required tools to use the SBOM toolkit.")
        sys.exit(1)
    elif total_tools < 2:  # 1 generator + 1 scanner minimum
        click.echo(f"⚠️  Limited functionality: {total_tools} tools available")
        click.echo("   Consider installing additional tools for full functionality")
    else:
        click.echo(f"✅ Good setup: {total_tools} tools available")
        click.echo("   SBOM toolkit is ready for full operation")

    logger.info(
        f"Tools check completed: {len(available_generators)} generators, {len(available_scanners)} scanners"
    )
