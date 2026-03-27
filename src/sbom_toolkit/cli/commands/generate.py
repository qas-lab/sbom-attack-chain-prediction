"""
Generate command for SBOM toolkit CLI.
"""

import sys
from pathlib import Path

from ...pipeline.repository import DownloadMethod
from ...pipeline.sbom.generation import SBOMProcessor
from ...shared.exceptions import SBOMToolkitError
from ...shared.models import ProcessingConfig
from ..utils import get_cli_flags, get_click

click, CLICK_AVAILABLE = get_click()


@click.command()
@click.argument("repository_url")
@click.option("--output-dir", "-o", default="outputs", help="Output directory for SBOM files")
@click.option("--no-repo-cache", is_flag=True, help="Disable repository caching")
@click.option(
    "--download-method",
    "-d",
    type=click.Choice(["shallow_clone", "tarball", "sparse_checkout", "full_clone"]),
    default="shallow_clone",
    help="Repository download method for optimization",
)
@click.option(
    "--generator",
    "-g",
    type=click.Choice(["syft", "cdxgen"]),
    help="Preferred SBOM generator",
    default="syft",
)
@click.option(
    "--env-backend",
    "-e",
    type=click.Choice(["uv", "venv", "auto"]),
    default="auto",
    help="Environment backend to use for dependency analysis",
)
@click.option("--no-cache", is_flag=True, help="Disable SBOM caching")
@click.pass_context
def generate(
    ctx,
    repository_url,
    output_dir,
    no_repo_cache,
    download_method,
    generator,
    env_backend,
    no_cache,
):
    """Generate SBOM for a GitHub repository with optimization options.

    REPOSITORY_URL: GitHub repository URL to analyze

    Download methods:
    - shallow_clone: Fast clone with depth=1 (default, 70-90% faster)
    - tarball: Download as zip/tar from GitHub API (fastest for large repos)
    - sparse_checkout: Download only files needed for SBOM generation
    - full_clone: Full git clone with history (slowest, most complete)

    Examples:

    Fast analysis with shallow clone:
    sbom generate https://github.com/django/django

    Fastest for large repos:
    sbom generate https://github.com/django/django --download-method tarball

    Minimal download for huge repos:
    sbom generate https://github.com/django/django --download-method sparse_checkout
    """
    logger = ctx.obj["logger"]

    # Get global no_cache flag and combine with local
    cli_flags = get_cli_flags(ctx)
    global_no_cache = cli_flags.get("no_cache", False)
    effective_no_cache = no_cache or global_no_cache

    try:
        # Setup configuration
        config = ProcessingConfig(output_dir=Path(output_dir), cache_enabled=not effective_no_cache)

        # Convert download method string to enum
        download_method_enum = DownloadMethod(download_method)

        # Process repository with optimizations
        env_backend_arg = None if env_backend == "auto" else env_backend
        with SBOMProcessor(
            config,
            preferred_env_backend=env_backend_arg,
            download_method=download_method_enum,
            repo_cache_enabled=not no_repo_cache,
        ) as processor:
            # Set preferred generator if specified
            if generator:
                processor.preferred_generator = generator

            result = processor.process_repository(repository_url)
            logger.info(f"✓ SBOM generated successfully: {result}")

    except SBOMToolkitError as e:
        logger.error(f"✗ SBOM generation failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"✗ Unexpected error: {e}")
        sys.exit(1)


# Add compatibility for non-click environments
def generate_main(repository_url: str, output_dir: str = "outputs", **kwargs):
    """Main function for generate command (non-click version)."""
    from ...shared.logging import setup_logging

    logger = setup_logging("INFO")

    try:
        # Setup configuration
        config = ProcessingConfig(
            output_dir=Path(output_dir), cache_enabled=not kwargs.get("no_cache", False)
        )

        # Get options
        download_method = DownloadMethod(kwargs.get("download_method", "shallow_clone"))
        env_backend = kwargs.get("env_backend", "auto")
        env_backend_arg = None if env_backend == "auto" else env_backend

        # Process repository
        with SBOMProcessor(
            config,
            preferred_env_backend=env_backend_arg,
            download_method=download_method,
            repo_cache_enabled=not kwargs.get("no_repo_cache", False),
        ) as processor:
            if kwargs.get("generator"):
                processor.preferred_generator = kwargs["generator"]

            result = processor.process_repository(repository_url)
            logger.info(f"✓ SBOM generated successfully: {result}")
            return result

    except SBOMToolkitError as e:
        logger.error(f"✗ SBOM generation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"✗ Unexpected error: {e}")
        raise
