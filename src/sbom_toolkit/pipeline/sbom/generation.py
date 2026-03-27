"""
Simplified SBOM generation using modular functions.
"""

import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ...shared.caching import CacheManager
from ...shared.exceptions import (
    EnvironmentError,
    ProcessingError,
    RepositoryError,
    SBOMError,
    SBOMToolkitError,
    create_error_context,
)
from ...shared.logging import setup_logging
from ...shared.models import ProcessingConfig, RepositoryOptimizationLevel
from ...shared.output import output_manager
from ..environment import cleanup_environment, install_dependencies, setup_environment
from ..repository import DownloadMethod, RepositoryHandler
from ..tools import generate_sbom


class SBOMProcessor:
    """Simplified SBOM processing orchestrator with repository optimization support."""

    def __init__(
        self,
        config: ProcessingConfig | None = None,
        preferred_env_backend: str | None = None,
        download_method: DownloadMethod | None = None,
        repo_cache_enabled: bool | None = None,
        optimization_level: RepositoryOptimizationLevel | None = None,
    ):
        """Initialize SBOM processor.

        Args:
            config: Processing configuration, defaults to basic config
            preferred_env_backend: Preferred environment backend ('conda', 'uv', 'venv', or None for auto-select)
            download_method: Repository download method for optimization (overrides optimization_level)
            repo_cache_enabled: Whether to enable repository caching (overrides optimization_level)
            optimization_level: Preset optimization level (overrides config if provided)
        """
        self.config = config or ProcessingConfig(output_dir=output_manager.base_dir)
        self.config.output_dir.mkdir(exist_ok=True)
        self.preferred_env_backend = preferred_env_backend
        self.preferred_generator = None

        # Apply optimization level or use individual settings
        if optimization_level:
            self.download_method, self.repo_cache_enabled = self._get_optimization_settings(
                optimization_level
            )
        else:
            self.download_method, self.repo_cache_enabled = self._get_optimization_settings(
                self.config.repo_optimization_level
            )

        # Override with explicit parameters if provided
        if download_method is not None:
            self.download_method = download_method
        if repo_cache_enabled is not None:
            self.repo_cache_enabled = repo_cache_enabled

        # Setup logging
        self.logger = setup_logging("INFO")

        # Initialize components
        self.temp_dir = Path(tempfile.mkdtemp(prefix=self.config.temp_dir_prefix))
        self.repository_handler = RepositoryHandler(
            self.temp_dir,
            download_method=self.download_method,
            cache_enabled=self.repo_cache_enabled,
        )
        self.cache_manager = CacheManager(self.config.output_dir)

        self.logger.debug(f"Initialized SBOM processor with output dir: {self.config.output_dir}")
        self.logger.debug(f"Repository download method: {self.download_method.value}")
        self.logger.debug(
            f"Repository caching: {'enabled' if self.repo_cache_enabled else 'disabled'}"
        )

    def _get_optimization_settings(
        self, level: RepositoryOptimizationLevel
    ) -> tuple[DownloadMethod, bool]:
        """Get download method and caching settings for optimization level."""
        if level == RepositoryOptimizationLevel.FASTEST:
            return DownloadMethod.TARBALL, False
        elif level == RepositoryOptimizationLevel.MINIMAL:
            return DownloadMethod.SPARSE_CHECKOUT, True
        elif level == RepositoryOptimizationLevel.COMPLETE:
            return DownloadMethod.FULL_CLONE, False
        else:  # BALANCED (default)
            return DownloadMethod.SHALLOW_CLONE, True

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp directory."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.logger.debug(f"Cleaned up temp directory: {self.temp_dir}")

    def process_repository(self, github_url: str) -> Path:
        """Process a repository and generate SBOM.

        Args:
            github_url: GitHub repository URL

        Returns:
            Path to generated SBOM file

        Raises:
            RepositoryError: If repository operations fail
            EnvironmentError: If environment setup fails
            SBOMError: If SBOM generation fails
            ProcessingError: If general processing fails
        """
        context = create_error_context(repository_url=github_url, operation="process_repository")

        self.logger.info(f"Processing repository: {github_url}")

        repo_info = None
        env_name = None

        try:
            # Clone repository
            repo_info = self.repository_handler.clone_repository(github_url)
            context["repo_name"] = repo_info.metadata.name

            # Check cache first
            if self.config.cache_enabled:
                cached_sbom = output_manager.find_cached_sbom(github_url, max_age_hours=24)
                if cached_sbom:
                    self.logger.debug(f"Found cached SBOM: {cached_sbom}")
                    return cached_sbom

            # Setup environment
            env_name = f"{self.config.conda_env_prefix}{repo_info.path.name}"
            context["env_name"] = env_name

            try:
                python_path, _ = setup_environment(
                    repo_info.path,
                    preferred_backend=self.preferred_env_backend,
                    env_name=env_name,
                )
                context["python_path"] = python_path
            except Exception as e:
                raise EnvironmentError(
                    f"Failed to setup environment for {repo_info.metadata.name}",
                    context,
                ) from e

            # Install dependencies with fallback strategy
            install_success = False

            # Docker generation has been archived

            # Try dependency installation
            try:
                install_success = install_dependencies(repo_info.path, python_path)
                if not install_success:
                    self.logger.warning("⚠️  Some dependencies failed to install")
            except Exception as e:
                self.logger.warning(f"Dependency installation failed: {e}")
                install_success = False

            # Generate SBOM
            try:
                generator_name = self.preferred_generator or "syft"
                organized_path = output_manager.get_sbom_path(
                    github_url, generator_name, no_cache=not self.config.cache_enabled
                )

                sbom_path = generate_sbom(
                    repo_info, organized_path.parent, generator=self.preferred_generator
                )

                if sbom_path and sbom_path != organized_path and sbom_path.exists():
                    shutil.move(sbom_path, organized_path)
                    sbom_path = organized_path

                if sbom_path:
                    self.logger.info(f"✓ SBOM generation successful: {sbom_path}")
                    if not install_success:
                        self.logger.warning(
                            "⚠️  SBOM generated without full dependency installation - may be incomplete"
                        )
                    return sbom_path
                else:
                    raise SBOMError(
                        f"SBOM generation returned None for {repo_info.metadata.name}",
                        context,
                    )

            except Exception as e:
                raise SBOMError(
                    f"SBOM generation failed for {repo_info.metadata.name}: {str(e)}",
                    context,
                ) from e

        except (SBOMToolkitError, RepositoryError, EnvironmentError, SBOMError):
            raise
        except Exception as e:
            raise ProcessingError(
                f"Unexpected error processing {github_url}: {str(e)}", context
            ) from e
        finally:
            # Cleanup environment
            if env_name:
                try:
                    cleanup_environment(env_name)
                except Exception as e:
                    self.logger.debug(f"Environment cleanup failed: {e}")

            # Cleanup repository
            if repo_info:
                try:
                    self.repository_handler.cleanup(repo_info)
                except Exception as e:
                    self.logger.debug(f"Repository cleanup failed: {e}")

    def clone_repository(self, github_url: str) -> Path:
        """Clone repository and return path (legacy interface).

        Args:
            github_url: GitHub repository URL

        Returns:
            Path to cloned repository
        """
        repo_info = self.repository_handler.clone_repository(github_url)
        return repo_info.path

    def process_repositories_parallel(
        self,
        repository_urls: list[str],
        max_workers: int | None = None,
    ) -> dict[str, Path | str]:
        """Process multiple repositories in parallel using Python 3.13 free-threading.

        This method leverages free-threading to process multiple SBOM generations
        concurrently, providing significant speedup for batch operations.

        Args:
            repository_urls: List of GitHub repository URLs to process
            max_workers: Maximum number of worker threads (default: auto-detect)

        Returns:
            Dictionary mapping repository URL to SBOM path (success) or error message (failure)
        """
        # Check if free-threading is available
        if sys._is_gil_enabled() or len(repository_urls) <= 1:
            # Fall back to sequential processing
            self.logger.debug("Using sequential processing (GIL enabled or single repository)")
            results = {}
            for url in repository_urls:
                try:
                    sbom_path = self.process_repository(url)
                    results[url] = sbom_path
                except Exception as e:
                    results[url] = f"Error: {str(e)}"
            return results

        self.logger.info(
            f"🚀 Using parallel SBOM generation for {len(repository_urls)} repositories"
        )

        # Determine optimal worker count
        if max_workers is None:
            # Balance between parallelism and resource usage
            max_workers = min(4, len(repository_urls))

        results = {}

        def process_single_repo(url: str) -> tuple[str, Path | str]:
            """Process a single repository and return result."""
            try:
                # Each worker needs its own temp directory
                temp_dir = Path(tempfile.mkdtemp(prefix=self.config.temp_dir_prefix))

                # Create a new repository handler for this worker
                repo_handler = RepositoryHandler(
                    temp_dir,
                    download_method=self.download_method,
                    cache_enabled=self.repo_cache_enabled,
                )

                # Store original handler and temp_dir
                original_handler = self.repository_handler
                original_temp = self.temp_dir

                # Temporarily use worker's handler
                self.repository_handler = repo_handler
                self.temp_dir = temp_dir

                try:
                    # Process the repository
                    sbom_path = self.process_repository(url)
                    return url, sbom_path
                finally:
                    # Restore original handler
                    self.repository_handler = original_handler
                    self.temp_dir = original_temp

                    # Clean up worker's temp directory
                    if temp_dir.exists():
                        shutil.rmtree(temp_dir, ignore_errors=True)

            except Exception as e:
                self.logger.error(f"Failed to process {url}: {e}")
                return url, f"Error: {str(e)}"

        # Process repositories in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_url = {
                executor.submit(process_single_repo, url): url for url in repository_urls
            }

            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_url):
                completed += 1
                try:
                    url, result = future.result()
                    results[url] = result

                    if isinstance(result, Path):
                        self.logger.info(
                            f"✓ [{completed}/{len(repository_urls)}] Generated SBOM for {url}: {result}"
                        )
                    else:
                        self.logger.error(
                            f"✗ [{completed}/{len(repository_urls)}] Failed for {url}: {result}"
                        )

                except Exception as e:
                    url = future_to_url[future]
                    results[url] = f"Error: Unexpected exception: {str(e)}"
                    self.logger.error(
                        f"✗ [{completed}/{len(repository_urls)}] Exception for {url}: {e}"
                    )

        # Summary
        successful = sum(1 for r in results.values() if isinstance(r, Path))
        self.logger.info(
            f"\n🎯 Batch processing complete: {successful}/{len(repository_urls)} successful"
        )

        return results

    def process_repositories_with_progress(
        self,
        repository_urls: list[str],
        callback=None,
        max_workers: int | None = None,
    ) -> dict[str, Path | str]:
        """Process multiple repositories with progress callback support.

        Args:
            repository_urls: List of GitHub repository URLs to process
            callback: Optional callback function(url, status, result) called on completion
            max_workers: Maximum number of worker threads

        Returns:
            Dictionary mapping repository URL to SBOM path or error message
        """
        results = self.process_repositories_parallel(repository_urls, max_workers)

        # Call progress callbacks if provided
        if callback:
            for url, result in results.items():
                status = "success" if isinstance(result, Path) else "error"
                callback(url, status, result)

        return results


def main():
    """Main entry point for direct execution."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Generate SBOM for a GitHub repository")
    parser.add_argument("repository_url", help="GitHub repository URL")
    parser.add_argument("--output-dir", "-o", default="outputs", help="Output directory")
    parser.add_argument(
        "--generator",
        "-g",
        choices=["syft", "cdxgen"],
        help="Preferred SBOM generator",
    )
    parser.add_argument(
        "--env-backend",
        "-e",
        choices=["uv", "venv"],
        help="Environment backend",
    )

    args = parser.parse_args()

    try:
        config = ProcessingConfig(output_dir=Path(args.output_dir))

        with SBOMProcessor(config, preferred_env_backend=args.env_backend) as processor:
            if args.generator:
                processor.preferred_generator = args.generator

            result = processor.process_repository(args.repository_url)
            print(f"✓ SBOM generated successfully: {result}")

    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
