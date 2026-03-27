"""
Repository handling module for cloning and managing GitHub repositories.
"""

import logging
import os
import shutil
import subprocess
import tarfile
import time
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

import requests

from ..shared.exceptions import (
    InvalidRepositoryURLError,
    RepositoryCloneError,
    RepositoryNotFoundError,
    create_error_context,
    wrap_external_error,
)
from ..shared.models import RepositoryInfo, RepositoryMetadata


class DownloadMethod(str, Enum):
    """Available repository download methods."""

    FULL_CLONE = "full_clone"
    SHALLOW_CLONE = "shallow_clone"
    TARBALL = "tarball"
    SPARSE_CHECKOUT = "sparse_checkout"


class RepositoryHandler:
    """Handles repository cloning and metadata extraction with optimization support."""

    def __init__(
        self,
        temp_dir: Path,
        download_method: DownloadMethod = DownloadMethod.SHALLOW_CLONE,
        cache_enabled: bool = True,
    ):
        """Initialize repository handler with temporary directory and download method.

        Args:
            temp_dir: Temporary directory for cloning repositories
            download_method: Method to use for downloading repositories
            cache_enabled: Whether to enable repository caching

        Raises:
            RepositoryCloneError: If temp directory cannot be created
        """
        self.temp_dir = temp_dir
        self.download_method = download_method
        self.cache_enabled = cache_enabled
        self.logger = logging.getLogger(__name__)

        # Cache directory for repositories
        self.cache_dir = temp_dir.parent / "repo_cache"
        if self.cache_enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Define file patterns needed for comprehensive SBOM generation
        self.sbom_required_patterns = [
            # Python dependency files
            "requirements*.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
            "pdm.lock",
            # Configuration files
            "tox.ini",
            "noxfile.py",
            "pytest.ini",
            "mypy.ini",
            ".python-version",
            # Source code (essential for analysis)
            "*.py",
            "**/*.py",
            # Package metadata
            "MANIFEST.in",
            "*.cfg",
            "*.ini",
            # Documentation that might contain version info
            "README*",
            "CHANGELOG*",
            "VERSION*",
            # CI/CD files that might have dependency info
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            ".gitlab-ci.yml",
            "azure-pipelines.yml",
            # Docker files
            "Dockerfile*",
            "docker-compose*.yml",
            "docker-compose*.yaml",
            # JavaScript/Node.js files (for mixed projects)
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            # Other common dependency files
            "Gemfile",
            "Gemfile.lock",
            "go.mod",
            "go.sum",
            "pom.xml",
            "build.gradle",
            "Cargo.toml",
            "Cargo.lock",
        ]

        try:
            self.temp_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise RepositoryCloneError(
                f"Failed to create temporary directory: {temp_dir}",
                create_error_context(temp_dir=str(temp_dir), operation="mkdir"),
            ) from e

    def clone_repository(
        self, github_url: str, method: DownloadMethod | None = None
    ) -> RepositoryInfo:
        """Clone a GitHub repository using the specified or default method.

        Args:
            github_url: GitHub repository URL
            method: Optional override for download method

        Returns:
            RepositoryInfo with cloned repository information

        Raises:
            InvalidRepositoryURLError: If URL format is invalid
            RepositoryCloneError: If cloning fails
            RepositoryNotFoundError: If repository doesn't exist
        """
        # Use provided method or default
        download_method = method or self.download_method

        # Check cache first if enabled
        if self.cache_enabled:
            cached_repo = self._get_cached_repository(github_url)
            if cached_repo:
                self.logger.info(f"Using cached repository: {cached_repo.path}")
                return cached_repo

        # Validate URL format
        self._validate_github_url(github_url)

        # Extract repo name from URL
        repo_name = github_url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        repo_path = self.temp_dir / repo_name
        context = create_error_context(
            repository_url=github_url,
            repo_name=repo_name,
            operation=f"repository_download_{download_method.value}",
        )

        # Remove existing directory if it exists
        if repo_path.exists():
            try:
                self._remove_readonly_directory(repo_path)
            except Exception as e:
                self.logger.warning(f"Could not remove existing directory: {e}")
                # Generate a unique name
                repo_path = self.temp_dir / f"{repo_name}_{int(time.time())}"
                context["repo_path"] = str(repo_path)

        # Choose download method
        if download_method == DownloadMethod.TARBALL:
            self.logger.info(f"Downloading {github_url} as tarball into {repo_path}...")
            repo_info = self._download_tarball(github_url, repo_path, context)
        elif download_method == DownloadMethod.SHALLOW_CLONE:
            self.logger.info(f"Shallow cloning {github_url} into {repo_path}...")
            repo_info = self._shallow_clone(github_url, repo_path, context)
        elif download_method == DownloadMethod.SPARSE_CHECKOUT:
            self.logger.info(f"Sparse checkout of {github_url} into {repo_path}...")
            repo_info = self._sparse_checkout(github_url, repo_path, context)
        else:  # FULL_CLONE
            self.logger.info(f"Full cloning {github_url} into {repo_path}...")
            repo_info = self._full_clone(github_url, repo_path, context)

        # Cache the repository if enabled
        if self.cache_enabled:
            self._cache_repository(repo_info)

        return repo_info

    def _download_tarball(self, github_url: str, repo_path: Path, context: dict) -> RepositoryInfo:
        """Download repository as tarball from GitHub API."""
        try:
            # Extract owner and repo from URL
            parsed_url = urlparse(github_url)
            path_parts = parsed_url.path.strip("/").split("/")
            owner = path_parts[0]
            repo_name = path_parts[1].replace(".git", "")

            # GitHub API endpoint for tarball
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/tarball"

            # Download with timeout
            response = requests.get(api_url, timeout=300, stream=True)
            response.raise_for_status()

            # Extract tarball
            with tarfile.open(fileobj=response.raw, mode="r|gz") as tar:
                tar.extractall(path=repo_path.parent)

            # GitHub tarballs extract to a directory with commit hash
            extracted_dirs = list(repo_path.parent.glob(f"{owner}-{repo_name}-*"))
            if extracted_dirs:
                # Rename to expected directory name
                extracted_dirs[0].rename(repo_path)

            # Get commit hash from directory name for metadata
            commit_hash = extracted_dirs[0].name.split("-")[-1] if extracted_dirs else None

            # Create metadata
            metadata = RepositoryMetadata(
                url=github_url,
                owner=owner,
                name=repo_name,
                branch="main",
                commit_hash=commit_hash,
                latest_tag=None,
            )

            return RepositoryInfo(path=repo_path, metadata=metadata, method="tarball")

        except requests.RequestException as e:
            raise RepositoryCloneError(f"Failed to download tarball: {str(e)}", context) from e
        except Exception as e:
            raise RepositoryCloneError(f"Failed to extract tarball: {str(e)}", context) from e

    def _shallow_clone(self, github_url: str, repo_path: Path, context: dict) -> RepositoryInfo:
        """Perform shallow clone with depth 1."""
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", github_url, str(repo_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Extract repository metadata
            metadata = self._extract_repo_metadata(github_url, repo_path)
            return RepositoryInfo(path=repo_path, metadata=metadata, method="shallow_clone")

        except subprocess.CalledProcessError as e:
            if "not found" in e.stderr.lower() or "does not exist" in e.stderr.lower():
                raise RepositoryNotFoundError(f"Repository not found: {github_url}", context) from e
            else:
                raise RepositoryCloneError(
                    f"Failed to shallow clone repository: {e.stderr}", context
                ) from e
        except subprocess.TimeoutExpired as e:
            raise RepositoryCloneError(
                f"Shallow clone operation timed out for repository: {github_url}", context
            ) from e
        except Exception as e:
            raise wrap_external_error(e, context) from e

    def _sparse_checkout(self, github_url: str, repo_path: Path, context: dict) -> RepositoryInfo:
        """Perform sparse checkout with only necessary files for SBOM generation."""
        try:
            # Create the repository directory first
            repo_path.mkdir(parents=True, exist_ok=True)

            # Initialize repository
            subprocess.run(
                ["git", "init"], cwd=repo_path, check=True, capture_output=True, text=True
            )

            # Add remote
            subprocess.run(
                ["git", "remote", "add", "origin", github_url],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
            )

            # Configure sparse checkout
            subprocess.run(
                ["git", "config", "core.sparseCheckout", "true"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
            )

            # Write sparse checkout patterns
            sparse_checkout_file = repo_path / ".git" / "info" / "sparse-checkout"
            sparse_checkout_file.parent.mkdir(parents=True, exist_ok=True)

            with open(sparse_checkout_file, "w") as f:
                for pattern in self.sbom_required_patterns:
                    f.write(f"{pattern}\n")

            # Try to pull from main branch first, then master
            default_branch = "main"
            try:
                subprocess.run(
                    ["git", "pull", "--depth=1", "origin", "main"],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            except subprocess.CalledProcessError:
                # Try master branch if main fails
                default_branch = "master"
                subprocess.run(
                    ["git", "pull", "--depth=1", "origin", "master"],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

            # Extract repository metadata
            metadata = self._extract_repo_metadata(github_url, repo_path)
            metadata.branch = default_branch
            return RepositoryInfo(path=repo_path, metadata=metadata, method="sparse_checkout")

        except subprocess.CalledProcessError as e:
            if "not found" in e.stderr.lower() or "does not exist" in e.stderr.lower():
                raise RepositoryNotFoundError(f"Repository not found: {github_url}", context) from e
            else:
                raise RepositoryCloneError(
                    f"Failed to sparse checkout repository: {e.stderr}", context
                ) from e
        except subprocess.TimeoutExpired as e:
            raise RepositoryCloneError(
                f"Sparse checkout operation timed out for repository: {github_url}", context
            ) from e
        except Exception as e:
            raise wrap_external_error(e, context) from e

    def _full_clone(self, github_url: str, repo_path: Path, context: dict) -> RepositoryInfo:
        """Perform full clone (original implementation)."""
        try:
            subprocess.run(
                ["git", "clone", github_url, str(repo_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Extract repository metadata
            metadata = self._extract_repo_metadata(github_url, repo_path)
            return RepositoryInfo(path=repo_path, metadata=metadata, method="full_clone")

        except subprocess.CalledProcessError as e:
            if "not found" in e.stderr.lower() or "does not exist" in e.stderr.lower():
                raise RepositoryNotFoundError(f"Repository not found: {github_url}", context) from e
            else:
                raise RepositoryCloneError(
                    f"Failed to clone repository: {e.stderr}", context
                ) from e
        except subprocess.TimeoutExpired as e:
            raise RepositoryCloneError(
                f"Clone operation timed out for repository: {github_url}", context
            ) from e
        except Exception as e:
            raise wrap_external_error(e, context) from e

    def _validate_github_url(self, url: str) -> None:
        """Validate GitHub URL format.

        Args:
            url: URL to validate

        Raises:
            InvalidRepositoryURLError: If URL is invalid
        """
        try:
            parsed = urlparse(url)
            if not parsed.netloc or parsed.netloc not in [
                "github.com",
                "www.github.com",
            ]:
                raise InvalidRepositoryURLError(
                    f"Only GitHub repositories are supported: {url}",
                    create_error_context(repository_url=url),
                )

            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) < 2:
                raise InvalidRepositoryURLError(
                    f"Invalid GitHub repository URL format: {url}",
                    create_error_context(repository_url=url),
                )
        except Exception as e:
            if isinstance(e, InvalidRepositoryURLError):
                raise
            raise InvalidRepositoryURLError(
                f"Invalid URL format: {url}", create_error_context(repository_url=url)
            ) from e

    def _remove_readonly_directory(self, path: Path) -> None:
        """Remove directory with read-only files.

        Args:
            path: Directory path to remove
        """
        for root, dirs, files in os.walk(str(path), topdown=False):
            for name in files:
                file_path = Path(root) / name
                file_path.chmod(0o666)
            for name in dirs:
                dir_path = Path(root) / name
                dir_path.chmod(0o777)

        shutil.rmtree(path)

    def _extract_repo_metadata(self, github_url: str, repo_path: Path) -> RepositoryMetadata:
        """Extract metadata about the repository.

        Args:
            github_url: GitHub repository URL
            repo_path: Local path to the repository

        Returns:
            RepositoryMetadata with extracted information
        """
        parsed_url = urlparse(github_url)
        path_parts = parsed_url.path.strip("/").split("/")

        # Get the owner and repo name
        owner = path_parts[-2] if len(path_parts) > 1 else "unknown"
        repo_name = path_parts[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        # Initialize commit and tag as None
        commit_hash = None
        latest_tag = None

        # Only try to get git info if it's a git repository
        if (repo_path / ".git").exists():
            try:
                # Get the current commit hash
                result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                commit_hash = result.stdout.strip()

                # Get the latest tag if it exists
                try:
                    result = subprocess.run(
                        ["git", "describe", "--tags", "--abbrev=0"],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    latest_tag = result.stdout.strip()
                except subprocess.CalledProcessError:
                    latest_tag = None
            except subprocess.CalledProcessError:
                # If git commands fail, use default values
                pass

        return RepositoryMetadata(
            url=github_url,
            owner=owner,
            name=repo_name,
            branch="main",  # Default branch
            commit_hash=commit_hash,
            latest_tag=latest_tag,
        )

    def _get_cached_repository(self, github_url: str) -> RepositoryInfo | None:
        """Get cached repository if available and valid."""
        try:
            # Get latest commit hash from GitHub API
            latest_commit = self._get_latest_commit_hash(github_url)
            if not latest_commit:
                return None

            # Extract repo name
            repo_name = github_url.rstrip("/").split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]

            # Check for cached repository with this commit
            cached_repo_path = self.cache_dir / f"{repo_name}_{latest_commit}"
            if cached_repo_path.exists():
                # Copy cached repository to temp directory
                temp_repo_path = self.temp_dir / repo_name
                if temp_repo_path.exists():
                    self._remove_readonly_directory(temp_repo_path)

                shutil.copytree(cached_repo_path, temp_repo_path)

                # Create metadata
                parsed_url = urlparse(github_url)
                path_parts = parsed_url.path.strip("/").split("/")
                owner = path_parts[0]

                metadata = RepositoryMetadata(
                    url=github_url,
                    owner=owner,
                    name=repo_name,
                    branch="main",
                    commit_hash=latest_commit,
                    latest_tag=None,
                )

                return RepositoryInfo(path=temp_repo_path, metadata=metadata, method="cached")

        except Exception as e:
            self.logger.debug(f"Cache lookup failed: {e}")
            return None

        return None

    def _cache_repository(self, repo_info: RepositoryInfo) -> None:
        """Cache repository for future use."""
        try:
            if not repo_info.metadata.commit_hash:
                return

            # Create cache path based on repo name and commit hash
            cache_path = (
                self.cache_dir / f"{repo_info.metadata.name}_{repo_info.metadata.commit_hash}"
            )

            # Remove existing cache if it exists
            if cache_path.exists():
                self._remove_readonly_directory(cache_path)

            # Copy repository to cache
            shutil.copytree(repo_info.path, cache_path)

            # Clean up old cached versions (keep only the latest 5)
            self._cleanup_old_cache_entries(repo_info.metadata.name)

            self.logger.debug(f"Cached repository: {cache_path}")

        except Exception as e:
            self.logger.debug(f"Failed to cache repository: {e}")

    def _cleanup_old_cache_entries(self, repo_name: str) -> None:
        """Clean up old cached versions of a repository."""
        try:
            # Find all cached versions of this repository
            cached_versions = list(self.cache_dir.glob(f"{repo_name}_*"))

            # Sort by modification time (newest first)
            cached_versions.sort(key=lambda p: p.stat().st_mtime, reverse=True)

            # Remove old versions (keep only the latest 5)
            for old_cache in cached_versions[5:]:
                self._remove_readonly_directory(old_cache)
                self.logger.debug(f"Removed old cache: {old_cache}")

        except Exception as e:
            self.logger.debug(f"Failed to cleanup old cache entries: {e}")

    def _get_latest_commit_hash(self, github_url: str) -> str | None:
        """Get the latest commit hash from GitHub API."""
        try:
            # Extract owner and repo from URL
            parsed_url = urlparse(github_url)
            path_parts = parsed_url.path.strip("/").split("/")
            owner = path_parts[0]
            repo_name = path_parts[1].replace(".git", "")

            # GitHub API endpoint for latest commit
            api_url = f"https://api.github.com/repos/{owner}/{repo_name}/commits/HEAD"

            response = requests.get(api_url, timeout=10)
            response.raise_for_status()

            commit_data = response.json()
            return commit_data.get("sha")

        except Exception as e:
            self.logger.debug(f"Failed to get latest commit hash: {e}")
            return None

    def cleanup(self, repo_info: RepositoryInfo):
        """Clean up repository directory.

        Args:
            repo_info: Repository information with path to clean up
        """
        if repo_info.path and repo_info.path.exists():
            print(f"Cleaning up temporary directory: {repo_info.path}")
            shutil.rmtree(repo_info.path, ignore_errors=True)
