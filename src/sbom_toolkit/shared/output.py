"""
Output management and organization for SBOM toolkit.
"""

import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .caching import CacheManager


class OutputManager:
    """Manages organized output structure and caching for SBOM toolkit."""

    def __init__(self, base_output_dir: Path = Path("outputs")):
        """Initialize output manager.

        Args:
            base_output_dir: Base directory for all outputs
        """
        self.base_dir = Path(base_output_dir)
        # Only create base directory, subdirectories created lazily
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Define organized subdirectories (created lazily when needed)
        self.dirs = {
            "sboms": self.base_dir / "sboms",
            "scans": self.base_dir / "scans",
            "visualizations": self.base_dir / "visualizations",
            "models": self.base_dir / "models",
            "evaluations": self.base_dir / "evaluations",
            "knowledge_graphs": self.base_dir / "knowledge_graphs",
            "cache": self.base_dir / ".cache",
        }

        # Initialize integrated cache manager (this will create cache dir when needed)
        self.cache_manager = CacheManager(self.dirs["cache"])

    def _ensure_dir_exists(self, dir_path: Path) -> Path:
        """Ensure directory exists, creating it if necessary.

        Args:
            dir_path: Directory path to ensure exists

        Returns:
            The directory path
        """
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def clean_repo_name(self, github_url: str) -> str:
        """Extract and clean repository name from GitHub URL.

        Args:
            github_url: GitHub repository URL

        Returns:
            Clean repository name suitable for filenames
        """
        try:
            # Handle different GitHub URL formats
            if github_url.startswith("git@"):
                # SSH format: git@github.com:owner/repo.git
                repo_part = github_url.split(":")[1].replace(".git", "")
            else:
                # HTTPS format: https://github.com/owner/repo
                parsed = urlparse(github_url)
                repo_part = parsed.path.strip("/").replace(".git", "")

            # Replace slashes and special chars with underscores
            clean_name = re.sub(r"[^\w\-.]", "_", repo_part)
            return clean_name.lower()
        except Exception:
            # Fallback to timestamp if URL parsing fails
            return f"repo_{int(time.time())}"

    def get_sbom_path(
        self, github_url: str, generator: str = "auto", no_cache: bool = False
    ) -> Path:
        """Get organized path for SBOM file.

        Args:
            github_url: GitHub repository URL
            generator: SBOM generator used
            no_cache: If True, generate consistent filename without timestamp for overwriting

        Returns:
            Path for SBOM file
        """
        repo_name = self.clean_repo_name(github_url)
        if no_cache:
            # Generate consistent filename without timestamp for overwriting
            filename = f"{repo_name}_{generator}.json"
        else:
            # Generate timestamped filename for versioning
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            filename = f"{repo_name}_{generator}_{timestamp}.json"

        # Ensure directory exists before returning path
        self._ensure_dir_exists(self.dirs["sboms"])
        return self.dirs["sboms"] / filename

    def get_scan_path(self, sbom_path: Path, scanner: str = "auto", no_cache: bool = False) -> Path:
        """Get organized path for vulnerability scan results.

        Args:
            sbom_path: Path to original SBOM file
            scanner: Scanner used
            no_cache: If True, generate consistent filename without timestamp for overwriting

        Returns:
            Path for enriched SBOM file
        """
        base_name = sbom_path.stem
        # Remove generator and timestamp from base name if present
        clean_base = re.sub(r"_(auto|syft|cdxgen|cyclonedx|docker)(_\d{8}_\d{4})?$", "", base_name)
        if no_cache:
            # Generate consistent filename without timestamp for overwriting
            filename = f"{clean_base}_{scanner}_scan.json"
        else:
            # Generate timestamped filename for versioning
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            filename = f"{clean_base}_{scanner}_scan_{timestamp}.json"

        # Ensure directory exists before returning path
        self._ensure_dir_exists(self.dirs["scans"])
        return self.dirs["scans"] / filename

    def get_visualization_path(
        self, sbom_path: Path, layout: str = "force-directed", no_cache: bool = False
    ) -> Path:
        """Get organized path for visualization files.

        Args:
            sbom_path: Path to SBOM file
            layout: Visualization layout type
            no_cache: If True, generate consistent filename without timestamp for overwriting

        Returns:
            Path for visualization HTML file
        """
        base_name = sbom_path.stem
        clean_base = re.sub(r"_(auto|syft|cdxgen|cyclonedx|docker)(_\d{8}_\d{4})?$", "", base_name)
        if no_cache:
            # Generate consistent filename without timestamp for overwriting
            filename = f"{clean_base}_{layout}.html"
        else:
            # Generate timestamped filename for versioning
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            filename = f"{clean_base}_{layout}_{timestamp}.html"

        # Ensure directory exists before returning path
        self._ensure_dir_exists(self.dirs["visualizations"])
        return self.dirs["visualizations"] / filename

    def get_kg_path(self, source_name: str, no_cache: bool = False) -> Path:
        """Get organized path for knowledge graph files.

        Args:
            source_name: Name describing the KG source
            no_cache: If True, generate consistent filename without timestamp for overwriting

        Returns:
            Path for knowledge graph file
        """
        clean_name = re.sub(r"[^\w\-.]", "_", source_name.lower())
        if no_cache:
            # Generate consistent filename without timestamp for overwriting
            filename = f"{clean_name}_kg.json"
        else:
            # Generate timestamped filename for versioning
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            filename = f"{clean_name}_kg_{timestamp}.json"

        # Ensure directory exists before returning path
        self._ensure_dir_exists(self.dirs["knowledge_graphs"])
        return self.dirs["knowledge_graphs"] / filename

    def find_cached_sbom(self, github_url: str, max_age_hours: int = 24) -> Path | None:
        """Find recent cached SBOM for a repository.

        Args:
            github_url: GitHub repository URL
            max_age_hours: Maximum age of cache file in hours

        Returns:
            Path to cached SBOM if found, None otherwise
        """
        repo_name = self.clean_repo_name(github_url)
        cutoff_time = time.time() - (max_age_hours * 3600)

        # Only search if directory exists
        if not self.dirs["sboms"].exists():
            return None

        # Look for SBOM files for this repo
        pattern = f"{repo_name}_*_*.json"
        for sbom_path in self.dirs["sboms"].glob(pattern):
            if sbom_path.stat().st_mtime > cutoff_time:
                return sbom_path

        return None

    def get_cached_scan_by_content(self, sbom_path: Path, scanner: str = "osv") -> Path | None:
        """Find cached scan result by matching SBOM content hash.

        Args:
            sbom_path: Path to SBOM file
            scanner: Scanner type used

        Returns:
            Path to cached scan if found, None otherwise
        """
        try:
            # Use CacheManager's built-in file hashing
            return self.cache_manager.get_cached_file_by_hash(sbom_path, f"_{scanner}_scan")
        except Exception:
            return None

    def cache_scan_result(
        self, sbom_path: Path, scan_result_path: Path, scanner: str = "osv"
    ) -> Path | None:
        """Cache a scan result for future use.

        Args:
            sbom_path: Original SBOM file path
            scan_result_path: Path to scan results
            scanner: Scanner type used

        Returns:
            Path to cached file, or None if caching failed
        """
        try:
            import shutil

            # Ensure cache directory exists
            self._ensure_dir_exists(self.cache_manager.cache_dir)

            # Generate cached filename using CacheManager
            input_hash = self.cache_manager.compute_file_hash(sbom_path)
            cached_filename = f"{sbom_path.stem}_{scanner}_scan_{input_hash}.json"
            cached_path = self.cache_manager.cache_dir / cached_filename

            # Copy scan result to cache
            shutil.copy2(scan_result_path, cached_path)
            return cached_path

        except Exception:
            return None

    def clean_old_files(self, max_age_days: int = 30, dry_run: bool = True) -> dict[str, int]:
        """Clean old files from output directories.

        Args:
            max_age_days: Maximum age of files to keep
            dry_run: If True, only report what would be deleted

        Returns:
            Dictionary with cleanup statistics
        """
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        stats = {"deleted": 0, "size_freed": 0, "errors": 0}

        for dir_name, dir_path in self.dirs.items():
            if dir_name == "cache":  # Skip cache directory
                continue

            # Only process directories that exist
            if not dir_path.exists():
                continue

            for file_path in dir_path.glob("*"):
                if file_path.is_file():
                    try:
                        if file_path.stat().st_mtime < cutoff_time:
                            file_size = file_path.stat().st_size
                            if not dry_run:
                                file_path.unlink()
                            stats["deleted"] += 1
                            stats["size_freed"] += file_size
                    except Exception:
                        stats["errors"] += 1

        return stats

    def get_status(self) -> dict[str, Any]:
        """Get status information about output directories.

        Returns:
            Dictionary with status information
        """
        directories: dict[str, dict[str, Any]] = {}
        status: dict[str, Any] = {
            "base_dir": str(self.base_dir),
            "directories": directories,
            "cache_dir": str(self.cache_manager.cache_dir),
        }

        for dir_name, dir_path in self.dirs.items():
            if dir_path.exists():
                files = list(dir_path.glob("*"))
                total_size = sum(f.stat().st_size for f in files if f.is_file())
                directories[dir_name] = {
                    "path": str(dir_path),
                    "file_count": len([f for f in files if f.is_file()]),
                    "total_size": total_size,
                    "exists": True,
                }
            else:
                directories[dir_name] = {
                    "path": str(dir_path),
                    "file_count": 0,
                    "total_size": 0,
                    "exists": False,
                }

        return status


# Global instance for backwards compatibility
output_manager = OutputManager()
