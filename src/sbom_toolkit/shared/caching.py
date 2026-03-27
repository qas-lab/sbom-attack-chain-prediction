"""
Caching utilities for SBOM processing.
"""

import hashlib
from pathlib import Path


class CacheManager:
    """Manages caching for SBOM files and processing results."""

    def __init__(self, cache_dir: Path):
        """Initialize cache manager.

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def compute_cache_key(
        self,
        github_url: str,
        branch: str = "main",
        commit: str | None = None,
        tag: str | None = None,
    ) -> str:
        """Compute a unique cache key for a repo, branch, and commit/tag.

        Args:
            github_url: GitHub repository URL
            branch: Git branch name
            commit: Git commit hash
            tag: Git tag

        Returns:
            SHA256 hash as cache key
        """
        key = f"{github_url}|{branch}|{commit or ''}|{tag or ''}"
        return hashlib.sha256(key.encode()).hexdigest()

    def compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file's contents.

        Args:
            file_path: Path to the file

        Returns:
            SHA256 hash of file contents
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def get_cached_sbom_path(
        self,
        github_url: str,
        branch: str = "main",
        commit: str | None = None,
        tag: str | None = None,
    ) -> Path | None:
        """Return the path to a cached SBOM if it exists.

        Args:
            github_url: GitHub repository URL
            branch: Git branch name
            commit: Git commit hash
            tag: Git tag

        Returns:
            Path to cached SBOM file, or None if not found
        """
        cache_key = self.compute_cache_key(github_url, branch, commit, tag)
        for file in self.cache_dir.glob(f"*_sbom_{cache_key}.json"):
            return file
        return None

    def get_cached_file_by_hash(self, input_path: Path, suffix: str = "_enriched") -> Path | None:
        """Get cached file based on input file content hash.

        Args:
            input_path: Path to input file
            suffix: Suffix to add to cached filename

        Returns:
            Path to cached file, or None if not found
        """
        try:
            input_hash = self.compute_file_hash(input_path)
            cached_filename = f"{input_path.stem}{suffix}_{input_hash}{input_path.suffix}"
            cached_path = self.cache_dir / cached_filename

            if cached_path.exists():
                return cached_path
        except Exception:
            pass

        return None

    def generate_cache_filename(
        self, base_name: str, cache_key: str, extension: str = ".json"
    ) -> Path:
        """Generate a cache filename with the given parameters.

        Args:
            base_name: Base name for the file
            cache_key: Cache key to include in filename
            extension: File extension

        Returns:
            Full path for the cache file
        """
        filename = f"{base_name}_sbom_{cache_key}{extension}"
        return self.cache_dir / filename

    def clean_cache(self, pattern: str = "*"):
        """Clean cache files matching the given pattern.

        Args:
            pattern: Glob pattern for files to delete
        """
        for file in self.cache_dir.glob(pattern):
            try:
                file.unlink()
                print(f"Removed cache file: {file}")
            except Exception as e:
                print(f"Error removing cache file {file}: {e}")

    def cache_exists(self, cache_path: Path) -> bool:
        """Check if a cache file exists.

        Args:
            cache_path: Path to cache file

        Returns:
            True if cache file exists, False otherwise
        """
        return cache_path.exists() and cache_path.is_file()


def cache_key_decorator(cache_manager: CacheManager):
    """Decorator for caching function results based on arguments.

    Args:
        cache_manager: CacheManager instance to use

    Returns:
        Decorator function
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create cache key from function arguments
            key_data = f"{func.__name__}|{args}|{sorted(kwargs.items())}"
            cache_key = hashlib.sha256(key_data.encode()).hexdigest()
            cache_path = cache_manager.cache_dir / f"{func.__name__}_{cache_key}.cache"

            # Check if cached result exists
            if cache_path.exists():
                try:
                    with open(cache_path) as f:
                        import json

                        return json.load(f)
                except Exception:
                    pass  # Fall through to compute result

            # Compute result and cache it
            result = func(*args, **kwargs)
            try:
                with open(cache_path, "w") as f:
                    import json

                    json.dump(result, f)
            except Exception:
                pass  # Ignore cache write errors

            return result

        return wrapper

    return decorator
