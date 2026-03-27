"""
Tests for caching utilities.
"""

from pathlib import Path

from sbom_toolkit.shared.caching import CacheManager


class TestCacheManager:
    """Tests for CacheManager class."""

    def test_initialization(self, temp_dir: Path) -> None:
        """Test cache manager creates directory."""
        cache_dir = temp_dir / "cache"
        manager = CacheManager(cache_dir)
        assert cache_dir.exists()
        assert manager.cache_dir == cache_dir

    def test_compute_cache_key(self, temp_dir: Path) -> None:
        """Test cache key computation is deterministic."""
        manager = CacheManager(temp_dir)
        key1 = manager.compute_cache_key("https://github.com/test/repo", "main")
        key2 = manager.compute_cache_key("https://github.com/test/repo", "main")
        assert key1 == key2
        assert len(key1) == 64  # SHA256 hex digest

    def test_different_urls_different_keys(self, temp_dir: Path) -> None:
        """Test different URLs produce different keys."""
        manager = CacheManager(temp_dir)
        key1 = manager.compute_cache_key("https://github.com/test/repo1")
        key2 = manager.compute_cache_key("https://github.com/test/repo2")
        assert key1 != key2

    def test_compute_file_hash(self, temp_dir: Path) -> None:
        """Test file hash computation."""
        manager = CacheManager(temp_dir)
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        hash1 = manager.compute_file_hash(test_file)
        hash2 = manager.compute_file_hash(test_file)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_generate_cache_filename(self, temp_dir: Path) -> None:
        """Test cache filename generation."""
        manager = CacheManager(temp_dir)
        path = manager.generate_cache_filename("myproject", "abc123", ".json")
        assert path.name == "myproject_sbom_abc123.json"
        assert path.parent == temp_dir

    def test_cache_exists(self, temp_dir: Path) -> None:
        """Test cache existence check."""
        manager = CacheManager(temp_dir)
        cache_file = temp_dir / "test_cache.json"

        assert not manager.cache_exists(cache_file)
        cache_file.write_text("{}")
        assert manager.cache_exists(cache_file)

    def test_get_cached_sbom_path_not_found(self, temp_dir: Path) -> None:
        """Test getting cached SBOM when none exists."""
        manager = CacheManager(temp_dir)
        result = manager.get_cached_sbom_path("https://github.com/test/repo")
        assert result is None
