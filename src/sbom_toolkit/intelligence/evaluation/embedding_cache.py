"""
Embedding cache system for RAG systems to avoid expensive re-computation.

This module provides persistent caching of embeddings generated from knowledge graph data,
using content-based hashing to detect changes and invalidate cache when needed.
"""

import hashlib
import json
import pickle
import tempfile
import threading
from pathlib import Path
from typing import Any

import numpy as np


class EmbeddingCache:
    """Manages persistent caching of embeddings for RAG systems."""

    def __init__(self, cache_dir: Path | None = None, cache_enabled: bool = True):
        self.cache_enabled = cache_enabled and cache_dir is not None
        if self.cache_enabled and cache_dir is not None:
            # Create embeddings subdirectory under the main cache dir
            self.cache_dir = cache_dir / "embeddings"
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.cache_dir = None

        # Thread-safe cache operations
        self._cache_lock = threading.Lock()

    def _compute_kg_content_hash(self, kg_data: dict[str, Any]) -> str:
        """Compute hash of knowledge graph content for cache key generation.

        This creates a content-based hash that changes when the KG structure
        or node/edge data changes, ensuring cache invalidation when needed.
        """
        # Extract the essential content that affects embeddings
        content_data = {
            "nodes": sorted(kg_data.get("nodes", []), key=lambda x: x.get("id", "")),
            "edges": sorted(
                kg_data.get("edges", []),
                key=lambda x: (x.get("source_id", ""), x.get("target_id", "")),
            ),
        }

        content_str = json.dumps(content_data, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()[:16]

    def _get_cache_paths(self, kg_hash: str) -> tuple[Path, Path]:
        """Get cache file paths for embeddings and metadata."""
        assert self.cache_dir is not None
        embeddings_path = self.cache_dir / f"embeddings_{kg_hash}.pkl"
        metadata_path = self.cache_dir / f"metadata_{kg_hash}.json"
        return embeddings_path, metadata_path

    def get_cached_embeddings(
        self, kg_data: dict[str, Any]
    ) -> tuple[list[str], list[np.ndarray]] | None:
        """Retrieve cached embeddings if available and valid.

        Args:
            kg_data: Knowledge graph data dictionary

        Returns:
            Tuple of (documents, embeddings) if cache hit, None if cache miss
        """
        if not self.cache_enabled or not self.cache_dir:
            return None

        kg_hash = self._compute_kg_content_hash(kg_data)
        embeddings_path, metadata_path = self._get_cache_paths(kg_hash)

        # Check if both files exist
        if not (embeddings_path.exists() and metadata_path.exists()):
            return None

        try:
            # Load metadata first to validate cache
            with open(metadata_path) as f:
                metadata = json.load(f)

            # Validate cache version and integrity
            if metadata.get("version") != "1.0":
                return None

            expected_kg_hash = metadata.get("kg_hash")
            if expected_kg_hash != kg_hash:
                return None

            # Load embeddings
            with open(embeddings_path, "rb") as f:
                cache_data = pickle.load(f)

            documents = cache_data["documents"]
            embeddings = cache_data["embeddings"]

            # Validate data integrity
            if len(documents) != len(embeddings):
                return None

            # Ensure embeddings are numpy arrays
            embeddings = [np.array(emb, dtype=np.float32) for emb in embeddings]

            return documents, embeddings

        except Exception:
            # Cache corruption or read error - return None to trigger regeneration
            return None

    def save_embeddings_to_cache(
        self, kg_data: dict[str, Any], documents: list[str], embeddings: list[np.ndarray]
    ) -> None:
        """Save embeddings to cache with atomic write operations.

        Args:
            kg_data: Knowledge graph data used to generate embeddings
            documents: List of document strings that were embedded
            embeddings: List of numpy arrays containing embeddings
        """
        if not self.cache_enabled or not self.cache_dir:
            return

        if len(documents) != len(embeddings):
            raise ValueError("Documents and embeddings lists must have same length")

        kg_hash = self._compute_kg_content_hash(kg_data)
        embeddings_path, metadata_path = self._get_cache_paths(kg_hash)

        # Use atomic write-then-rename pattern to prevent corruption
        with self._cache_lock:
            try:
                # Save embeddings data
                temp_emb_fd, temp_emb_path = tempfile.mkstemp(
                    suffix=".tmp", prefix="embeddings_", dir=self.cache_dir
                )

                try:
                    with open(temp_emb_fd, "wb") as f:
                        cache_data = {
                            "documents": documents,
                            "embeddings": [
                                emb.tolist() for emb in embeddings
                            ],  # Convert to lists for JSON serialization
                        }
                        pickle.dump(cache_data, f, protocol=pickle.HIGHEST_PROTOCOL)

                    # Save metadata
                    temp_meta_fd, temp_meta_path = tempfile.mkstemp(
                        suffix=".tmp", prefix="metadata_", dir=self.cache_dir
                    )

                    try:
                        with open(temp_meta_fd, "w") as f:
                            metadata = {
                                "version": "1.0",
                                "kg_hash": kg_hash,
                                "document_count": len(documents),
                                "embedding_dimension": len(embeddings[0]) if embeddings else 0,
                                "created_at": __import__("datetime").datetime.now().isoformat(),
                            }
                            json.dump(metadata, f, indent=2)

                        # Atomic renames - either both succeed or both fail
                        Path(temp_emb_path).rename(embeddings_path)
                        Path(temp_meta_path).rename(metadata_path)

                    except Exception as e:
                        # Clean up metadata temp file on failure
                        try:
                            Path(temp_meta_path).unlink(missing_ok=True)
                        except Exception:
                            pass
                        raise e

                except Exception as e:
                    # Clean up embeddings temp file on failure
                    try:
                        Path(temp_emb_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                    raise e

            except Exception as e:
                # Log cache write failures for debugging but don't fail the operation
                print(f"⚠️  Embedding cache write failed: {e}")

    def clear_cache(self) -> int:
        """Clear all cached embeddings.

        Returns:
            Number of files removed
        """
        if not self.cache_enabled or not self.cache_dir:
            return 0

        files_removed = 0
        with self._cache_lock:
            try:
                # Remove all embedding and metadata files
                for pattern in ["embeddings_*.pkl", "metadata_*.json"]:
                    for file_path in self.cache_dir.glob(pattern):
                        try:
                            file_path.unlink()
                            files_removed += 1
                        except Exception:
                            pass  # Continue with other files
            except Exception:
                pass

        return files_removed

    def get_cache_stats(self) -> dict[str, Any]:
        """Get statistics about the embedding cache.

        Returns:
            Dictionary with cache statistics
        """
        if not self.cache_enabled or not self.cache_dir:
            return {"enabled": False}

        try:
            embedding_files = list(self.cache_dir.glob("embeddings_*.pkl"))
            metadata_files = list(self.cache_dir.glob("metadata_*.json"))

            # Calculate total cache size
            total_size = sum(f.stat().st_size for f in embedding_files + metadata_files)

            # Get details from metadata files
            cache_entries = []
            for metadata_file in metadata_files:
                try:
                    with open(metadata_file) as f:
                        metadata = json.load(f)
                    cache_entries.append(
                        {
                            "kg_hash": metadata.get("kg_hash", "unknown"),
                            "document_count": metadata.get("document_count", 0),
                            "embedding_dimension": metadata.get("embedding_dimension", 0),
                            "created_at": metadata.get("created_at", "unknown"),
                        }
                    )
                except Exception:
                    continue

            return {
                "enabled": True,
                "cache_dir": str(self.cache_dir),
                "entry_count": len(cache_entries),
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "entries": cache_entries,
            }

        except Exception:
            return {"enabled": True, "error": "Failed to compute cache stats"}

    def warm_cache_for_kg(self, kg_data: dict[str, Any]) -> bool:
        """Check if cache exists for given KG data, useful for pre-warming.

        Args:
            kg_data: Knowledge graph data to check

        Returns:
            True if cache exists and is valid, False otherwise
        """
        cached_data = self.get_cached_embeddings(kg_data)
        return cached_data is not None
