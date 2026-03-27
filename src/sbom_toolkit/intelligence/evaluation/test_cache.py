"""
Caching functionality for performance test results.

This module handles caching of individual test results and performance comparisons
to avoid re-running expensive tests when possible.
"""

import hashlib
import json
import tempfile
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ...shared.caching import CacheManager
from ...shared.models import PerformanceComparison, TestCase, TestResult
from .embedding_cache import EmbeddingCache


class TestResultCache:
    """Manages caching of test results and performance comparisons."""

    def __init__(self, cache_dir: Path | None = None, cache_enabled: bool = True):
        self.cache_enabled = cache_enabled and cache_dir is not None
        if self.cache_enabled and cache_dir is not None:
            self.cache_manager = CacheManager(cache_dir)
            # Initialize embedding cache as well
            self.embedding_cache = EmbeddingCache(cache_dir, cache_enabled)
        else:
            self.cache_manager = None
            self.embedding_cache = EmbeddingCache(None, False)
        # Thread-safe cache writes
        self._cache_lock = threading.Lock()

    def _compute_sbom_hash(self, sbom_data: dict[str, Any]) -> str:
        """Compute hash of SBOM data for cache key generation."""
        sbom_str = json.dumps(sbom_data, sort_keys=True)
        return hashlib.sha256(sbom_str.encode()).hexdigest()[:16]

    def _compute_test_cache_key(self, test_case: TestCase, sbom_hash: str, system_type: str) -> str:
        """Compute cache key for individual test results."""
        key_data = f"{test_case.id}|{sbom_hash}|{system_type}|advanced_eval"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _compute_comparison_cache_key(
        self, repository_url: str, sbom_hash: str, test_config: dict[str, Any]
    ) -> str:
        """Compute cache key for overall performance comparison."""
        config_str = json.dumps(test_config, sort_keys=True)
        key_data = f"{repository_url}|{sbom_hash}|{config_str}|advanced_eval"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get_cached_test_result(
        self, test_case: TestCase, sbom_hash: str, system_type: str
    ) -> TestResult | None:
        """Retrieve cached test result if available."""
        if not self.cache_enabled or not self.cache_manager:
            return None

        cache_key = self._compute_test_cache_key(test_case, sbom_hash, system_type)
        cache_path = self.cache_manager.cache_dir / f"test_result_{cache_key}.json"

        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    result_data = json.load(f)
                # Reconstruct TestCase object from stored data
                test_case_data = result_data.pop("test_case")

                # Ensure required TestCase fields have defaults
                if "question" not in test_case_data:
                    test_case_data["question"] = ""

                # Create TestCase with just the question field to ensure it has required parameters
                test_case_obj = TestCase(
                    question=test_case_data.get("question", ""),
                    category=test_case_data.get("category", "general"),
                    difficulty=test_case_data.get("difficulty", "medium"),
                    id=test_case_data.get("id", ""),
                    context=test_case_data.get("context", ""),
                    expected_elements=test_case_data.get("expected_elements", []),
                    repository_context=test_case_data.get("repository_context", ""),
                    expected_cve_ids=test_case_data.get("expected_cve_ids", []),
                    expected_cwe_ids=test_case_data.get("expected_cwe_ids", []),
                    expected_capec_ids=test_case_data.get("expected_capec_ids", []),
                    expected_component_names=test_case_data.get("expected_component_names", []),
                )

                # Ensure required TestResult fields have defaults
                required_defaults = {
                    "system_name": "unknown",
                    "response": "",
                    "response_time": 0.0,
                    "tokens_used": 0,
                }

                for field, default_value in required_defaults.items():
                    if field not in result_data:
                        result_data[field] = default_value

                # Create TestResult with explicit parameters to ensure all required fields are present
                return TestResult(
                    test_case=test_case_obj,
                    system_name=result_data.get("system_name", "unknown"),
                    response=result_data.get("response", ""),
                    response_time=result_data.get("response_time", 0.0),
                    tokens_used=result_data.get("tokens_used", 0),
                    citation_metrics=result_data.get("citation_metrics", {}),
                    precision=result_data.get("precision", 0.0),
                    recall=result_data.get("recall", 0.0),
                    f1_score=result_data.get("f1_score", 0.0),
                    f1_5_score=result_data.get("f1_5_score", 0.0),
                    passed=result_data.get("passed", False),
                    errors=result_data.get("errors", []),
                )
            except Exception:
                pass  # Fall through to recompute

        return None

    def save_test_result_to_cache(
        self,
        test_result: TestResult,
        test_case: TestCase,
        sbom_hash: str,
        system_type: str,
    ) -> None:
        """Save test result to cache with atomic write and file locking."""
        if not self.cache_enabled or not self.cache_manager:
            return

        cache_key = self._compute_test_cache_key(test_case, sbom_hash, system_type)
        cache_path = self.cache_manager.cache_dir / f"test_result_{cache_key}.json"

        # Use atomic write-then-rename pattern to prevent corruption
        with self._cache_lock:
            try:
                # Create temporary file in same directory to ensure atomic rename
                temp_fd, temp_path = tempfile.mkstemp(
                    suffix=".tmp", prefix="cache_", dir=self.cache_manager.cache_dir
                )

                try:
                    with open(temp_fd, "w") as f:
                        json.dump(asdict(test_result), f, indent=2)

                    # Atomic rename - either fully succeeds or fails completely
                    Path(temp_path).rename(cache_path)

                except Exception as e:
                    # Clean up temp file on failure
                    try:
                        Path(temp_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                    raise e

            except Exception as e:
                # Log cache write failures for debugging but don't fail the test
                if hasattr(self, "_verbose") and self._verbose:
                    print(f"⚠️  Cache write failed for {system_type} test: {e}")

    def get_cached_comparison(
        self, repository_url: str, sbom_hash: str, test_config: dict[str, Any]
    ) -> PerformanceComparison | None:
        """Retrieve cached performance comparison if available."""
        if not self.cache_enabled or not self.cache_manager:
            return None

        cache_key = self._compute_comparison_cache_key(repository_url, sbom_hash, test_config)
        cache_path = self.cache_manager.cache_dir / f"comparison_{cache_key}.json"

        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    comparison_data = json.load(f)
                # Convert test results back to TestResult objects
                kg_results = [
                    self._dict_to_test_result(r) for r in comparison_data["kg_enhanced_results"]
                ]
                legacy_results = [
                    self._dict_to_test_result(r) for r in comparison_data["legacy_rag_results"]
                ]
                standalone_results = [
                    self._dict_to_test_result(r) for r in comparison_data["standalone_results"]
                ]

                comparison_data["kg_enhanced_results"] = kg_results
                comparison_data["legacy_rag_results"] = legacy_results
                comparison_data["standalone_results"] = standalone_results

                # Create PerformanceComparison with explicit parameters to ensure all required fields are present
                return PerformanceComparison(
                    test_session_id=comparison_data.get("test_session_id", ""),
                    timestamp=comparison_data.get("timestamp", ""),
                    repository_url=comparison_data.get("repository_url", ""),
                    total_test_cases=comparison_data.get("total_test_cases", 0),
                    kg_enhanced_results=comparison_data.get("kg_enhanced_results", []),
                    legacy_rag_results=comparison_data.get("legacy_rag_results", []),
                    standalone_results=comparison_data.get("standalone_results", []),
                    summary_stats=comparison_data.get("summary_stats", {}),
                    test_metadata=comparison_data.get("test_metadata", {}),
                )
            except Exception:
                pass  # Fall through to recompute

        return None

    def save_comparison_to_cache(
        self,
        comparison: PerformanceComparison,
        repository_url: str,
        sbom_hash: str,
        test_config: dict[str, Any],
    ) -> None:
        """Save performance comparison to cache with atomic write and file locking."""
        if not self.cache_enabled or not self.cache_manager:
            return

        cache_key = self._compute_comparison_cache_key(repository_url, sbom_hash, test_config)
        cache_path = self.cache_manager.cache_dir / f"comparison_{cache_key}.json"

        # Use atomic write-then-rename pattern to prevent corruption
        with self._cache_lock:
            try:
                # Create temporary file in same directory to ensure atomic rename
                temp_fd, temp_path = tempfile.mkstemp(
                    suffix=".tmp", prefix="cache_", dir=self.cache_manager.cache_dir
                )

                try:
                    with open(temp_fd, "w") as f:
                        json.dump(asdict(comparison), f, indent=2)

                    # Atomic rename - either fully succeeds or fails completely
                    Path(temp_path).rename(cache_path)

                except Exception as e:
                    # Clean up temp file on failure
                    try:
                        Path(temp_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                    raise e

            except Exception as e:
                # Log cache write failures for debugging but don't fail the test
                if hasattr(self, "_verbose") and self._verbose:
                    print(f"⚠️  Cache write failed for comparison: {e}")

    def _dict_to_test_result(self, result_dict: dict[str, Any]) -> TestResult:
        """Convert dictionary back to TestResult object."""
        test_case_data = result_dict.pop("test_case")

        # Ensure required TestCase fields have defaults
        if "question" not in test_case_data:
            test_case_data["question"] = ""

        # Create TestCase with explicit parameters to ensure all required fields are present
        test_case_obj = TestCase(
            question=test_case_data.get("question", ""),
            category=test_case_data.get("category", "general"),
            difficulty=test_case_data.get("difficulty", "medium"),
            id=test_case_data.get("id", ""),
            context=test_case_data.get("context", ""),
            expected_elements=test_case_data.get("expected_elements", []),
            repository_context=test_case_data.get("repository_context", ""),
            expected_cve_ids=test_case_data.get("expected_cve_ids", []),
            expected_cwe_ids=test_case_data.get("expected_cwe_ids", []),
            expected_capec_ids=test_case_data.get("expected_capec_ids", []),
            expected_component_names=test_case_data.get("expected_component_names", []),
        )

        # Ensure required TestResult fields have defaults
        required_defaults = {
            "system_name": "unknown",
            "response": "",
            "response_time": 0.0,
            "tokens_used": 0,
        }

        for field, default_value in required_defaults.items():
            if field not in result_dict:
                result_dict[field] = default_value

        # Create TestResult with explicit parameters to ensure all required fields are present
        return TestResult(
            test_case=test_case_obj,
            system_name=result_dict.get("system_name", "unknown"),
            response=result_dict.get("response", ""),
            response_time=result_dict.get("response_time", 0.0),
            tokens_used=result_dict.get("tokens_used", 0),
            citation_metrics=result_dict.get("citation_metrics", {}),
            precision=result_dict.get("precision", 0.0),
            recall=result_dict.get("recall", 0.0),
            f1_score=result_dict.get("f1_score", 0.0),
            f1_5_score=result_dict.get("f1_5_score", 0.0),
            passed=result_dict.get("passed", False),
            errors=result_dict.get("errors", []),
        )
