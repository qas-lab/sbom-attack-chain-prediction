"""
CVSS version handling utilities for consistent version-aware CVSS processing.
"""

from typing import Any


class CVSSVersionHandler:
    """Handles CVSS version priority and extraction logic."""

    # CVSS version priority: higher number = higher priority
    VERSION_PRIORITY = {"4.0": 40, "3.1": 31, "3.0": 30, "2.0": 20}

    @classmethod
    def select_best_cvss(cls, all_cvss_data: dict[str, Any]) -> dict[str, Any]:
        """
        Select the best CVSS version from available data.

        Args:
            all_cvss_data: Dictionary with version keys and CVSS data

        Returns:
            Dictionary with selected CVSS data including:
            - cvss_score: float | None
            - cvss_version: str | None
            - cvss_vector: str | None
            - cvss_severity: str | None
            - all_cvss_metrics: dict (original data)
        """
        if not all_cvss_data:
            return {
                "cvss_score": None,
                "cvss_version": None,
                "cvss_vector": None,
                "cvss_severity": None,
                "all_cvss_metrics": {},
            }

        # Find the highest priority version with valid data
        best_version = None
        best_priority = -1

        for version, data in all_cvss_data.items():
            normalized_version = cls._normalize_version(version)
            priority = cls.VERSION_PRIORITY.get(normalized_version, 0)

            # Check if this version has valid score data
            if priority > best_priority and cls._has_valid_score(data):
                best_version = version
                best_priority = priority

        if not best_version:
            return {
                "cvss_score": None,
                "cvss_version": None,
                "cvss_vector": None,
                "cvss_severity": None,
                "all_cvss_metrics": all_cvss_data,
            }

        best_data = all_cvss_data[best_version]

        return {
            "cvss_score": cls._extract_score(best_data),
            "cvss_version": cls._normalize_version(best_version),
            "cvss_vector": cls._extract_vector(best_data),
            "cvss_severity": cls._extract_severity(best_data),
            "all_cvss_metrics": all_cvss_data,
        }

    @classmethod
    def _normalize_version(cls, version: str) -> str:
        """Normalize version string to standard format."""
        version = str(version).lower().strip()

        # Handle common variations
        if version in ["4", "4.0", "v4", "v4.0"]:
            return "4.0"
        elif version in ["3.1", "v3.1", "31"]:
            return "3.1"
        elif version in ["3", "3.0", "v3", "v3.0", "3.x"]:
            return "3.0"
        elif version in ["2", "2.0", "v2", "v2.0"]:
            return "2.0"

        return version

    @classmethod
    def _has_valid_score(cls, data: dict[str, Any]) -> bool:
        """Check if CVSS data contains a valid score."""
        if not isinstance(data, dict):
            return False

        # Check common score field names
        score_fields = ["baseScore", "base_score", "score", "cvssScore", "cvss_score"]

        for field in score_fields:
            if field in data:
                try:
                    score = float(data[field])
                    return 0.0 <= score <= 10.0
                except (ValueError, TypeError):
                    continue

        # Check nested metrics
        if "metrics" in data and isinstance(data["metrics"], dict):
            return cls._has_valid_score(data["metrics"])

        # Check cvssData nested structure (NVD format)
        if "cvssData" in data and isinstance(data["cvssData"], dict):
            return cls._has_valid_score(data["cvssData"])

        return False

    @classmethod
    def _extract_score(cls, data: dict[str, Any]) -> float | None:
        """Extract CVSS score from data structure."""
        if not isinstance(data, dict):
            return None

        # Try common score field names
        score_fields = ["baseScore", "base_score", "score", "cvssScore", "cvss_score"]

        for field in score_fields:
            if field in data:
                try:
                    score = float(data[field])
                    if 0.0 <= score <= 10.0:
                        return score
                except (ValueError, TypeError):
                    continue

        # Check nested structures
        if "metrics" in data and isinstance(data["metrics"], dict):
            nested_score = cls._extract_score(data["metrics"])
            if nested_score is not None:
                return nested_score

        if "cvssData" in data and isinstance(data["cvssData"], dict):
            nested_score = cls._extract_score(data["cvssData"])
            if nested_score is not None:
                return nested_score

        return None

    @classmethod
    def _extract_vector(cls, data: dict[str, Any]) -> str | None:
        """Extract CVSS vector string from data structure."""
        if not isinstance(data, dict):
            return None

        # Try common vector field names
        vector_fields = ["vectorString", "vector_string", "vector", "cvssVector", "cvss_vector"]

        for field in vector_fields:
            if field in data and isinstance(data[field], str):
                return data[field]

        # Check nested structures
        if "metrics" in data and isinstance(data["metrics"], dict):
            nested_vector = cls._extract_vector(data["metrics"])
            if nested_vector:
                return nested_vector

        if "cvssData" in data and isinstance(data["cvssData"], dict):
            nested_vector = cls._extract_vector(data["cvssData"])
            if nested_vector:
                return nested_vector

        return None

    @classmethod
    def _extract_severity(cls, data: dict[str, Any]) -> str | None:
        """Extract CVSS severity from data structure."""
        if not isinstance(data, dict):
            return None

        # Try common severity field names
        severity_fields = [
            "baseSeverity",
            "base_severity",
            "severity",
            "cvssSeverity",
            "cvss_severity",
        ]

        for field in severity_fields:
            if field in data and isinstance(data[field], str):
                return data[field].upper()

        # Check nested structures
        if "metrics" in data and isinstance(data["metrics"], dict):
            nested_severity = cls._extract_severity(data["metrics"])
            if nested_severity:
                return nested_severity

        if "cvssData" in data and isinstance(data["cvssData"], dict):
            nested_severity = cls._extract_severity(data["cvssData"])
            if nested_severity:
                return nested_severity

        # If no severity found but we have a score, calculate it
        score = cls._extract_score(data)
        if score is not None:
            return cls._score_to_severity(score)

        return None

    @classmethod
    def _score_to_severity(cls, score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score == 0.0:
            return "NONE"
        elif 0.1 <= score <= 3.9:
            return "LOW"
        elif 4.0 <= score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= score <= 8.9:
            return "HIGH"
        elif 9.0 <= score <= 10.0:
            return "CRITICAL"
        else:
            return "UNKNOWN"

    @classmethod
    def parse_grype_cvss(cls, grype_cvss_array: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Parse Grype CVSS array format into version-keyed dictionary.

        Grype format:
        [
            {"version": "2.0", "vector": "...", "metrics": {"baseScore": 2.1}},
            {"version": "3.x", "metrics": {"baseScore": 7.5}}
        ]
        """
        parsed_data = {}

        for cvss_entry in grype_cvss_array:
            if not isinstance(cvss_entry, dict):
                continue

            version = cvss_entry.get("version", "unknown")
            normalized_version = cls._normalize_version(version)

            # Combine vector and metrics into single data structure
            entry_data = {}
            if "vector" in cvss_entry:
                entry_data["vectorString"] = cvss_entry["vector"]

            if "metrics" in cvss_entry and isinstance(cvss_entry["metrics"], dict):
                entry_data.update(cvss_entry["metrics"])

            if entry_data:
                parsed_data[normalized_version] = entry_data

        return parsed_data

    @classmethod
    def parse_nvd_cvss(cls, nvd_metrics: dict[str, Any]) -> dict[str, Any]:
        """
        Parse NVD metrics format into version-keyed dictionary.

        NVD format has cvssMetricV2, cvssMetricV3, cvssMetricV31, cvssMetricV4 arrays
        """
        parsed_data = {}

        # Map NVD metric keys to versions
        metric_mapping = {
            "cvssMetricV4": "4.0",
            "cvssMetricV31": "3.1",
            "cvssMetricV3": "3.0",
            "cvssMetricV2": "2.0",
        }

        for metric_key, version in metric_mapping.items():
            if metric_key not in nvd_metrics:
                continue

            metric_array = nvd_metrics[metric_key]
            if not isinstance(metric_array, list) or not metric_array:
                continue

            # Use the first (primary) entry for each version
            # NVD typically has Primary source first
            primary_entry = metric_array[0]

            if "cvssData" in primary_entry:
                parsed_data[version] = primary_entry["cvssData"]
            elif isinstance(primary_entry, dict):
                parsed_data[version] = primary_entry

        return parsed_data
