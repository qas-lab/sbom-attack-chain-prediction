"""
Component processing utilities for SBOM consistency and normalization.

This module implements the recommendations from SBOM comparison analysis:
1. Case-insensitive component matching
2. Component type standardization
3. File component filtering
"""

import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


class ComponentNormalizer:
    """Handles component name normalization for case-insensitive matching."""

    @staticmethod
    def normalize_name(component_name: str) -> str:
        """Normalize component name for case-insensitive comparison.

        Args:
            component_name: Original component name

        Returns:
            Normalized component name (lowercase, stripped)
        """
        if not component_name:
            return ""
        return component_name.lower().strip()

    @staticmethod
    def normalize_component_key(component: dict[str, Any]) -> str:
        """Generate normalized key for component deduplication.

        Args:
            component: Component dictionary with name and version

        Returns:
            Normalized component key in format "name@version"
        """
        name = ComponentNormalizer.normalize_name(component.get("name", ""))
        version = component.get("version", "unknown").strip()
        return f"{name}@{version}"

    @staticmethod
    def components_match(comp1: dict[str, Any], comp2: dict[str, Any]) -> bool:
        """Check if two components match using case-insensitive comparison.

        Args:
            comp1: First component dictionary
            comp2: Second component dictionary

        Returns:
            True if components match (same name and version)
        """
        key1 = ComponentNormalizer.normalize_component_key(comp1)
        key2 = ComponentNormalizer.normalize_component_key(comp2)
        return key1 == key2


class ComponentTypeStandardizer:
    """Standardizes component types to match cdxgen's more specific categorization."""

    # Django-family packages that should be classified as 'framework'
    FRAMEWORK_PACKAGES = {
        "django",
        "django-rest-framework",
        "djangorestframework",
        "django-oauth-toolkit",
        "django-cors-headers",
        "django-extensions",
        "flask",
        "fastapi",
        "tornado",
        "pyramid",
        "bottle",
        "cherrypy",
        "express",
        "react",
        "angular",
        "vue",
        "svelte",
        "next.js",
        "nuxt.js",
        "spring-boot",
        "spring-framework",
        "spring-core",
        "hibernate",
        "laravel",
        "symfony",
        "codeigniter",
        "zend",
        "cakephp",
        "rails",
        "sinatra",
        "grape",
    }

    # Packages that should remain as 'library' (override framework detection)
    LIBRARY_PACKAGES = {
        "numpy",
        "pandas",
        "requests",
        "urllib3",
        "certifi",
        "setuptools",
        "pip",
        "wheel",
        "six",
        "pycparser",
        "cffi",
        "cryptography",
        "idna",
        "chardet",
        "pytz",
        "sqlparse",
        "typing-extensions",
    }

    @staticmethod
    def standardize_component_type(component: dict[str, Any]) -> str:
        """Standardize component type using cdxgen-style categorization.

        Args:
            component: Component dictionary with name and type

        Returns:
            Standardized component type
        """
        original_type = component.get("type", "library")
        component_name = ComponentNormalizer.normalize_name(component.get("name", ""))

        # If already correctly categorized, keep it
        if original_type in ["framework", "application", "container", "device", "firmware"]:
            return original_type

        # Check for explicit library override (even if it might look like a framework)
        if component_name in ComponentTypeStandardizer.LIBRARY_PACKAGES:
            return "library"

        # Check for framework packages
        if component_name in ComponentTypeStandardizer.FRAMEWORK_PACKAGES:
            return "framework"

        # Pattern-based detection for frameworks
        framework_patterns = [
            r".*framework.*",
            r".*-framework$",
            r"^framework-.*",
            r".*-rest-.*",
            r".*-api-.*",
            r".*-web-.*",
            r".*-server$",
        ]

        for pattern in framework_patterns:
            if re.match(pattern, component_name):
                # Double-check it's not explicitly a library
                if component_name not in ComponentTypeStandardizer.LIBRARY_PACKAGES:
                    return "framework"

        # Default to original type or 'library'
        return original_type if original_type != "unknown" else "library"

    @staticmethod
    def update_component_types(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Update component types in a list of components.

        Args:
            components: List of component dictionaries

        Returns:
            Updated list with standardized component types
        """
        updated_components = []

        for component in components:
            updated_component = component.copy()
            updated_component["type"] = ComponentTypeStandardizer.standardize_component_type(
                component
            )
            updated_components.append(updated_component)

        return updated_components


class ComponentFilter:
    """Filters out unwanted component types (like file components)."""

    # File extensions that indicate file components to exclude
    FILE_EXTENSIONS = {
        ".txt",
        ".md",
        ".rst",
        ".py",
        ".js",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".css",
        ".scss",
        ".less",
        ".conf",
        ".cfg",
        ".ini",
        ".properties",
        ".env",
        ".lock",
        ".log",
    }

    # Specific file names to exclude
    EXCLUDED_FILENAMES = {
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
        "build.gradle",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "makefile",
        "dockerfile",
        "readme.md",
        "readme.txt",
        "license",
        "license.txt",
        "changelog.md",
        "pyproject.toml",
    }

    @staticmethod
    def should_exclude_component(component: dict[str, Any]) -> bool:
        """Determine if a component should be excluded from processing.

        Args:
            component: Component dictionary

        Returns:
            True if component should be excluded
        """
        component_type = component.get("type", "").lower()
        component_name = component.get("name", "").lower()

        # Exclude file-type components
        if component_type == "file":
            return True

        # Exclude components that look like file paths
        if "/" in component_name or "\\" in component_name:
            return True

        # Exclude specific filenames
        if component_name in ComponentFilter.EXCLUDED_FILENAMES:
            return True

        # Exclude by file extension
        for ext in ComponentFilter.FILE_EXTENSIONS:
            if component_name.endswith(ext.lower()):
                return True

        return False

    @staticmethod
    def filter_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter out unwanted components from a list.

        Args:
            components: List of component dictionaries

        Returns:
            Filtered list with unwanted components removed
        """
        return [
            component
            for component in components
            if not ComponentFilter.should_exclude_component(component)
        ]


class ComponentProcessor:
    """Main processor that applies all component improvements."""

    def __init__(self):
        """Initialize the component processor."""
        self.normalizer = ComponentNormalizer()
        self.type_standardizer = ComponentTypeStandardizer()
        self.filter = ComponentFilter()
        self.logger = logging.getLogger(__name__)

    def process_components(
        self,
        components: list[dict[str, Any]],
        filter_files: bool = True,
        standardize_types: bool = True,
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Process components with all improvements applied.

        Args:
            components: List of component dictionaries
            filter_files: Whether to filter out file components
            standardize_types: Whether to standardize component types

        Returns:
            Tuple of (processed_components, processing_stats)
        """
        original_count = len(components)
        processed_components = components.copy()

        # Step 1: Filter out unwanted components
        if filter_files:
            processed_components = self.filter.filter_components(processed_components)

        # Step 2: Standardize component types
        if standardize_types:
            processed_components = self.type_standardizer.update_component_types(
                processed_components
            )

        # Generate processing statistics
        stats = {
            "original_count": original_count,
            "final_count": len(processed_components),
            "filtered_count": original_count - len(processed_components),
        }

        # Count type changes
        if standardize_types:
            type_changes = 0
            for original, processed in zip(components, processed_components, strict=False):
                if original.get("type") != processed.get("type"):
                    type_changes += 1
            stats["type_changes"] = type_changes

        return processed_components, stats

    def process_components_parallel(
        self,
        components: list[dict[str, Any]],
        filter_files: bool = True,
        standardize_types: bool = True,
        batch_size: int = 50,
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Process components with all improvements applied using parallel processing.

        This method leverages Python 3.13 free-threading to process component batches
        in parallel, providing significant speedup for large component lists.

        Args:
            components: List of component dictionaries
            filter_files: Whether to filter out file components
            standardize_types: Whether to standardize component types
            batch_size: Number of components to process per batch

        Returns:
            Tuple of (processed_components, processing_stats)
        """
        # Use sequential processing for small lists or if GIL is enabled
        if sys._is_gil_enabled() or len(components) < batch_size * 2:
            return self.process_components(components, filter_files, standardize_types)

        self.logger.debug(f"Using parallel component processing for {len(components)} components")

        original_count = len(components)

        # Create batches
        batches = [components[i : i + batch_size] for i in range(0, len(components), batch_size)]

        def process_batch(
            batch: list[dict[str, Any]],
        ) -> tuple[list[dict[str, Any]], dict[str, int]]:
            """Process a single batch of components."""
            batch_processed = batch.copy()

            # Apply filtering
            if filter_files:
                batch_processed = self.filter.filter_components(batch_processed)

            # Apply type standardization
            if standardize_types:
                batch_processed = self.type_standardizer.update_component_types(batch_processed)

            # Calculate batch stats
            batch_stats = {
                "original": len(batch),
                "processed": len(batch_processed),
                "filtered": len(batch) - len(batch_processed),
                "type_changes": 0,
            }

            # Count type changes
            if standardize_types:
                for orig, proc in zip(batch, batch_processed, strict=False):
                    if orig.get("type") != proc.get("type"):
                        batch_stats["type_changes"] += 1

            return batch_processed, batch_stats

        # Process batches in parallel
        max_workers = min(4, len(batches))  # Reasonable thread count
        all_processed = []
        total_filtered = 0
        total_type_changes = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(process_batch, batch): i for i, batch in enumerate(batches)
            }

            # Collect results in order
            batch_results = [None] * len(batches)

            for future in as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    processed_batch, batch_stats = future.result()
                    batch_results[batch_idx] = (processed_batch, batch_stats)
                    total_filtered += batch_stats["filtered"]
                    total_type_changes += batch_stats["type_changes"]
                except Exception as e:
                    print(f"  ✗ Error processing batch {batch_idx}: {e}")
                    # Use original batch on error
                    batch_results[batch_idx] = (
                        batches[batch_idx],
                        {"filtered": 0, "type_changes": 0},
                    )

        # Combine results in order
        for result in batch_results:
            if result:
                processed_batch, _ = result
                all_processed.extend(processed_batch)

        # Generate overall statistics
        stats = {
            "original_count": original_count,
            "final_count": len(all_processed),
            "filtered_count": total_filtered,
        }

        if standardize_types:
            stats["type_changes"] = total_type_changes

        return all_processed, stats

    def deduplicate_components(
        self, components: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Remove duplicate components using case-insensitive matching.

        Args:
            components: List of component dictionaries

        Returns:
            Tuple of (deduplicated_components, duplicate_count)
        """
        seen_keys = set()
        deduplicated = []
        duplicate_count = 0

        for component in components:
            normalized_key = self.normalizer.normalize_component_key(component)

            if normalized_key not in seen_keys:
                seen_keys.add(normalized_key)
                deduplicated.append(component)
            else:
                duplicate_count += 1

        return deduplicated, duplicate_count

    def compare_component_lists(
        self,
        list1: list[dict[str, Any]],
        list2: list[dict[str, Any]],
        list1_name: str = "List 1",
        list2_name: str = "List 2",
    ) -> dict[str, Any]:
        """Compare two component lists using case-insensitive matching.

        Args:
            list1: First component list
            list2: Second component list
            list1_name: Name for first list in results
            list2_name: Name for second list in results

        Returns:
            Detailed comparison results
        """
        # Normalize component keys
        keys1 = {self.normalizer.normalize_component_key(comp) for comp in list1}
        keys2 = {self.normalizer.normalize_component_key(comp) for comp in list2}

        common_keys = keys1 & keys2
        only_in_list1 = keys1 - keys2
        only_in_list2 = keys2 - keys1

        return {
            f"{list1_name.lower().replace(' ', '_')}_total": len(list1),
            f"{list2_name.lower().replace(' ', '_')}_total": len(list2),
            "common_components": len(common_keys),
            f"only_in_{list1_name.lower().replace(' ', '_')}": len(only_in_list1),
            f"only_in_{list2_name.lower().replace(' ', '_')}": len(only_in_list2),
            "overlap_percentage": len(common_keys) / max(len(keys1), 1) * 100,
            f"only_in_{list1_name.lower().replace(' ', '_')}_list": sorted(only_in_list1),
            f"only_in_{list2_name.lower().replace(' ', '_')}_list": sorted(only_in_list2),
            "common_components_list": sorted(common_keys),
        }
