"""
Data transformation utilities for SBOM visualization.

This module provides data cleaning and transformation functions to ensure
consistent, clean data flow between SBOM processing and visualization rendering.
"""

import logging
import re
from typing import Any

from ...shared.component_utils import ComponentProcessor


class SBOMDataTransformer:
    """Transforms and cleans SBOM data for visualization."""

    def __init__(self):
        """Initialize the data transformer."""
        self.logger = logging.getLogger(__name__)

        # Initialize component processor for advanced filtering and normalization
        self.component_processor = ComponentProcessor()

        # Patterns to identify and clean temporary paths
        self.temp_path_patterns = [
            r"/var/folders/[^/]+/[^/]+/T/[^/]*temp[^/]*/",  # macOS temp paths
            r"/tmp/[^/]*temp[^/]*/",  # Linux temp paths
            r"C:\\Windows\\Temp\\[^\\]*temp[^\\]*\\",  # Windows temp paths
            r"/var/folders/.*/T/.*",  # General macOS temp
            r".*sbomgen-temp.*",  # SBOM generator temp
        ]

        # Compile regex patterns for efficiency
        self.compiled_patterns = [re.compile(pattern) for pattern in self.temp_path_patterns]

    def should_exclude_component(self, component: dict[str, Any]) -> bool:
        """Check if a component should be excluded from visualization.

        Args:
            component: Component data dictionary

        Returns:
            True if component should be excluded
        """
        # Use the new component filter for comprehensive exclusion logic
        should_exclude = self.component_processor.filter.should_exclude_component(component)

        if should_exclude:
            self.logger.debug(
                f"Excluding component: {component.get('name', 'unknown')} "
                f"(type: {component.get('type', 'unknown')})"
            )

        return should_exclude

    def clean_component_name(self, name: str) -> str:
        """Clean component name by removing temporary paths.

        Args:
            name: Original component name

        Returns:
            Cleaned component name
        """
        if not name:
            return name

        cleaned_name = name
        for pattern in self.compiled_patterns:
            cleaned_name = pattern.sub("", cleaned_name)

        return cleaned_name.strip()

    def sanitize_component(self, component: dict[str, Any]) -> dict[str, Any]:
        """Sanitize component data for consistency.

        Args:
            component: Component data dictionary

        Returns:
            Sanitized component data
        """
        if not component:
            return component

        sanitized = component.copy()

        # Clean component name and paths
        if "name" in sanitized:
            sanitized["name"] = self.clean_component_name(sanitized["name"])

        # Clean bom-ref if it contains temp paths
        if "bom-ref" in sanitized:
            sanitized["bom-ref"] = self.clean_component_name(sanitized["bom-ref"])

        # Ensure required fields exist with safe defaults
        sanitized.setdefault("name", "unknown")
        sanitized.setdefault("version", "unknown")
        sanitized.setdefault("type", "library")

        # Standardize component type using the new type standardizer
        sanitized["type"] = self.component_processor.type_standardizer.standardize_component_type(
            sanitized
        )

        # Clean vulnerabilities
        if "vulnerabilities" in sanitized:
            sanitized["vulnerabilities"] = self.sanitize_vulnerabilities(
                sanitized["vulnerabilities"]
            )

        return sanitized

    def sanitize_vulnerabilities(
        self, vulnerabilities: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Sanitize vulnerability data.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Sanitized vulnerabilities list
        """
        if not vulnerabilities:
            return []

        sanitized_vulns = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            sanitized_vuln = vuln.copy()

            # Ensure required fields with defaults
            sanitized_vuln.setdefault("id", "unknown")
            sanitized_vuln.setdefault("source", {})

            # Normalize source data
            source = sanitized_vuln.get("source", {})
            if isinstance(source, dict):
                source.setdefault("name", "unknown")
                source.setdefault("url", "")

            # Ensure numeric fields are properly typed, preserve None for missing scores
            if "cvss_score" in sanitized_vuln:
                score_value = sanitized_vuln["cvss_score"]
                if score_value is None:
                    # Preserve None to distinguish from zero score
                    sanitized_vuln["cvss_score"] = None
                else:
                    try:
                        sanitized_vuln["cvss_score"] = float(score_value)
                    except (ValueError, TypeError):
                        # Set to None for invalid/unparseable scores, not 0.0
                        sanitized_vuln["cvss_score"] = None

            sanitized_vulns.append(sanitized_vuln)

        return sanitized_vulns

    def clean_dependency_references(
        self, dependencies: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Clean and validate dependency references.

        Args:
            dependencies: List of dependency dictionaries

        Returns:
            Cleaned dependencies list with valid references
        """
        if not dependencies:
            return []

        cleaned_deps = []
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue

            cleaned_dep = dep.copy()

            # Clean ref field
            if "ref" in cleaned_dep:
                cleaned_dep["ref"] = self.clean_component_name(cleaned_dep["ref"])

            # Clean dependsOn references
            if "dependsOn" in cleaned_dep and isinstance(cleaned_dep["dependsOn"], list):
                cleaned_depends_on = []
                for ref in cleaned_dep["dependsOn"]:
                    if isinstance(ref, str):
                        cleaned_ref = self.clean_component_name(ref)
                        if cleaned_ref:  # Only add non-empty references
                            cleaned_depends_on.append(cleaned_ref)
                cleaned_dep["dependsOn"] = cleaned_depends_on

            # Only include dependencies with valid references
            if cleaned_dep.get("ref") and cleaned_dep.get("dependsOn"):
                cleaned_deps.append(cleaned_dep)

        return cleaned_deps

    def create_unique_id(self, component: dict[str, Any]) -> str:
        """Create a unique identifier for a component.

        Args:
            component: Component data dictionary

        Returns:
            Unique identifier string
        """
        # Use the new component normalizer for consistent key generation
        return self.component_processor.normalizer.normalize_component_key(component)

    def transform_sbom_data(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Transform SBOM data by sanitizing all components and references.

        Args:
            sbom_data: Raw SBOM data dictionary

        Returns:
            Transformed and sanitized SBOM data
        """
        if not sbom_data:
            return sbom_data

        transformed_data = sbom_data.copy()

        # Process components using the new component processor
        if "components" in transformed_data:
            original_components = transformed_data["components"]
            original_count = len(original_components)
            self.logger.debug(
                f"Processing {original_count} components with enhanced filtering and normalization"
            )

            # Apply advanced component processing
            processed_components, stats = self.component_processor.process_components(
                original_components,
                filter_files=True,  # Filter out file components
                standardize_types=True,  # Standardize component types
            )

            # Apply additional sanitization
            sanitized_components = []
            for component in processed_components:
                if not self.should_exclude_component(component):
                    sanitized_components.append(self.sanitize_component(component))

            transformed_data["components"] = sanitized_components

            self.logger.info(
                f"Component processing complete: {stats['original_count']} → {len(sanitized_components)} "
                f"(filtered: {stats['filtered_count']}, type changes: {stats.get('type_changes', 0)})"
            )

        # Process dependencies
        if "dependencies" in transformed_data:
            original_dep_count = len(transformed_data["dependencies"])
            self.logger.debug(f"Cleaning {original_dep_count} dependency relationships")

            transformed_data["dependencies"] = self.clean_dependency_references(
                transformed_data["dependencies"]
            )

            cleaned_dep_count = len(transformed_data["dependencies"])
            self.logger.debug(
                f"Cleaned {original_dep_count - cleaned_dep_count} invalid dependencies"
            )

        # Sanitize vulnerabilities
        if "vulnerabilities" in transformed_data:
            self.logger.debug(
                f"Sanitizing {len(transformed_data['vulnerabilities'])} vulnerabilities"
            )
            transformed_data["vulnerabilities"] = self.sanitize_vulnerabilities(
                transformed_data["vulnerabilities"]
            )

        # Clean metadata component if present
        if "metadata" in transformed_data and "component" in transformed_data["metadata"]:
            transformed_data["metadata"]["component"] = self.sanitize_component(
                transformed_data["metadata"]["component"]
            )

        self.logger.info("SBOM data transformation completed")
        return transformed_data

    def validate_data_integrity(self, sbom_data: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate that the transformed data maintains integrity.

        Args:
            sbom_data: Transformed SBOM data

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        # Check that components exist
        components = sbom_data.get("components", [])
        if not components:
            issues.append("No components found in SBOM data")

        # Check for component identifier consistency using normalized comparison
        component_keys = set()
        for component in components:
            component_key = self.component_processor.normalizer.normalize_component_key(component)

            if not component_key or component_key == "@unknown":
                issues.append(
                    f"Component missing valid name/version: {component.get('name', 'unknown')}"
                )
            elif component_key in component_keys:
                issues.append(f"Duplicate component after normalization: {component_key}")
            else:
                component_keys.add(component_key)

        # Check dependency reference validity using normalized keys
        dependencies = sbom_data.get("dependencies", [])
        for dep in dependencies:
            ref = dep.get("ref", "")
            depends_on = dep.get("dependsOn", [])

            if not ref:
                issues.append("Dependency missing ref field")
                continue

            if not depends_on:
                issues.append(f"Dependency {ref} has no dependsOn references")

            # Validate that referenced components exist (after normalization)
            for target_ref in depends_on:
                # Check if any component normalizes to this reference
                found = False
                for component in components:
                    if (
                        component.get("bom-ref") == target_ref
                        or self.component_processor.normalizer.normalize_component_key(component)
                        == target_ref
                    ):
                        found = True
                        break

                if not found:
                    issues.append(f"Dependency reference not found: {target_ref}")

        # Check for vulnerability data consistency
        vulnerabilities = sbom_data.get("vulnerabilities", [])
        if vulnerabilities:
            vuln_count = 0
            for vuln in vulnerabilities:
                if isinstance(vuln, dict) and vuln.get("id"):
                    vuln_count += 1
            if vuln_count == 0:
                issues.append("Vulnerabilities present but none have valid IDs")

        return len(issues) == 0, issues

    def get_component_stats(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Get statistics about components in the SBOM data.

        Args:
            sbom_data: SBOM data dictionary

        Returns:
            Dictionary with component statistics
        """
        components = sbom_data.get("components", [])

        if not components:
            return {
                "total_components": 0,
                "component_types": {},
                "vulnerable_components": 0,
                "components_with_licenses": 0,
            }

        # Count component types
        type_counts = {}
        vulnerable_count = 0
        license_count = 0

        for component in components:
            # Count by type
            comp_type = component.get("type", "unknown")
            type_counts[comp_type] = type_counts.get(comp_type, 0) + 1

            # Count vulnerabilities
            if component.get("vulnerabilities"):
                vulnerable_count += 1

            # Count licenses
            if component.get("licenses"):
                license_count += 1

        return {
            "total_components": len(components),
            "component_types": type_counts,
            "vulnerable_components": vulnerable_count,
            "components_with_licenses": license_count,
        }
