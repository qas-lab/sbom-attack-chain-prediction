"""
Core graph processing logic extracted from legacy generators.

This module provides the fundamental graph building and processing capabilities
that were previously embedded in f_graph_generator and h_graph_generator.
"""

import json
import logging
from pathlib import Path
from typing import Any

import networkx as nx

from .data_transformer import SBOMDataTransformer


class BaseGraphProcessor:
    """Base class for graph processing with common functionality."""

    def __init__(self):
        """Initialize the graph processor."""
        self.logger = logging.getLogger(__name__)
        self.data_transformer: SBOMDataTransformer = SBOMDataTransformer()

        # Standard color scheme for consistency across visualizations
        self.node_colors: dict[str, Any] = {
            "SBOM": "#808080",  # Grey for root
            "LIBRARY": {
                "SAFE": "#7FD13B",  # Green
                "WEAK": "#FFA500",  # Orange for dependent
                "VULN": "#FF5252",  # Red for vulnerable
                "DEFAULT": "#4169E1",  # Blue for default
            },
            "LICENSE": "#800080",  # Purple
        }

        # Standard size scheme
        self.node_sizes: dict[str, int] = {
            "SBOM": 80,
            "LIBRARY": 40,
            "LICENSE": 25,
        }

    def load_and_transform_sbom(self, sbom_path: Path) -> dict[str, Any]:
        """Load SBOM data and apply data transformation.

        Args:
            sbom_path: Path to SBOM JSON file

        Returns:
            Transformed SBOM data
        """
        try:
            with open(sbom_path) as f:
                sbom_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to load SBOM file {sbom_path}: {e}")
            raise

        # Transform and sanitize the data
        transformed_data = self.data_transformer.transform_sbom_data(sbom_data)

        # Validate data integrity
        is_valid, issues = self.data_transformer.validate_data_integrity(transformed_data)
        if not is_valid:
            self.logger.warning(f"Data integrity issues found: {issues}")

        return transformed_data

    def determine_component_status(self, component: dict[str, Any]) -> str:
        """Determine component status based on vulnerabilities.

        Args:
            component: Component data dictionary

        Returns:
            Status string ('VULN', 'WEAK', 'DEFAULT')
        """
        # Check for direct vulnerabilities
        vulnerabilities = component.get("vulnerabilities", [])
        if vulnerabilities:
            return "VULN"

        return "DEFAULT"

    def extract_license_name(self, license_info: Any) -> str | None:
        """Extract license name from various license info formats.

        Args:
            license_info: License information in various formats

        Returns:
            License name string or None if not found
        """
        if isinstance(license_info, str):
            return license_info
        elif isinstance(license_info, dict):
            if "license" in license_info:
                lic = license_info["license"]
                if isinstance(lic, dict):
                    return lic.get("name", lic.get("id"))
                else:
                    return str(lic)
            elif "name" in license_info:
                return license_info["name"]
        return None

    def create_abbreviated_label(self, full_label: str, node_type: str) -> str:
        """Create abbreviated label while preserving important information.

        Args:
            full_label: Full label text
            node_type: Type of node ('SBOM', 'LICENSE', 'LIBRARY')

        Returns:
            Abbreviated label
        """
        if node_type == "SBOM":
            return full_label
        elif node_type == "LICENSE":
            label = full_label.replace("License :: OSI Approved :: ", "")
            return label[:20] + "..." if len(label) > 20 else label
        else:  # LIBRARY
            if "==" in full_label:
                return full_label.split("==")[0]
            return full_label

    def _determine_license_type(self, license_name: str) -> str:
        """Determine the type/category of a license.

        Args:
            license_name: License name

        Returns:
            License type ('permissive', 'copyleft', 'proprietary', 'unknown')
        """
        license_lower = license_name.lower()

        # Permissive licenses
        permissive_keywords = [
            "mit",
            "bsd",
            "apache",
            "isc",
            "unlicense",
            "zlib",
            "boost",
        ]
        if any(keyword in license_lower for keyword in permissive_keywords):
            return "permissive"

        # Copyleft licenses
        copyleft_keywords = ["gpl", "lgpl", "agpl", "mpl", "epl", "cpl", "cddl"]
        if any(keyword in license_lower for keyword in copyleft_keywords):
            return "copyleft"

        # Proprietary/commercial
        proprietary_keywords = ["proprietary", "commercial", "closed"]
        if any(keyword in license_lower for keyword in proprietary_keywords):
            return "proprietary"

        return "unknown"

    def _extract_license_url(self, license_data: dict[str, Any]) -> str | None:
        """Extract license URL from license data.

        Args:
            license_data: License data dictionary

        Returns:
            License URL if found
        """
        if not isinstance(license_data, dict):
            return None

        # Check various possible URL fields
        url_fields = ["url", "licenseUrl", "license_url", "reference"]
        for field in url_fields:
            if field in license_data:
                return license_data[field]

        # Check nested license object
        if "license" in license_data and isinstance(license_data["license"], dict):
            for field in url_fields:
                if field in license_data["license"]:
                    return license_data["license"][field]

        return None

    def build_vulnerability_info(
        self, component_id: str, component: dict[str, Any], sbom_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Build comprehensive vulnerability information for a component.

        Args:
            component_id: Component identifier
            component: Component data
            sbom_data: Full SBOM data

        Returns:
            List of vulnerability information dictionaries
        """
        vulnerability_info = []

        # Check component-level vulnerabilities
        component_vulns = component.get("vulnerabilities", [])

        # Check top-level SBOM vulnerabilities that affect this component
        top_level_vulns = []
        for vuln in sbom_data.get("vulnerabilities", []):
            for affect in vuln.get("affects", []):
                if affect.get("ref") == component_id:
                    top_level_vulns.append(vuln)
                    break

        # Process all relevant vulnerabilities
        all_vulns = component_vulns + top_level_vulns

        for vuln in all_vulns:
            # Determine the best ID to use - prefer cve_id or source_id over literal "unknown"
            raw_id = vuln.get("id", "")
            cve_id = vuln.get("cve_id", "")
            source_id = vuln.get("source_id", "")

            # Use raw_id only if it's meaningful (not empty and not "unknown")
            if raw_id and raw_id.lower() != "unknown":
                best_id = raw_id
            elif cve_id and cve_id.lower() != "unknown":
                best_id = cve_id
            elif source_id and source_id.lower() != "unknown":
                best_id = source_id
            else:
                best_id = "Unknown"

            vuln_info = {
                "id": best_id,
                "cve_id": cve_id if cve_id else "Unknown",
                "source_id": source_id if source_id else "Unknown",
                "description": vuln.get("description", "No description available"),
                "cvss_score": vuln.get("cvss_score"),
                "cvss_severity": vuln.get("cvss_severity", "Unknown"),
                "cvss_vector": vuln.get("cvss_vector", "N/A"),
                "published_date": vuln.get("published_date"),
                "modified_date": vuln.get("modified_date"),
                "references": vuln.get("references", []),
                "affected_versions": vuln.get("affected_versions", ["Unknown"]),
                "fixed_versions": vuln.get("fixed_versions", ["Unknown"]),
            }
            vulnerability_info.append(vuln_info)

        return vulnerability_info


class NetworkGraphProcessor(BaseGraphProcessor):
    """Processor for creating NetworkX graphs suitable for network layouts."""

    def __init__(self):
        """Initialize the network graph processor."""
        super().__init__()
        self.graph = nx.Graph()

    def create_graph_from_sbom(self, sbom_data: dict[str, Any]) -> nx.Graph:
        """Create NetworkX graph from SBOM data.

        Args:
            sbom_data: Transformed SBOM data

        Returns:
            NetworkX Graph object
        """
        self.graph = nx.Graph()

        # Extract root information
        root_ref = self._extract_root_reference(sbom_data)
        self._add_root_node(root_ref, sbom_data)

        # Process components
        self._process_components(sbom_data)

        # Process dependencies
        self._process_dependencies(sbom_data, root_ref)

        # Calculate node layers based on vulnerability propagation
        self._calculate_vulnerability_layers()

        return self.graph

    def _extract_root_reference(self, sbom_data: dict[str, Any]) -> str:
        """Extract root component reference from SBOM metadata.

        Args:
            sbom_data: SBOM data

        Returns:
            Root component reference
        """
        metadata = sbom_data.get("metadata", {})
        component = metadata.get("component", {})

        root_ref = component.get("bom-ref")
        if not root_ref:
            root_name = component.get("name", "Unknown Project")
            root_version = component.get("version", "N/A")

            # Try to get name from repository info if component name is generic
            if root_name in ["Unknown Project", ""]:
                repo_info = metadata.get("repository", {})
                if isinstance(repo_info, dict) and repo_info.get("name"):
                    root_name = repo_info["name"]

            root_ref = f"{root_name}=={root_version}"

        return root_ref

    def _add_root_node(self, root_ref: str, sbom_data: dict[str, Any]):
        """Add root node to the graph.

        Note: The root_ref parameter must NOT be modified - it's used for
        consistent node identification throughout the graph building process.

        Args:
            root_ref: Root reference identifier
            sbom_data: SBOM data
        """
        metadata = sbom_data.get("metadata", {})
        component = metadata.get("component", {})

        # Skip adding root node if it's a container (Docker scanning artifact)
        component_type = component.get("type", "").lower()
        if component_type == "container":
            self.logger.debug(f"Skipping container root node: {root_ref}")
            return

        # Skip if the component should be excluded based on data transformer rules
        if self.data_transformer.should_exclude_component(component):
            self.logger.debug(f"Skipping excluded root component: {root_ref}")
            return

        root_name = component.get("name", "Unknown Project")
        root_version = component.get("version", "N/A")

        # If we have repository information, prefer that for naming (display only)
        repo_info = metadata.get("repository", {})
        if isinstance(repo_info, dict) and repo_info.get("name"):
            repo_name = repo_info["name"]
            if root_name in ["Unknown Project", "", repo_name]:
                root_name = repo_name
                # NOTE: Do NOT modify root_ref here - it must match what's
                # used in _process_dependencies

        full_label = f"{root_name}=={root_version}"
        abbreviated_label = self.create_abbreviated_label(full_label, "LIBRARY")
        description = component.get("description", "")

        self.graph.add_node(
            root_ref,
            type="LIBRARY",
            status="DEFAULT",
            color=self.node_colors["LIBRARY"]["DEFAULT"],
            size=self.node_sizes["LIBRARY"],
            full_label=full_label,
            abbreviated_label=abbreviated_label,
            description=description,
            is_root=True,
        )

    def _process_components(self, sbom_data: dict[str, Any]):
        """Process and add component nodes to the graph.

        Note: Uses bom-ref as node ID to match dependency references.
        Falls back to normalized ID if bom-ref is not available.

        Args:
            sbom_data: SBOM data
        """
        for component in sbom_data.get("components", []):
            # Use bom-ref as node ID since dependencies reference it
            component_id = component.get("bom-ref")
            if not component_id:
                # Fallback to normalized ID if bom-ref not available
                component_id = self.data_transformer.create_unique_id(component)

            # Skip if already added (like root component)
            if self.graph.has_node(component_id):
                continue

            status = self.determine_component_status(component)
            node_style = self.node_colors["LIBRARY"][status]

            full_label = (
                f"{component.get('name', 'Unknown')}=={component.get('version', 'unknown')}"
            )
            abbreviated_label = self.create_abbreviated_label(full_label, "LIBRARY")

            self.graph.add_node(
                component_id,
                type="LIBRARY",
                status=status,
                color=node_style,
                size=self.node_sizes["LIBRARY"],
                full_label=full_label,
                abbreviated_label=abbreviated_label,
                description=component.get("description", ""),
                vulnerabilities=self.build_vulnerability_info(component_id, component, sbom_data),
            )

            # Process licenses for this component
            self._process_component_licenses(component_id, component)

    def _process_component_licenses(self, component_id: str, component: dict[str, Any]):
        """Process and store license information as component attributes.

        Args:
            component_id: Component identifier
            component: Component data
        """
        licenses = component.get("licenses", [])
        license_info = []

        for license_data in licenses:
            license_name = self.extract_license_name(license_data)
            if license_name:
                # Store license as component attribute instead of separate node
                license_details = {
                    "name": license_name,
                    "type": self._determine_license_type(license_name),
                    "url": (
                        self._extract_license_url(license_data)
                        if isinstance(license_data, dict)
                        else None
                    ),
                }
                license_info.append(license_details)

        # Add license information to the component node
        if self.graph.has_node(component_id) and license_info:
            self.graph.nodes[component_id]["licenses"] = license_info

    def _process_dependencies(self, sbom_data: dict[str, Any], root_ref: str):
        """Process dependency relationships and add edges.

        Args:
            sbom_data: SBOM data
            root_ref: Root component reference
        """
        dependencies = sbom_data.get("dependencies", [])

        if not dependencies:
            self.logger.warning("No dependencies found in SBOM data")
            self._create_fallback_structure()
            return

        # Create a mapping of component identifiers for fuzzy matching
        component_refs = {}
        for node_id in self.graph.nodes():
            component_refs[node_id] = node_id
            # Also map by simplified name for fuzzy matching
            if "==" in node_id:
                name_part = node_id.split("==")[0]
                if name_part not in component_refs:
                    component_refs[name_part] = node_id

        edges_created = 0
        dependencies_processed = 0

        for dep in dependencies:
            source_ref = dep.get("ref")
            if not source_ref:
                continue

            dependencies_processed += 1

            # Try exact match first, then fuzzy match
            matched_source = component_refs.get(source_ref)
            if not matched_source and "==" in source_ref:
                name_part = source_ref.split("==")[0]
                matched_source = component_refs.get(name_part)

            if not matched_source or not self.graph.has_node(matched_source):
                continue

            # Add edge from root to direct dependencies
            if (
                self.graph.nodes[matched_source].get("type") != "LICENSE"
                and matched_source != root_ref
                and self.graph.has_node(root_ref)
            ):
                if not self.graph.has_edge(root_ref, matched_source):
                    self.graph.add_edge(
                        root_ref,
                        matched_source,
                        weight=2,
                        color="#a8a8a8",
                        relationship="direct",
                    )
                    edges_created += 1

            # Add dependency edges
            # If source is root, dependencies are "direct", otherwise "transitive"
            depends_on_list = dep.get("dependsOn", [])
            is_root_deps = matched_source == root_ref

            for target_ref in depends_on_list:
                if not target_ref:
                    continue

                # Try exact match first, then fuzzy match
                matched_target = component_refs.get(target_ref)
                if not matched_target and "==" in target_ref:
                    name_part = target_ref.split("==")[0]
                    matched_target = component_refs.get(name_part)

                if (
                    matched_target
                    and self.graph.has_node(matched_target)
                    and matched_source != matched_target
                    and self.graph.nodes[matched_target].get("type") != "LICENSE"
                ):
                    if not self.graph.has_edge(matched_source, matched_target):
                        # Root's dependencies are "direct", others are "transitive"
                        relationship = "direct" if is_root_deps else "transitive"
                        self.graph.add_edge(
                            matched_source,
                            matched_target,
                            weight=2 if is_root_deps else 1,
                            color="#a8a8a8",
                            relationship=relationship,
                        )
                        edges_created += 1

        self.logger.info(
            f"Processed {dependencies_processed} dependencies, created {edges_created} edges"
        )

        # If we still have many isolated components, run fallback structure
        isolated_count = sum(
            1
            for node in self.graph.nodes()
            if (
                self.graph.nodes[node].get("type") == "LIBRARY"
                and len(list(self.graph.neighbors(node))) == 0
            )
        )

        if isolated_count > len(list(self.graph.nodes())) * 0.3:  # More than 30% isolated
            self.logger.info(
                f"Many components still isolated ({isolated_count}), creating fallback structure"
            )
            self._create_fallback_structure()

    def _create_fallback_structure(self):
        """Create fallback visualization structure when dependencies are missing."""
        # Group components by licenses to create visual structure
        license_groups = {}
        components_without_licenses = []
        vulnerable_components = []
        safe_components = []

        for node_id, attrs in self.graph.nodes(data=True):
            if attrs.get("type") == "LIBRARY":
                # Get license information from component attributes
                component_licenses = attrs.get("licenses", [])

                if component_licenses:
                    # Group by first license (simple heuristic)
                    license_key = component_licenses[0]["name"]
                    if license_key not in license_groups:
                        license_groups[license_key] = []
                    license_groups[license_key].append(node_id)
                else:
                    components_without_licenses.append(node_id)

                # Categorize by vulnerability status
                if attrs.get("status") == "VULN":
                    vulnerable_components.append(node_id)
                else:
                    safe_components.append(node_id)

        # Create connections between components that share licenses
        connections_created = 0
        for _license_name, components in license_groups.items():
            if len(components) > 1:
                for i, comp1 in enumerate(components):
                    for comp2 in components[i + 1 :]:
                        if not self.graph.has_edge(comp1, comp2):
                            self.graph.add_edge(
                                comp1,
                                comp2,
                                weight=0.5,
                                color="#666666",
                                relationship="license_group",
                            )
                            connections_created += 1

        # Find root nodes to connect isolated components to
        root_nodes = [
            node for node, attrs in self.graph.nodes(data=True) if attrs.get("is_root", False)
        ]

        if root_nodes:
            root_node = root_nodes[0]

            # Connect vulnerable components to root with higher priority
            for vuln_comp in vulnerable_components:
                if not self.graph.has_edge(root_node, vuln_comp):
                    self.graph.add_edge(
                        root_node,
                        vuln_comp,
                        weight=1,
                        color="#ff6b6b",
                        relationship="vulnerability_focus",
                    )
                    connections_created += 1

            # Connect more safe components to create a better structure
            # Connect up to 50% of safe components to reduce isolation
            max_safe_connections = max(10, len(safe_components) // 2)
            for safe_comp in safe_components[:max_safe_connections]:
                if not self.graph.has_edge(root_node, safe_comp):
                    self.graph.add_edge(
                        root_node,
                        safe_comp,
                        weight=0.3,
                        color="#a8a8a8",
                        relationship="context",
                    )
                    connections_created += 1

            # For remaining isolated components, create a hub-and-spoke pattern
            # Group them and connect to intermediate hubs to reduce visual clutter
            isolated_components = []
            for node_id, attrs in self.graph.nodes(data=True):
                if attrs.get("type") == "LIBRARY" and len(list(self.graph.neighbors(node_id))) == 0:
                    isolated_components.append(node_id)

            # Create mini-hubs for groups of isolated components
            hub_size = 8
            for i in range(0, len(isolated_components), hub_size):
                group = isolated_components[i : i + hub_size]
                if len(group) > 1:
                    # Use first component in group as hub
                    hub_node = group[0]
                    # Connect hub to root
                    if not self.graph.has_edge(root_node, hub_node):
                        self.graph.add_edge(
                            root_node,
                            hub_node,
                            weight=0.2,
                            color="#cccccc",
                            relationship="hub",
                        )
                        connections_created += 1

                    # Connect other components in group to hub
                    for comp in group[1:]:
                        if not self.graph.has_edge(hub_node, comp):
                            self.graph.add_edge(
                                hub_node,
                                comp,
                                weight=0.1,
                                color="#dddddd",
                                relationship="spoke",
                            )
                            connections_created += 1

        self.logger.info(f"Created fallback structure with {connections_created} connections")

    def _calculate_vulnerability_layers(self):
        """Calculate node layers based on vulnerability status and propagation."""
        vulnerable_nodes = set()
        dependent_nodes = set()

        # Identify vulnerable nodes
        for node, attrs in self.graph.nodes(data=True):
            if attrs.get("status") == "VULN" and attrs.get("type") != "LICENSE":
                vulnerable_nodes.add(node)

        # Find nodes dependent on vulnerable components
        for node in vulnerable_nodes:
            for neighbor in self.graph.neighbors(node):
                if neighbor not in vulnerable_nodes:
                    edge_data = self.graph.get_edge_data(node, neighbor)
                    if edge_data and edge_data.get("relationship") != "license":
                        dependent_nodes.add(neighbor)

        # Update node attributes
        for node, attrs in self.graph.nodes(data=True):
            if node in vulnerable_nodes:
                attrs["layer"] = 1
                attrs["status"] = "VULN"
                attrs["color"] = self.node_colors["LIBRARY"]["VULN"]
            elif node in dependent_nodes:
                attrs["layer"] = 2
                attrs["status"] = "WEAK"
                attrs["color"] = self.node_colors["LIBRARY"]["WEAK"]
            else:
                attrs["layer"] = 3
                if attrs.get("status") == "DEFAULT":
                    attrs["color"] = self.node_colors["LIBRARY"]["DEFAULT"]


class HierarchicalGraphProcessor(BaseGraphProcessor):
    """Processor for creating directed graphs suitable for hierarchical layouts."""

    def __init__(self):
        """Initialize the hierarchical graph processor."""
        super().__init__()
        self.graph = nx.DiGraph()

    def create_hierarchy_from_sbom(self, sbom_data: dict[str, Any]) -> nx.DiGraph:
        """Create hierarchical directed graph from SBOM data.

        Args:
            sbom_data: Transformed SBOM data

        Returns:
            NetworkX DiGraph object
        """
        self.graph = nx.DiGraph()

        # Extract root information
        root_ref = self._extract_root_reference(sbom_data)
        self._add_root_node(root_ref, sbom_data)

        # Process components
        self._process_components(sbom_data)

        # Process dependencies with hierarchy
        self._process_hierarchical_dependencies(sbom_data, root_ref)

        return self.graph

    def _extract_root_reference(self, sbom_data: dict[str, Any]) -> str:
        """Extract root component reference from SBOM metadata."""
        # Same logic as NetworkGraphProcessor
        metadata = sbom_data.get("metadata", {})
        component = metadata.get("component", {})

        root_ref = component.get("bom-ref")
        if not root_ref:
            root_name = component.get("name", "Unknown Project")
            root_version = component.get("version", "N/A")

            if root_name in ["Unknown Project", ""]:
                repo_info = metadata.get("repository", {})
                if isinstance(repo_info, dict) and repo_info.get("name"):
                    root_name = repo_info["name"]

            root_ref = f"{root_name}=={root_version}"

        return root_ref

    def _add_root_node(self, root_ref: str, sbom_data: dict[str, Any]):
        """Add root node to the directed graph.

        Note: The root_ref parameter must NOT be modified - it's used for
        consistent node identification throughout the graph building process.
        """
        metadata = sbom_data.get("metadata", {})
        component = metadata.get("component", {})

        # Skip adding root node if it's a container (Docker scanning artifact)
        component_type = component.get("type", "").lower()
        if component_type == "container":
            self.logger.debug(f"Skipping container root node: {root_ref}")
            return

        # Skip if the component should be excluded based on data transformer rules
        if self.data_transformer.should_exclude_component(component):
            self.logger.debug(f"Skipping excluded root component: {root_ref}")
            return

        root_name = component.get("name", "Unknown Project")
        root_version = component.get("version", "N/A")

        # If we have repository information, prefer that for naming (display only)
        repo_info = metadata.get("repository", {})
        if isinstance(repo_info, dict) and repo_info.get("name"):
            repo_name = repo_info["name"]
            if root_name in ["Unknown Project", "", repo_name]:
                root_name = repo_name
                # NOTE: Do NOT modify root_ref here - it must match what's
                # used in _process_hierarchical_dependencies

        full_label = f"{root_name}=={root_version}"
        abbreviated_label = self.create_abbreviated_label(full_label, "LIBRARY")
        description = component.get("description", "")

        self.graph.add_node(
            root_ref,
            type="LIBRARY",
            status="DEFAULT",
            color=self.node_colors["LIBRARY"]["DEFAULT"],
            size=self.node_sizes["LIBRARY"],
            full_label=full_label,
            abbreviated_label=abbreviated_label,
            description=description,
            is_root=True,
        )

    def _process_components(self, sbom_data: dict[str, Any]):
        """Process and add component nodes to the directed graph.

        Note: Uses bom-ref as node ID to match dependency references.
        Falls back to normalized ID if bom-ref is not available.
        """
        for component in sbom_data.get("components", []):
            # Use bom-ref as node ID since dependencies reference it
            component_id = component.get("bom-ref")
            if not component_id:
                # Fallback to normalized ID if bom-ref not available
                component_id = self.data_transformer.create_unique_id(component)

            if self.graph.has_node(component_id):
                continue

            status = self.determine_component_status(component)
            node_style = self.node_colors["LIBRARY"][status]

            full_label = (
                f"{component.get('name', 'Unknown')}=={component.get('version', 'unknown')}"
            )
            abbreviated_label = self.create_abbreviated_label(full_label, "LIBRARY")

            self.graph.add_node(
                component_id,
                type="LIBRARY",
                status=status,
                color=node_style,
                size=self.node_sizes["LIBRARY"],
                full_label=full_label,
                abbreviated_label=abbreviated_label,
                description=component.get("description", ""),
                vulnerabilities=self.build_vulnerability_info(component_id, component, sbom_data),
            )

            # Process licenses as child nodes
            self._process_component_licenses(component_id, component)

    def _process_component_licenses(self, component_id: str, component: dict[str, Any]):
        """Process and store license information as component attributes."""
        licenses = component.get("licenses", [])
        license_info = []

        for license_data in licenses:
            license_name = self.extract_license_name(license_data)
            if license_name:
                # Store license as component attribute instead of separate node
                license_details = {
                    "name": license_name,
                    "type": self._determine_license_type(license_name),
                    "url": (
                        self._extract_license_url(license_data)
                        if isinstance(license_data, dict)
                        else None
                    ),
                }
                license_info.append(license_details)

        # Add license information to the component node
        if self.graph.has_node(component_id) and license_info:
            self.graph.nodes[component_id]["licenses"] = license_info

    def _process_hierarchical_dependencies(self, sbom_data: dict[str, Any], root_ref: str):
        """Process dependencies as hierarchical parent-child relationships.

        Creates edges in the graph:
        - root -> direct dependencies (relationship="direct")
        - parent -> child dependencies (relationship="transitive")

        Handles SBOMs where the root component has no explicit dependency entry
        by treating top-level components as direct dependencies.
        """
        dependencies = sbom_data.get("dependencies", [])

        if not dependencies:
            self.logger.warning("No dependencies found in SBOM data")
            return

        # Collect all refs and all targets to find top-level components
        all_refs = set()
        all_targets = set()
        for dep in dependencies:
            ref = dep.get("ref")
            if ref:
                all_refs.add(ref)
                for target in dep.get("dependsOn", []):
                    if target:
                        all_targets.add(target)

        # Top-level components: have dependency entries but not depended upon
        top_level_components = all_refs - all_targets

        # Check if root has explicit dependencies
        root_has_deps = any(dep.get("ref") == root_ref for dep in dependencies)

        # If root has no explicit deps, add edges to top-level components
        if not root_has_deps and self.graph.has_node(root_ref):
            for comp_ref in top_level_components:
                if (
                    self.graph.has_node(comp_ref)
                    and self.graph.nodes[comp_ref].get("type") != "LICENSE"
                ):
                    self.graph.add_edge(root_ref, comp_ref, relationship="direct")
                    self.logger.debug(f"Added direct edge: {root_ref} -> {comp_ref}")

        # Process all dependency entries
        for dep in dependencies:
            source_ref = dep.get("ref")
            depends_on_list = dep.get("dependsOn", [])

            if not source_ref:
                continue

            # Determine if this is the root's dependencies or a component's dependencies
            is_root_deps = source_ref == root_ref

            for target_ref in depends_on_list:
                if not target_ref:
                    continue
                if not self.graph.has_node(target_ref):
                    continue
                if self.graph.nodes[target_ref].get("type") == "LICENSE":
                    continue

                if is_root_deps:
                    # Root's dependencies are "direct"
                    self.graph.add_edge(root_ref, target_ref, relationship="direct")
                else:
                    # Component's dependencies are "transitive"
                    # First ensure the source node exists in the graph
                    if self.graph.has_node(source_ref):
                        self.graph.add_edge(source_ref, target_ref, relationship="transitive")
