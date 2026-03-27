"""
Enhanced SBOM visualization combining pyvis with advanced D3.js features.

This module provides sophisticated interactive visualizations with:
- Advanced tooltip system with vulnerability details
- Edge visibility controls (direct, transitive, license, vulnerable paths)
- GNN prediction integration
- Multiple layout algorithms
- Vulnerability highlighting and analysis
"""

import json
import logging
from pathlib import Path
from typing import Any

from ..shared.exceptions import SBOMError, create_error_context

# Use Any for type hints to avoid conditional import issues
NetworkType = Any

try:
    import networkx as nx
    from pyvis.network import Network

    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False
    Network = None  # type: ignore[misc,assignment]
    nx = None  # type: ignore[misc,assignment]


class PyvisVisualizer:
    """Interactive SBOM visualization using pyvis."""

    def __init__(self, width: str = "100%", height: str = "600px", layout: str = "force_directed"):
        """Initialize enhanced pyvis visualizer.

        Args:
            width: Network width
            height: Network height
            layout: Layout algorithm ("force_directed", "hierarchical", "circular")

        Raises:
            SBOMError: If pyvis is not available
        """
        if not PYVIS_AVAILABLE:
            raise SBOMError(
                "pyvis is not available. Install with: pip install pyvis",
                create_error_context(operation="visualizer_init"),
            )

        self.width = width
        self.height = height
        self.layout = layout
        self.logger = logging.getLogger(__name__)
        self.gnn_predictions = {}

        # Enhanced color scheme matching D3.js implementations
        self.node_colors: dict[str, Any] = {
            "SBOM": "#808080",  # Grey for root
            "LIBRARY": {
                "SAFE": "#7FD13B",  # Green
                "WEAK": "#FFA500",  # Orange for dependent
                "VULN": "#FF5252",  # Red for vulnerable
                "DEFAULT": "#4169E1",  # Blue for default
            },
            "LICENSE": "#800080",  # Purple
            "repository": "#2E86AB",  # Blue (legacy)
            "library": "#A23B72",  # Purple (legacy)
            "vulnerable": "#F18F01",  # Orange (legacy)
            "critical": "#C73E1D",  # Red (legacy)
            "dependency": "#795548",  # Brown (legacy)
        }

        # Enhanced size scheme
        self.node_sizes: dict[str, int] = {
            "SBOM": 80,
            "LIBRARY": 40,
            "LICENSE": 25,
            "repository": 50,  # legacy
            "library": 30,  # legacy
            "vulnerable": 35,  # legacy
            "critical": 40,  # legacy
            "dependency": 25,  # legacy
        }

    def load_gnn_predictions(self, predictions: dict[str, Any]) -> None:
        """Load GNN predictions for vulnerability analysis.

        Args:
            predictions: Dictionary mapping component IDs to prediction data
        """
        self.gnn_predictions = predictions or {}
        self.logger.info("Loaded %d GNN predictions", len(self.gnn_predictions))

    def _get_component_status_and_color(
        self, component: dict[str, Any], component_id: str
    ) -> dict[str, Any]:
        """Determine component status and visual properties based on vulnerabilities and dependencies.

        Args:
            component: Component data from SBOM
            component_id: Component identifier

        Returns:
            Dictionary with color, size, shape, and status information
        """
        # Check for direct vulnerabilities
        vulnerabilities = component.get("vulnerabilities", [])
        has_vulnerabilities = bool(vulnerabilities)

        # Check for critical vulnerabilities
        has_critical = any(
            vuln.get("cvss_severity", "").upper() == "CRITICAL"
            or vuln.get("severity", "").upper() == "CRITICAL"
            for vuln in vulnerabilities
        )

        # Check GNN prediction if available
        gnn_prediction = self.gnn_predictions.get(component_id, {})
        gnn_vulnerable = gnn_prediction.get("prediction") == "Vulnerable"

        if has_critical:
            return {
                "color": self.node_colors["LIBRARY"]["VULN"],
                "size": self.node_sizes["LIBRARY"] + 10,
                "shape": "triangle",
                "status": "VULN",
                "is_vulnerable": True,
                "is_dependent": False,
            }
        elif has_vulnerabilities or gnn_vulnerable:
            return {
                "color": self.node_colors["LIBRARY"]["VULN"],
                "size": self.node_sizes["LIBRARY"] + 5,
                "shape": "diamond",
                "status": "VULN",
                "is_vulnerable": True,
                "is_dependent": False,
            }
        else:
            # Default safe component
            return {
                "color": self.node_colors["LIBRARY"]["DEFAULT"],
                "size": self.node_sizes["LIBRARY"],
                "shape": "dot",
                "status": "DEFAULT",
                "is_vulnerable": False,
                "is_dependent": False,
            }

    def _create_enhanced_tooltip(
        self, component: dict[str, Any], component_id: str, node_props: dict[str, Any]
    ) -> str:
        """Create enhanced tooltip with vulnerability details and GNN predictions.

        Args:
            component: Component data
            component_id: Component identifier
            node_props: Node visual properties

        Returns:
            HTML string for tooltip
        """
        name = component.get("name", "Unknown")
        version = component.get("version", "Unknown")
        comp_type = component.get("type", "library")

        tooltip = f"""
        <div style="max-width: 400px; font-family: Arial, sans-serif;">
            <h3 style="margin: 0 0 10px 0; color: #333;">{name}</h3>
            <p><strong>Version:</strong> {version}</p>
            <p><strong>Type:</strong> {comp_type}</p>
        """

        # Add GNN prediction if available
        gnn_prediction = self.gnn_predictions.get(component_id)
        if gnn_prediction:
            prediction = gnn_prediction.get("prediction", "Unknown")
            confidence = gnn_prediction.get("confidence", 0.0)
            confidence_percent = f"{confidence * 100:.1f}%"

            gnn_color = "#E69500" if prediction == "Vulnerable" else "#28a745"
            tooltip += f"""
            <div style="background-color: #f0f0f0; padding: 8px; border-radius: 4px; margin: 10px 0;">
                <h4 style="margin: 0 0 5px 0; font-size: 14px;">GNN Analysis</h4>
                <p style="margin: 3px 0;">Prediction: <strong style="color:{gnn_color};">{prediction}</strong></p>
                <p style="margin: 3px 0;">Confidence: {confidence_percent}</p>
            </div>
            """

        # Add vulnerability details
        vulnerabilities = component.get("vulnerabilities", [])
        if vulnerabilities and node_props.get("is_vulnerable"):
            tooltip += """
            <div style="background-color: #fff5f5; padding: 8px; border-radius: 4px; margin: 10px 0; border-left: 3px solid #ff5252;">
                <h4 style="margin: 0 0 8px 0; color: #d32f2f; font-size: 14px;">Vulnerabilities</h4>
            """

            for vuln in vulnerabilities[:3]:  # Limit to first 3 vulnerabilities
                vuln_id = vuln.get("id", vuln.get("cve_id", "Unknown"))
                severity = vuln.get("cvss_severity", vuln.get("severity", "Unknown"))
                cvss_score = vuln.get("cvss_score", "N/A")
                description = vuln.get("description", "No description available")

                tooltip += f"""
                <div style="margin-bottom: 8px; padding: 6px; background-color: white; border-radius: 3px;">
                    <strong>{vuln_id}</strong><br>
                    <small>Severity: {severity} | CVSS: {cvss_score}</small><br>
                    <small style="color: #666;">{description[:100]}{"..." if len(description) > 100 else ""}</small>
                </div>
                """

            if len(vulnerabilities) > 3:
                tooltip += f"<small>...and {len(vulnerabilities) - 3} more vulnerabilities</small>"

            tooltip += "</div>"

        elif node_props.get("is_dependent"):
            tooltip += """
            <div style="background-color: #fff8e1; padding: 8px; border-radius: 4px; margin: 10px 0; border-left: 3px solid #ffa500;">
                <h4 style="margin: 0 0 5px 0; color: #ff8f00; font-size: 14px;">Dependency Warning</h4>
                <p style="margin: 0; font-size: 13px;">This component depends on vulnerable packages.</p>
            </div>
            """
        else:
            tooltip += """
            <div style="background-color: #e8f5e8; padding: 8px; border-radius: 4px; margin: 10px 0;">
                <p style="margin: 0; color: #2e7d32; font-size: 13px;">✓ No known vulnerabilities</p>
            </div>
            """

        # Add licenses if available
        licenses = component.get("licenses", [])
        if licenses:
            tooltip += """
            <div style="background-color: #f3e5f5; padding: 8px; border-radius: 4px; margin: 10px 0;">
                <h4 style="margin: 0 0 5px 0; color: #7b1fa2; font-size: 14px;">Licenses</h4>
            """
            for license_info in licenses[:2]:  # Limit to first 2 licenses
                if isinstance(license_info, dict):
                    license_name = license_info.get("license", {}).get("name", "Unknown")
                else:
                    license_name = str(license_info)
                tooltip += f"<small>• {license_name}</small><br>"
            tooltip += "</div>"

        tooltip += "</div>"
        return tooltip

    def _create_root_tooltip(self, metadata: dict[str, Any]) -> str:
        """Create enhanced tooltip for root node.

        Args:
            metadata: SBOM metadata

        Returns:
            HTML string for root tooltip
        """
        component_info = metadata.get("component", {})
        repo_info = metadata.get("repository", {})

        tooltip = """
        <div style="max-width: 400px; font-family: Arial, sans-serif;">
            <h3 style="margin: 0 0 10px 0; color: #333;">Project Root</h3>
        """

        if component_info:
            name = component_info.get("name", "Unknown Project")
            version = component_info.get("version", "N/A")
            description = component_info.get("description", "")

            tooltip += f"""
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Version:</strong> {version}</p>
            """
            if description:
                tooltip += f"<p><strong>Description:</strong> {description}</p>"

        if repo_info:
            repo_name = repo_info.get("name", "")
            repo_url = repo_info.get("url", "")
            owner = repo_info.get("owner", "")

            if repo_name or repo_url or owner:
                tooltip += """
                <div style="background-color: #e3f2fd; padding: 8px; border-radius: 4px; margin: 10px 0;">
                    <h4 style="margin: 0 0 5px 0; color: #1976d2; font-size: 14px;">Repository</h4>
                """
                if repo_name:
                    tooltip += f"<p style='margin: 3px 0;'>Name: {repo_name}</p>"
                if owner:
                    tooltip += f"<p style='margin: 3px 0;'>Owner: {owner}</p>"
                if repo_url:
                    tooltip += f"<p style='margin: 3px 0;'>URL: <a href='{repo_url}' target='_blank'>{repo_url}</a></p>"
                tooltip += "</div>"

        # Add SBOM generation info
        sbom_generated = metadata.get("timestamp", metadata.get("sbom_generated_at", ""))
        if sbom_generated:
            tooltip += f"""
            <div style="background-color: #f0f0f0; padding: 8px; border-radius: 4px; margin: 10px 0;">
                <h4 style="margin: 0 0 5px 0; font-size: 14px;">SBOM Info</h4>
                <p style="margin: 3px 0;">Generated: {sbom_generated}</p>
            </div>
            """

        tooltip += "</div>"
        return tooltip

    def _add_dependency_relationships(
        self, net: NetworkType, sbom_data: dict[str, Any], vulnerable_components: set
    ) -> None:
        """Add dependency relationships and update dependent node colors.

        Args:
            net: Pyvis network object
            sbom_data: SBOM data
            vulnerable_components: Set of component IDs that are vulnerable
        """
        dependencies = sbom_data.get("dependencies", [])
        dependent_components = set()

        # Process dependencies to find components that depend on vulnerable ones
        for dep in dependencies:
            source_ref = dep.get("ref")
            depends_on = dep.get("dependsOn", [])

            if source_ref and depends_on:
                # Check if any dependency is vulnerable
                has_vulnerable_dep = any(dep_id in vulnerable_components for dep_id in depends_on)

                if has_vulnerable_dep and source_ref not in vulnerable_components:
                    dependent_components.add(source_ref)

                # Add dependency edges
                for target_ref in depends_on:
                    if source_ref != target_ref:  # Avoid self-loops
                        edge_color = "#FF5252" if target_ref in vulnerable_components else "#cccccc"
                        edge_width = 3 if target_ref in vulnerable_components else 1

                        net.add_edge(
                            source=source_ref,
                            to=target_ref,
                            color=edge_color,
                            width=edge_width,
                            label="depends on",
                        )

        # Update colors of dependent components
        for node in net.nodes:
            if node["id"] in dependent_components:
                node["color"] = self.node_colors["LIBRARY"]["WEAK"]
                node["shape"] = "square"
                # Update tooltip to reflect dependency status
                current_title = node.get("title", "")
                if "Dependency Warning" not in current_title:
                    dependency_warning = """
                    <div style="background-color: #fff8e1; padding: 8px; border-radius: 4px; margin: 10px 0; border-left: 3px solid #ffa500;">
                        <h4 style="margin: 0 0 5px 0; color: #ff8f00; font-size: 14px;">Dependency Warning</h4>
                        <p style="margin: 0; font-size: 13px;">This component depends on vulnerable packages.</p>
                    </div>
                    """
                    node["title"] = current_title.replace("</div>", dependency_warning + "</div>")

        self.logger.info(
            "Added %d dependency relationships, identified %d dependent components",
            len(dependencies),
            len(dependent_components),
        )

    def _add_enhanced_license_nodes(self, net: NetworkType, sbom_data: dict[str, Any]) -> None:
        """Add enhanced license nodes with better organization.

        Args:
            net: Pyvis network object
            sbom_data: SBOM data
        """
        license_counts = {}
        component_licenses = {}

        # First pass: collect all licenses and their usage
        for component in sbom_data.get("components", []):
            component_id = self._get_component_id(component)
            licenses = component.get("licenses", [])
            component_licenses[component_id] = []

            for license_info in licenses:
                license_name = self._extract_license_name(license_info)
                if license_name:
                    component_licenses[component_id].append(license_name)
                    license_counts[license_name] = license_counts.get(license_name, 0) + 1

        # Add license nodes (only if used by multiple components or unique)
        added_licenses = set()
        for license_name, count in license_counts.items():
            if license_name not in added_licenses:
                license_id = f"license_{license_name.replace(' ', '_').replace('/', '_')}"

                # Create license tooltip
                license_tooltip = f"""
                <div style="max-width: 300px; font-family: Arial, sans-serif;">
                    <h3 style="margin: 0 0 10px 0; color: #7b1fa2;">{license_name}</h3>
                    <p>Used by {count} component{"s" if count > 1 else ""}</p>
                    <div style="background-color: #f3e5f5; padding: 8px; border-radius: 4px; margin: 10px 0;">
                        <p style="margin: 0; font-size: 13px;">This is an open source license.</p>
                    </div>
                </div>
                """

                # Size license nodes based on usage
                license_size = min(self.node_sizes["LICENSE"] + (count * 2), 40)

                net.add_node(
                    license_id,
                    label=license_name[:15] + ("..." if len(license_name) > 15 else ""),
                    color=self.node_colors["LICENSE"],
                    size=license_size,
                    title=license_tooltip,
                    shape="box",
                )
                added_licenses.add(license_name)

        # Add edges from components to licenses
        for component_id, licenses in component_licenses.items():
            for license_name in licenses:
                license_id = f"license_{license_name.replace(' ', '_').replace('/', '_')}"
                net.add_edge(
                    source=component_id,
                    to=license_id,
                    color="#90EE90",
                    width=1,
                    label="licensed under",
                )

        self.logger.info("Added %d license nodes with relationships", len(added_licenses))

    def _extract_license_name(self, license_info: Any) -> str:
        """Extract license name from various license info formats.

        Args:
            license_info: License information in various formats

        Returns:
            License name string or empty string if not found
        """
        if isinstance(license_info, str):
            return license_info
        elif isinstance(license_info, dict):
            if "license" in license_info:
                lic = license_info["license"]
                if isinstance(lic, dict):
                    return lic.get("name", lic.get("id", ""))
                else:
                    return str(lic)
            elif "name" in license_info:
                return license_info["name"]
        return ""

    def create_sbom_network(self, sbom_data: dict[str, Any]) -> NetworkType:
        """Create interactive network from SBOM data.

        Args:
            sbom_data: SBOM data dictionary

        Returns:
            Pyvis Network object

        Raises:
            SBOMError: If SBOM data is invalid
        """
        if not sbom_data or "components" not in sbom_data:
            raise SBOMError(
                "Invalid SBOM data: missing components",
                create_error_context(operation="create_network"),
            )

        if not PYVIS_AVAILABLE or Network is None:
            raise SBOMError(
                "pyvis is not available. Install with: pip install pyvis",
                create_error_context(operation="create_network"),
            )

        # Create pyvis network with enhanced configuration
        net = Network(
            width=self.width,
            height=self.height,
            bgcolor="#ffffff",
            font_color=False,
            directed=True,
        )

        # Enhanced physics configuration based on layout type
        if self.layout == "hierarchical":
            physics_config = """
            var options = {
              "physics": {
                "enabled": true,
                "hierarchicalRepulsion": {
                  "centralGravity": 0.0,
                  "springLength": 100,
                  "springConstant": 0.01,
                  "nodeDistance": 120,
                  "damping": 0.09
                }
              },
              "layout": {
                "hierarchical": {
                  "enabled": true,
                  "levelSeparation": 150,
                  "nodeSpacing": 100,
                  "treeSpacing": 200,
                  "blockShifting": true,
                  "edgeMinimization": true,
                  "parentCentralization": true,
                  "direction": "UD",
                  "sortMethod": "directed"
                }
              },
              "interaction": {
                "hover": true,
                "tooltipDelay": 200,
                "zoomView": true
              }
            }
            """
        elif self.layout == "circular":
            physics_config = """
            var options = {
              "physics": {
                "enabled": false
              },
              "interaction": {
                "hover": true,
                "tooltipDelay": 200,
                "zoomView": true
              }
            }
            """
        else:  # force_directed (default)
            physics_config = """
            var options = {
              "physics": {
                "enabled": true,
                "stabilization": {"iterations": 200},
                "barnesHut": {
                  "gravitationalConstant": -2000,
                  "centralGravity": 0.3,
                  "springLength": 95,
                  "springConstant": 0.04,
                  "damping": 0.09
                }
              },
              "interaction": {
                "hover": true,
                "tooltipDelay": 200,
                "zoomView": true
              }
            }
            """

        net.set_options(physics_config)

        # Add enhanced root node from metadata
        metadata = sbom_data.get("metadata", {})
        component_metadata = metadata.get("component", {})
        repo_info = metadata.get("repository", {})

        # Determine root node properties
        if component_metadata:
            root_name = component_metadata.get("name", "Project Root")
            root_version = component_metadata.get("version", "N/A")
            root_label = f"{root_name}=={root_version}"
            root_id = "sbom_root"
        else:
            root_name = repo_info.get("name", "Unknown Repository")
            root_label = root_name
            root_id = "repository"

        # Enhanced root tooltip
        root_tooltip = self._create_root_tooltip(metadata)

        net.add_node(
            root_id,
            label=root_label,
            color=self.node_colors["SBOM"],
            size=self.node_sizes["SBOM"],
            title=root_tooltip,
            shape="star",
        )

        # Track processed components and vulnerable nodes
        processed_components = set()
        vulnerable_components = set()

        # Add root component if it doesn't exist in components list
        if component_metadata:
            root_component_id = self._get_component_id(component_metadata)
            if root_component_id not in [
                self._get_component_id(c) for c in sbom_data.get("components", [])
            ]:
                # Add root as a component for dependency processing
                root_props = self._get_component_status_and_color(
                    component_metadata, root_component_id
                )
                root_tooltip = self._create_enhanced_tooltip(
                    component_metadata, root_component_id, root_props
                )

                net.add_node(
                    root_component_id,
                    label=component_metadata.get("name", "Project Root"),
                    color=root_props["color"],
                    size=self.node_sizes["SBOM"],  # Use SBOM size for root
                    title=root_tooltip,
                    shape="star",
                )
                processed_components.add(root_component_id)

        # First pass: Add all component nodes with enhanced properties
        for component in sbom_data.get("components", []):
            component_id = self._get_component_id(component)

            if component_id in processed_components:
                continue
            processed_components.add(component_id)

            # Determine enhanced node properties
            node_props = self._get_component_status_and_color(component, component_id)

            # Track vulnerable components for dependency analysis
            if node_props["is_vulnerable"]:
                vulnerable_components.add(component_id)

            # Create enhanced tooltip
            tooltip = self._create_enhanced_tooltip(component, component_id, node_props)

            # Add component node with enhanced properties
            net.add_node(
                component_id,
                label=component.get("name", "Unknown"),
                color=node_props["color"],
                size=node_props["size"],
                title=tooltip,
                shape=node_props["shape"],
            )

            # Add edge from root to component
            net.add_edge(source=root_id, to=component_id, color="#cccccc", width=2, label="uses")

        # Second pass: Add dependency edges and update dependent nodes
        self._add_dependency_relationships(net, sbom_data, vulnerable_components)

        # Add license relationships
        self._add_enhanced_license_nodes(net, sbom_data)

        self.logger.info(
            "Created enhanced network with %d nodes and %d edges",
            len(net.nodes),
            len(net.edges),
        )
        return net

    def save_interactive_html(self, net: NetworkType, output_path: Path) -> Path:
        """Save enhanced interactive HTML visualization.

        Args:
            net: Pyvis network
            output_path: Output file path

        Returns:
            Path to saved HTML file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate pyvis HTML content
        temp_path = output_path.with_suffix(".temp.html")
        net.save_graph(str(temp_path))

        # Read the generated pyvis HTML
        with open(temp_path, encoding="utf-8") as f:
            pyvis_content = f.read()

        # Extract body content and script tags needed for vis.js
        import re

        # Extract the body content
        body_match = re.search(r"<body[^>]*>(.*?)</body>", pyvis_content, re.DOTALL)
        if body_match:
            pyvis_body = body_match.group(1)
        else:
            pyvis_body = pyvis_content  # Fallback

        # Extract vis.js script tags from head section
        script_tags = re.findall(
            r"<script[^>]*(?:vis|cdnjs\.cloudflare\.com/ajax/libs/vis)[^>]*>.*?</script>",
            pyvis_content,
            re.DOTALL | re.IGNORECASE,
        )
        vis_scripts = "\n".join(script_tags)

        # Calculate statistics for the template
        stats = self._calculate_network_statistics(net)

        # Load and populate the enhanced template
        template_path = Path(__file__).parent / "templates" / "enhanced_pyvis_template.html"
        with open(template_path, encoding="utf-8") as f:
            template_content = f.read()

        # Replace template placeholders
        enhanced_html = template_content.replace("{{PYVIS_HTML}}", pyvis_body)
        enhanced_html = enhanced_html.replace(
            "{{TOTAL_COMPONENTS}}", str(stats["total_components"])
        )
        enhanced_html = enhanced_html.replace("{{TOTAL_LICENSES}}", str(stats["total_licenses"]))
        enhanced_html = enhanced_html.replace(
            "{{VULNERABLE_COUNT}}", str(stats["vulnerable_count"])
        )
        enhanced_html = enhanced_html.replace("{{SAFE_COUNT}}", str(stats["safe_count"]))

        # Inject vis.js scripts into the head section (before closing </head>)
        if vis_scripts:
            enhanced_html = enhanced_html.replace("</head>", f"{vis_scripts}\n</head>")

        # Save the enhanced HTML
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(enhanced_html)

        # Clean up temporary file
        if temp_path.exists():
            temp_path.unlink()

        self.logger.info("Enhanced interactive visualization saved to: %s", output_path)
        return output_path

    def _calculate_network_statistics(self, net: NetworkType) -> dict[str, int]:
        """Calculate statistics for the network.

        Args:
            net: Pyvis network object

        Returns:
            Dictionary with network statistics
        """
        total_components = 0
        total_licenses = 0
        vulnerable_count = 0
        safe_count = 0

        for node in net.nodes:
            node_id = str(node.get("id", ""))

            if "license_" in node_id:
                total_licenses += 1
            elif node_id not in ["repository", "sbom_root"]:
                total_components += 1

                # Check if node is vulnerable based on color or shape
                color = node.get("color", "")
                shape = node.get("shape", "")

                if color == self.node_colors["LIBRARY"]["VULN"] or shape in [
                    "triangle",
                    "diamond",
                ]:
                    vulnerable_count += 1
                else:
                    safe_count += 1

        return {
            "total_components": total_components,
            "total_licenses": total_licenses,
            "vulnerable_count": vulnerable_count,
            "safe_count": safe_count,
        }

    def create_dependency_graph(self, sbom_data: dict[str, Any]) -> NetworkType:
        """Create dependency-focused network visualization.

        Args:
            sbom_data: SBOM data dictionary

        Returns:
            Pyvis Network object focused on dependencies
        """
        if not PYVIS_AVAILABLE or Network is None:
            raise SBOMError(
                "pyvis is not available. Install with: pip install pyvis",
                create_error_context(operation="create_dependency_graph"),
            )

        net = Network(
            width=self.width,
            height=self.height,
            bgcolor="#f8f9fa",
            font_color=False,
            directed=True,
        )

        # Use NetworkX to analyze dependencies first
        if nx is None:
            raise SBOMError("NetworkX is required for dependency analysis")

        # Build NetworkX graph for analysis
        nx_graph = nx.DiGraph()

        # Add nodes and edges based on component relationships
        components = sbom_data.get("components", [])

        for component in components:
            comp_id = self._get_component_id(component)
            nx_graph.add_node(comp_id, **component)

            # Add dependencies if available (would need to parse from SBOM)
            # This is a simplified version - real implementation would parse dependency info

        # Calculate centrality measures
        centrality = nx.degree_centrality(nx_graph)

        # Add nodes to pyvis with sizing based on centrality
        for node_id, node_data in nx_graph.nodes(data=True):
            importance = centrality.get(node_id, 0.1)
            size = max(20, min(60, int(importance * 100)))

            net.add_node(
                node_id,
                label=node_data.get("name", node_id),
                size=size,
                color=self._get_centrality_color(importance),
                title=f"Centrality: {importance:.3f}",
            )

        # Add edges
        for source, target in nx_graph.edges():
            net.add_edge(source, target, color="#999999")

        return net

    def _get_component_id(self, component: dict[str, Any]) -> str:
        """Generate unique component ID."""
        # Check if component has a bom-ref first
        bom_ref = component.get("bom-ref")
        if bom_ref:
            return bom_ref

        # Otherwise generate from name and version
        name = component.get("name", "unknown")
        version = component.get("version", "unknown")
        return f"{name}=={version}"

    def _get_component_node_properties(self, component: dict[str, Any]) -> dict[str, Any]:
        """Determine node properties based on component data."""
        vulnerabilities = component.get("vulnerabilities", [])

        if not vulnerabilities:
            return {
                "color": self.node_colors["library"],
                "size": self.node_sizes["library"],
                "shape": "dot",
            }

        # Check for critical vulnerabilities
        has_critical = any(
            vuln.get("severity", "").upper() == "CRITICAL" for vuln in vulnerabilities
        )

        if has_critical:
            return {
                "color": self.node_colors["critical"],
                "size": self.node_sizes["critical"],
                "shape": "triangle",
            }
        else:
            return {
                "color": self.node_colors["vulnerable"],
                "size": self.node_sizes["vulnerable"],
                "shape": "diamond",
            }

    def _create_repo_tooltip(self, repo_info: dict[str, Any]) -> str:
        """Create tooltip for repository node."""
        return """
        <b>Repository:</b> {}<br>
        <b>Owner:</b> {}<br>
        <b>URL:</b> {}<br>
        <b>Commit:</b> {}...<br>
        <b>Generated:</b> {}
        """.format(
            repo_info.get("name", "Unknown"),
            repo_info.get("owner", "Unknown"),
            repo_info.get("url", "Unknown"),
            repo_info.get("commit", "Unknown")[:8],
            repo_info.get("sbom_generated_at", "Unknown"),
        )

    def _create_component_tooltip(self, component: dict[str, Any]) -> str:
        """Create tooltip for component node."""
        vulnerabilities = component.get("vulnerabilities", [])
        vuln_count = len(vulnerabilities)

        tooltip = """
        <b>Component:</b> {}<br>
        <b>Version:</b> {}<br>
        <b>Type:</b> {}<br>
        <b>Vulnerabilities:</b> {}
        """.format(
            component.get("name", "Unknown"),
            component.get("version", "Unknown"),
            component.get("type", "Unknown"),
            vuln_count,
        )

        if vulnerabilities:
            severities = [v.get("severity", "UNKNOWN") for v in vulnerabilities[:3]]
            tooltip += "<br><b>Top Severities:</b> {}".format(", ".join(severities))

        return tooltip

    def _add_license_nodes(
        self, net: NetworkType, component: dict[str, Any], component_id: str
    ) -> None:
        """Add license nodes and edges."""
        licenses = component.get("licenses", [])

        for license_info in licenses:
            license_name = None

            if isinstance(license_info, dict):
                if "license" in license_info:
                    license_name = license_info["license"].get("name")
                elif "name" in license_info:
                    license_name = license_info["name"]
            elif isinstance(license_info, str):
                license_name = license_info

            if license_name:
                license_id = f"license_{license_name}"

                # Add license node if not already added
                if license_id not in [node["id"] for node in net.nodes]:
                    net.add_node(
                        license_id,
                        label=license_name,
                        color=self.node_colors["license"],
                        size=self.node_sizes["license"],
                        title=f"License: {license_name}",
                        shape="box",
                    )

                # Add edge from component to license
                net.add_edge(source=component_id, to=license_id, color="#90EE90", width=1)

    def _add_vulnerability_nodes(
        self, net: NetworkType, component: dict[str, Any], component_id: str
    ) -> None:
        """Add vulnerability nodes and edges."""
        vulnerabilities = component.get("vulnerabilities", [])

        for vuln in vulnerabilities[:5]:  # Limit to first 5 vulnerabilities
            vuln_id = vuln.get("id", "unknown")
            severity = vuln.get("severity", "UNKNOWN").upper()

            # Determine vulnerability node color based on severity
            if severity == "CRITICAL":
                vuln_color = self.node_colors["critical"]
            elif severity in ["HIGH", "MEDIUM"]:
                vuln_color = self.node_colors["vulnerable"]
            else:
                vuln_color = "#FFC107"  # Yellow for low/unknown

            vuln_node_id = f"vuln_{vuln_id}"

            net.add_node(
                vuln_node_id,
                label=vuln_id,
                color=vuln_color,
                size=15,
                title=self._create_vulnerability_tooltip(vuln),
                shape="star",
            )

            # Add edge from component to vulnerability
            net.add_edge(source=component_id, to=vuln_node_id, color="#FF6B6B", width=2)

    def _create_vulnerability_tooltip(self, vuln: dict[str, Any]) -> str:
        """Create tooltip for vulnerability node."""
        return """
        <b>ID:</b> {}<br>
        <b>Severity:</b> {}<br>
        <b>CVSS Score:</b> {}<br>
        <b>Description:</b> {}...
        """.format(
            vuln.get("id", "Unknown"),
            vuln.get("severity", "Unknown"),
            vuln.get("cvss_score", "N/A"),
            vuln.get("description", "No description")[:100],
        )

    def _get_centrality_color(self, centrality: float) -> str:
        """Get color based on centrality score."""
        if centrality > 0.7:
            return "#8B0000"  # Dark red
        elif centrality > 0.5:
            return "#FF4500"  # Orange red
        elif centrality > 0.3:
            return "#FFA500"  # Orange
        elif centrality > 0.1:
            return "#FFD700"  # Gold
        else:
            return "#87CEEB"  # Sky blue


def create_sbom_visualization(
    sbom_path: Path,
    output_dir: Path,
    visualization_type: str = "standard",
    layout: str = "force_directed",
    gnn_predictions: dict[str, Any] | None = None,
) -> Path:
    """Create enhanced SBOM visualization using pyvis.

    Args:
        sbom_path: Path to SBOM JSON file
        output_dir: Output directory for visualization
        visualization_type: Type of visualization ("standard", "dependencies", "enhanced")
        layout: Layout algorithm ("force_directed", "hierarchical", "circular")
        gnn_predictions: Optional GNN predictions for vulnerability analysis

    Returns:
        Path to generated HTML file

    Raises:
        SBOMError: If visualization creation fails
    """
    try:
        # Load SBOM data
        with open(sbom_path, encoding="utf-8") as f:
            sbom_data = json.load(f)

        # Create enhanced visualizer
        visualizer = PyvisVisualizer(layout=layout)

        # Load GNN predictions if provided
        if gnn_predictions:
            visualizer.load_gnn_predictions(gnn_predictions)

        # Create appropriate network
        if visualization_type == "dependencies":
            net = visualizer.create_dependency_graph(sbom_data)
            output_filename = f"{sbom_path.stem}_{layout}_dependencies.html"
        else:
            net = visualizer.create_sbom_network(sbom_data)
            output_filename = f"{sbom_path.stem}_{layout}_enhanced.html"

        # Save visualization
        output_path = output_dir / output_filename
        return visualizer.save_interactive_html(net, output_path)

    except Exception as e:
        raise SBOMError(
            f"Failed to create visualization: {str(e)}",
            create_error_context(
                sbom_path=str(sbom_path),
                visualization_type=visualization_type,
                operation="create_visualization",
            ),
        ) from e
