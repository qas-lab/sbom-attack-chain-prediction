"""
Unified visualization orchestrator for SBOM data.

This class provides the main interface for creating SBOM visualizations,
coordinating between different engines and handling data transformation.

Supports ML predictions:
- HGAT predictions: Component vulnerability predictions
- Cascade predictions: CVE attack chain predictions
"""

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from ..builders.template_builder import TemplateBuilder
from ..engines import CircularEngine, ForceDirectedEngine, HierarchicalEngine
from .data_transformer import SBOMDataTransformer


class UnifiedVisualizer:
    """Main orchestrator for SBOM visualizations with ML prediction support."""

    def __init__(self) -> None:
        """Initialize the unified visualizer."""
        self.logger = logging.getLogger(__name__)
        self.data_transformer = SBOMDataTransformer()
        self.template_builder = TemplateBuilder()

        # Initialize engines (force-directed and hierarchical are primary)
        self.engines: dict[str, ForceDirectedEngine | HierarchicalEngine | CircularEngine] = {
            "force-directed": ForceDirectedEngine(),
            "hierarchical": HierarchicalEngine(),
            "circular": CircularEngine(),
        }

        # Available layout types (prioritize force-directed and hierarchical)
        self.available_layouts = ["force-directed", "hierarchical"]

    def create_visualization(
        self,
        sbom_path: Path,
        output_path: Path,
        layout_types: list[str] | None = None,
        gnn_predictions: dict[str, Any] | None = None,
    ) -> Path:
        """Create unified visualization with multiple layout options.

        Args:
            sbom_path: Path to SBOM JSON file
            output_path: Output HTML file path
            layout_types: List of layout types to include (default: force-directed, hierarchical)
            gnn_predictions: Optional GNN predictions data with format:
                {
                    "hgat": {component: {prediction, confidence}, ...},
                    "cascades": [(cve1, cve2, probability), ...],
                }
                Or legacy format for backwards compatibility.

        Returns:
            Path to generated HTML file
        """
        if layout_types is None:
            layout_types = self.available_layouts.copy()

        # Filter to only available layouts
        layout_types = [lt for lt in layout_types if lt in self.engines]

        if not layout_types:
            raise ValueError(
                f"No valid layout types specified. Available: {self.available_layouts}"
            )

        self.logger.info(f"Creating unified visualization with layouts: {layout_types}")

        # Load and transform SBOM data
        try:
            with open(sbom_path) as f:
                raw_sbom_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load SBOM file {sbom_path}: {e}") from e

        # Transform and sanitize data
        sbom_data = self.data_transformer.transform_sbom_data(raw_sbom_data)

        # Validate data integrity
        is_valid, issues = self.data_transformer.validate_data_integrity(sbom_data)
        if not is_valid:
            self.logger.warning(f"Data integrity issues: {issues}")

        # Parse predictions into HGAT and cascade formats
        hgat_predictions, cascade_predictions = self._parse_predictions(gnn_predictions)

        if hgat_predictions:
            self.logger.info(f"Using {len(hgat_predictions)} HGAT predictions")
        if cascade_predictions:
            self.logger.info(f"Using {len(cascade_predictions)} cascade predictions")

        # Process data with each requested engine
        visualization_data: dict[str, Any] = {}
        for layout_type in layout_types:
            self.logger.info(f"Processing data for {layout_type} layout")

            try:
                engine = self.engines[layout_type]

                # Pass predictions to engines that support them
                if layout_type in ("force-directed", "hierarchical"):
                    processed_data = engine.process_sbom_data(
                        sbom_data,
                        hgat_predictions=hgat_predictions,
                        cascade_predictions=cascade_predictions,
                    )
                else:
                    processed_data = engine.process_sbom_data(sbom_data)

                layout_config = engine.get_layout_config()

                visualization_data[layout_type] = {
                    "data": processed_data,
                    "config": layout_config,
                    "engine": layout_type,
                }

                self.logger.info(f"Successfully processed {layout_type} layout")

            except Exception as e:
                self.logger.error(f"Failed to process {layout_type} layout: {e}")
                # Continue with other layouts instead of failing completely
                continue

        if not visualization_data:
            raise RuntimeError("Failed to process any visualization layouts")

        # Create template data package
        template_data = self._create_template_data(
            sbom_data=sbom_data,
            visualization_data=visualization_data,
            gnn_predictions=gnn_predictions,
            sbom_path=sbom_path,
        )

        # Generate HTML file
        html_path = self._generate_unified_html(template_data, output_path)

        self.logger.info(f"Unified visualization created: {html_path}")
        return html_path

    def _parse_predictions(
        self, gnn_predictions: dict[str, Any] | None
    ) -> tuple[dict[str, dict[str, str | float]] | None, list[tuple[str, str, float]] | None]:
        """Parse GNN predictions into HGAT and cascade formats.

        Args:
            gnn_predictions: Raw predictions dict

        Returns:
            Tuple of (hgat_predictions, cascade_predictions)
        """
        if not gnn_predictions:
            return None, None

        hgat_predictions: dict[str, dict[str, str | float]] | None = None
        cascade_predictions: list[tuple[str, str, float]] | None = None

        # Try new format first: {"hgat": {...}, "cascades": [...]}
        if "hgat" in gnn_predictions:
            hgat_predictions = gnn_predictions["hgat"]

        if "cascades" in gnn_predictions:
            raw_cascades = gnn_predictions["cascades"]
            if raw_cascades:
                # Convert to tuple format if needed
                if isinstance(raw_cascades[0], dict):
                    cascade_predictions = [
                        (c["cve1"], c["cve2"], c["probability"]) for c in raw_cascades
                    ]
                else:
                    cascade_predictions = [tuple(c) for c in raw_cascades]

        # Try legacy format: direct component predictions
        if not hgat_predictions and not cascade_predictions:
            # Check if it looks like direct HGAT predictions
            sample_value = next(iter(gnn_predictions.values()), None)
            if isinstance(sample_value, dict) and "prediction" in sample_value:
                hgat_predictions = gnn_predictions

        return hgat_predictions, cascade_predictions

    def _create_template_data(
        self,
        sbom_data: dict[str, Any],
        visualization_data: dict[str, Any],
        gnn_predictions: dict[str, Any] | None,
        sbom_path: Path,
    ) -> dict[str, Any]:
        """Create comprehensive template data package.

        Args:
            sbom_data: Transformed SBOM data
            visualization_data: Processed visualization data for each layout
            gnn_predictions: Optional GNN predictions
            sbom_path: Original SBOM file path

        Returns:
            Template data dictionary
        """
        # Extract metadata
        metadata = sbom_data.get("metadata", {})
        component_info = metadata.get("component", {})
        repo_info = metadata.get("repository", {})

        # Calculate comprehensive statistics
        stats = self._calculate_comprehensive_statistics(sbom_data, visualization_data)

        # Build template data
        template_data = {
            "title": self._generate_title(component_info, repo_info),
            "sbom_metadata": {
                "component": component_info,
                "repository": repo_info,
                "timestamp": metadata.get("timestamp"),
                "tools": metadata.get("tools", []),
                "source_file": sbom_path.name,
            },
            "visualization_data": visualization_data,
            "statistics": stats,
            "available_layouts": list(visualization_data.keys()),
            "default_layout": (
                list(visualization_data.keys())[0] if visualization_data else "force-directed"
            ),
            "gnn_predictions": gnn_predictions or {},
            "features": {
                "has_vulnerabilities": stats["total_vulnerabilities"] > 0,
                "has_dependencies": stats["total_dependencies"] > 0,
                "has_licenses": stats["total_licenses"] > 0,
                "has_gnn_predictions": bool(gnn_predictions),
            },
        }

        return template_data

    def _generate_title(self, component_info: dict[str, Any], repo_info: dict[str, Any]) -> str:
        """Generate appropriate title for the visualization.

        Args:
            component_info: Component metadata
            repo_info: Repository metadata

        Returns:
            Generated title string
        """
        if component_info and component_info.get("name"):
            name = component_info["name"]
            version = component_info.get("version", "")
            if version:
                return f"SBOM Analysis: {name} v{version}"
            else:
                return f"SBOM Analysis: {name}"
        elif repo_info and repo_info.get("name"):
            return f"SBOM Analysis: {repo_info['name']}"
        else:
            return "SBOM Security Analysis"

    def _calculate_comprehensive_statistics(
        self, sbom_data: dict[str, Any], visualization_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate comprehensive statistics across all visualizations.

        Args:
            sbom_data: SBOM data
            visualization_data: Processed visualization data

        Returns:
            Comprehensive statistics dictionary
        """
        # Base statistics from SBOM data
        components = sbom_data.get("components", [])
        dependencies = sbom_data.get("dependencies", [])
        vulnerabilities = sbom_data.get("vulnerabilities", [])

        # Count vulnerabilities in components
        component_vulnerabilities = 0
        vulnerable_components = 0
        critical_vulnerabilities = 0

        for component in components:
            comp_vulns = component.get("vulnerabilities", [])
            component_vulnerabilities += len(comp_vulns)
            if comp_vulns:
                vulnerable_components += 1
                # Count critical vulnerabilities
                critical_vulnerabilities += sum(
                    1
                    for vuln in comp_vulns
                    if (vuln.get("cvss_severity") or "").upper() == "CRITICAL"
                )

        # Count licenses
        unique_licenses = set()
        for component in components:
            for license_info in component.get("licenses", []):
                if isinstance(license_info, dict):
                    if "license" in license_info:
                        lic = license_info["license"]
                        if isinstance(lic, dict):
                            license_name = lic.get("name", lic.get("id"))
                        else:
                            license_name = str(lic)
                    elif "name" in license_info:
                        license_name = license_info["name"]
                    else:
                        continue
                else:
                    license_name = str(license_info)

                if license_name:
                    unique_licenses.add(license_name)

        # Layout-specific statistics
        layout_stats = {}
        for layout_type, layout_data in visualization_data.items():
            data = layout_data.get("data", {})
            if layout_type in ["force-directed", "circular"]:
                # Network-based layouts
                nodes = data.get("nodes", [])
                links = data.get("links", [])
                layout_stats[layout_type] = {
                    "nodes": len(nodes),
                    "links": len(links),
                    "vulnerable_nodes": sum(1 for node in nodes if node.get("isVulnerable", False)),
                    "dependent_nodes": sum(1 for node in nodes if node.get("isDependent", False)),
                }
            elif layout_type == "hierarchical":
                # Tree-based layout
                def count_tree_nodes(node, counts=None):
                    if counts is None:
                        counts = {"total": 0, "vulnerable": 0, "dependent": 0}

                    counts["total"] += 1
                    if node.get("isVulnerable", False):
                        counts["vulnerable"] += 1
                    if node.get("isDependentOnVulnerable", False):
                        counts["dependent"] += 1

                    for child in node.get("children", []):
                        count_tree_nodes(child, counts)

                    return counts

                if isinstance(data, dict) and "id" in data:
                    tree_counts = count_tree_nodes(data)
                    layout_stats[layout_type] = tree_counts
                else:
                    layout_stats[layout_type] = {
                        "total": 0,
                        "vulnerable": 0,
                        "dependent": 0,
                    }

        # Comprehensive statistics
        stats = {
            "total_components": len(components),
            "total_dependencies": len(dependencies),
            "total_vulnerabilities": len(vulnerabilities) + component_vulnerabilities,
            "vulnerable_components": vulnerable_components,
            "critical_vulnerabilities": critical_vulnerabilities,
            "total_licenses": len(unique_licenses),
            "layout_statistics": layout_stats,
            "sbom_size": {
                "components": len(components),
                "top_level_vulnerabilities": len(vulnerabilities),
                "component_vulnerabilities": component_vulnerabilities,
                "dependencies": len(dependencies),
            },
        }

        return stats

    def _generate_unified_html(self, template_data: dict[str, Any], output_path: Path) -> Path:
        """Generate unified HTML file with all visualizations using modular template builder.

        Args:
            template_data: Complete template data
            output_path: Output file path

        Returns:
            Path to generated HTML file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Use the new modular template builder
        self.logger.info("Generating HTML using modular template builder")
        html_content = self.template_builder.build_unified_template(
            template_data=template_data,
            include_layouts=template_data.get("available_layouts", ["force-directed"]),
        )

        # Write HTML file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        self.logger.info(f"Modular unified visualization saved to: {output_path}")
        return output_path

    def _create_basic_html_template(self, template_data: dict[str, Any]) -> str:
        """Create a basic HTML template as fallback.

        Args:
            template_data: Template data

        Returns:
            HTML content string
        """
        # Serialize data for JavaScript
        js_data = json.dumps(template_data, indent=2, default=str)

        # Create basic HTML structure
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{template_data["title"]}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e0e0e0;
        }}

        .layout-selector {{
            margin: 20px 0;
            text-align: center;
        }}

        .layout-button {{
            margin: 0 10px;
            padding: 10px 20px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }}

        .layout-button:hover {{
            background: #0056b3;
        }}

        .layout-button.active {{
            background: #28a745;
        }}

        .visualization-container {{
            width: 100%;
            height: 600px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin: 20px 0;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .stat-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}

        .stat-number {{
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }}

        .stat-label {{
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{template_data["title"]}</h1>
            <p>Interactive SBOM Security Visualization</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{template_data["statistics"]["total_components"]}</div>
                <div class="stat-label">Components</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{template_data["statistics"]["total_vulnerabilities"]}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{template_data["statistics"]["vulnerable_components"]}</div>
                <div class="stat-label">Vulnerable Components</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{template_data["statistics"]["total_licenses"]}</div>
                <div class="stat-label">Licenses</div>
            </div>
        </div>

        <div class="layout-selector">
            <h3>Visualization Type:</h3>
            {self._generate_layout_buttons(template_data["available_layouts"])}
        </div>

        <div class="visualization-container" id="visualization">
            <p style="text-align: center; margin-top: 200px; color: #666;">
                Select a visualization type above to view the SBOM analysis
            </p>
        </div>
    </div>

    <script>
        // Template data
        const templateData = {js_data};

        // Current layout
        let currentLayout = '{template_data["default_layout"]}';

        // Initialize visualization
        function initVisualization() {{
            showLayout(currentLayout);
        }}

        // Show specific layout
        function showLayout(layoutType) {{
            currentLayout = layoutType;
            updateButtons();

            const container = d3.select('#visualization');
            container.selectAll('*').remove();

            container.append('div')
                .style('text-align', 'center')
                .style('margin-top', '200px')
                .style('color', '#666')
                .text(`${{layoutType}} visualization would be rendered here`);
        }}

        // Update button states
        function updateButtons() {{
            d3.selectAll('.layout-button')
                .classed('active', false);
            d3.select(`#btn-${{currentLayout.replace('-', '')}}`)
                .classed('active', true);
        }}

        // Initialize on load
        document.addEventListener('DOMContentLoaded', initVisualization);
    </script>
</body>
</html>"""

        return html_content

    def _generate_layout_buttons(self, available_layouts: list[str]) -> str:
        """Generate HTML for layout selection buttons.

        Args:
            available_layouts: List of available layout types

        Returns:
            HTML string for buttons
        """
        buttons = []
        for layout in available_layouts:
            button_id = layout.replace("-", "")
            button_text = layout.replace("-", " ").title()
            buttons.append(
                f'<button class="layout-button" id="btn-{button_id}" '
                f"onclick=\"showLayout('{layout}')\">{button_text}</button>"
            )

        return "\n".join(buttons)

    def _populate_template(self, template: str, data: dict[str, Any]) -> str:
        """Populate template with data (placeholder implementation).

        Args:
            template: HTML template string
            data: Template data

        Returns:
            Populated HTML string
        """
        # This is a basic implementation - the actual template system
        # will be more sophisticated with proper templating
        result = template

        # Replace basic placeholders
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        result = result.replace("{{TITLE}}", data["title"])
        result = result.replace("{{TIMESTAMP}}", timestamp)
        result = result.replace("{{TEMPLATE_DATA}}", json.dumps(data, indent=2, default=str))

        # Replace statistics placeholders
        stats = data.get("statistics", {})
        result = result.replace("{{TOTAL_COMPONENTS}}", str(stats.get("total_components", 0)))
        result = result.replace(
            "{{VULNERABLE_COMPONENTS}}", str(stats.get("vulnerable_components", 0))
        )
        result = result.replace(
            "{{CRITICAL_VULNERABILITIES}}",
            str(stats.get("critical_vulnerabilities", 0)),
        )
        result = result.replace("{{TOTAL_LICENSES}}", str(stats.get("total_licenses", 0)))

        return result

    def get_available_layouts(self) -> list[str]:
        """Get list of available layout types.

        Returns:
            List of layout type names
        """
        return self.available_layouts.copy()

    def validate_sbom_file(self, sbom_path: Path) -> bool:
        """Validate that SBOM file is readable and contains valid data.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            True if valid, False otherwise
        """
        try:
            with open(sbom_path) as f:
                sbom_data = json.load(f)

            # Basic validation
            if not isinstance(sbom_data, dict):
                return False

            if "components" not in sbom_data:
                self.logger.warning("SBOM file missing 'components' section")
                return False

            components = sbom_data["components"]
            if not isinstance(components, list) or len(components) == 0:
                self.logger.warning("SBOM has no components")
                return False

            return True

        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            self.logger.error(f"SBOM validation failed: {e}")
            return False
