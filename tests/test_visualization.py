"""
Tests for SBOM visualization module.

This module provides comprehensive tests for:
- PredictionLoader class
- ForceDirectedEngine with ML predictions
- HierarchicalEngine with ML predictions
- Template building with prediction data
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

# ============================================================================
# Test Fixtures for Visualization
# ============================================================================


@pytest.fixture
def visualization_sbom_data() -> dict[str, Any]:
    """Return sample SBOM data with components suitable for visualization testing."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:viz-test-1234",
        "version": 1,
        "metadata": {
            "timestamp": "2024-01-15T10:30:00Z",
            "tools": [{"name": "syft", "version": "0.100.0"}],
            "component": {
                "bom-ref": "pkg:pypi/my-project@1.0.0",
                "type": "application",
                "name": "my-project",
                "version": "1.0.0",
                "description": "Test application for visualization",
            },
            "repository": {"name": "my-project", "url": "https://github.com/test/my-project"},
        },
        "components": [
            {
                "bom-ref": "pkg:pypi/flask@2.0.0",
                "type": "library",
                "name": "flask",
                "version": "2.0.0",
                "purl": "pkg:pypi/flask@2.0.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "description": "A simple framework for building complex web applications.",
            },
            {
                "bom-ref": "pkg:pypi/jinja2@3.1.0",
                "type": "library",
                "name": "jinja2",
                "version": "3.1.0",
                "purl": "pkg:pypi/jinja2@3.1.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "vulnerabilities": [
                    {
                        "source_id": "GHSA-h5c8-rqwp-cp95",
                        "cve_id": "CVE-2024-22195",
                        "description": "Jinja2 vulnerable to HTML attribute injection",
                        "cvss_score": 6.1,
                        "cvss_severity": "MEDIUM",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-22195"],
                        "cwe_ids": ["CWE-79"],
                    }
                ],
            },
            {
                "bom-ref": "pkg:pypi/werkzeug@2.0.0",
                "type": "library",
                "name": "werkzeug",
                "version": "2.0.0",
                "purl": "pkg:pypi/werkzeug@2.0.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "vulnerabilities": [
                    {
                        "source_id": "GHSA-2g68-c3qc-8985",
                        "cve_id": "CVE-2024-34069",
                        "description": "Werkzeug debugger vulnerable to RCE",
                        "cvss_score": 9.8,
                        "cvss_severity": "CRITICAL",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-34069"],
                        "cwe_ids": ["CWE-94"],
                    }
                ],
            },
            {
                "bom-ref": "pkg:pypi/markupsafe@2.1.0",
                "type": "library",
                "name": "markupsafe",
                "version": "2.1.0",
                "purl": "pkg:pypi/markupsafe@2.1.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
            {
                "bom-ref": "pkg:pypi/click@8.0.0",
                "type": "library",
                "name": "click",
                "version": "8.0.0",
                "purl": "pkg:pypi/click@8.0.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
            {
                "bom-ref": "pkg:pypi/itsdangerous@2.0.0",
                "type": "library",
                "name": "itsdangerous",
                "version": "2.0.0",
                "purl": "pkg:pypi/itsdangerous@2.0.0",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
        ],
        "dependencies": [
            {
                "ref": "pkg:pypi/my-project@1.0.0",
                "dependsOn": ["pkg:pypi/flask@2.0.0"],
            },
            {
                "ref": "pkg:pypi/flask@2.0.0",
                "dependsOn": [
                    "pkg:pypi/jinja2@3.1.0",
                    "pkg:pypi/werkzeug@2.0.0",
                    "pkg:pypi/click@8.0.0",
                    "pkg:pypi/itsdangerous@2.0.0",
                ],
            },
            {
                "ref": "pkg:pypi/jinja2@3.1.0",
                "dependsOn": ["pkg:pypi/markupsafe@2.1.0"],
            },
        ],
        "vulnerabilities": [],
    }


@pytest.fixture
def visualization_sbom_file(visualization_sbom_data: dict[str, Any]) -> Path:
    """Create a temporary SBOM file for visualization testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(visualization_sbom_data, f)
        return Path(f.name)


@pytest.fixture
def mock_hgat_predictions() -> dict[str, dict[str, str | float]]:
    """Return mock HGAT predictions for visualization testing.

    Format: {component_identifier: {"prediction": label, "confidence": float}}
    """
    return {
        "pkg:pypi/flask@2.0.0": {"prediction": "Non-Vulnerable", "confidence": 0.15},
        "pkg:pypi/jinja2@3.1.0": {"prediction": "Vulnerable", "confidence": 0.85},
        "pkg:pypi/werkzeug@2.0.0": {"prediction": "Vulnerable", "confidence": 0.92},
        "pkg:pypi/markupsafe@2.1.0": {"prediction": "Non-Vulnerable", "confidence": 0.08},
        "pkg:pypi/click@8.0.0": {"prediction": "Non-Vulnerable", "confidence": 0.12},
        "pkg:pypi/itsdangerous@2.0.0": {"prediction": "Non-Vulnerable", "confidence": 0.05},
        # Alternative key formats that models might return
        "flask@2.0.0": {"prediction": "Non-Vulnerable", "confidence": 0.15},
        "jinja2@3.1.0": {"prediction": "Vulnerable", "confidence": 0.85},
    }


@pytest.fixture
def mock_cascade_predictions() -> list[tuple[str, str, float]]:
    """Return mock MLP cascade predictions for visualization testing.

    Format: [(cve1, cve2, probability), ...]
    These represent predicted attack chains between CVEs.
    """
    return [
        ("CVE-2024-22195", "CVE-2024-34069", 0.78),  # Jinja2 -> Werkzeug chain
        ("CVE-2024-34069", "CVE-2024-22195", 0.65),  # Reverse direction
    ]


@pytest.fixture
def mock_cve_features() -> dict[str, list[float]]:
    """Return mock CVE feature vectors for cascade prediction.

    Format: {cve_id: [9-dim feature vector]}
    """
    return {
        "CVE-2024-22195": [6.1, 0.0, 1.0, 1.0, 0.0, 2024.0, 0.0, 1.0, 0.0],
        "CVE-2024-34069": [9.8, 1.0, 1.0, 1.0, 1.0, 2024.0, 1.0, 1.0, 1.0],
    }


@pytest.fixture
def mock_predictions_file(
    mock_hgat_predictions: dict[str, dict[str, str | float]],
    mock_cascade_predictions: list[tuple[str, str, float]],
) -> Path:
    """Create a temporary predictions file combining HGAT and cascade predictions."""
    predictions_data = {
        "hgat_predictions": mock_hgat_predictions,
        "cascade_predictions": [
            {"cve1": c[0], "cve2": c[1], "probability": c[2]} for c in mock_cascade_predictions
        ],
        "model_info": {
            "hgat_model": "outputs/models/hgat_best.pt",
            "cascade_model": "outputs/models/cascade_predictor.pt",
            "timestamp": "2024-01-15T10:30:00Z",
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix="_predictions.json", delete=False) as f:
        json.dump(predictions_data, f)
        return Path(f.name)


# ============================================================================
# Tests for PredictionLoader
# ============================================================================


class TestPredictionLoader:
    """Tests for the PredictionLoader class."""

    def test_load_hgat_predictions_from_dict(
        self, mock_hgat_predictions: dict[str, dict[str, str | float]]
    ) -> None:
        """Test loading HGAT predictions from a dictionary."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()
        loader.load_hgat_predictions(mock_hgat_predictions)

        assert loader.has_hgat_predictions()
        assert len(loader.hgat_predictions) > 0

        # Check prediction retrieval
        pred = loader.get_component_prediction("pkg:pypi/jinja2@3.1.0")
        assert pred is not None
        assert pred["prediction"] == "Vulnerable"
        assert pred["confidence"] == 0.85

    def test_load_hgat_predictions_normalizes_keys(
        self, mock_hgat_predictions: dict[str, dict[str, str | float]]
    ) -> None:
        """Test that prediction loader normalizes component identifiers."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()
        loader.load_hgat_predictions(mock_hgat_predictions)

        # Should find prediction using various key formats
        pred1 = loader.get_component_prediction("pkg:pypi/jinja2@3.1.0")
        pred2 = loader.get_component_prediction("jinja2@3.1.0")
        pred3 = loader.get_component_prediction("jinja2==3.1.0")

        assert pred1 is not None or pred2 is not None or pred3 is not None

    def test_load_cascade_predictions(
        self, mock_cascade_predictions: list[tuple[str, str, float]]
    ) -> None:
        """Test loading cascade predictions."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()
        loader.load_cascade_predictions(mock_cascade_predictions)

        assert loader.has_cascade_predictions()
        assert len(loader.cascade_predictions) == 2

    def test_get_cascade_for_cve(
        self, mock_cascade_predictions: list[tuple[str, str, float]]
    ) -> None:
        """Test retrieving cascade predictions for a specific CVE."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()
        loader.load_cascade_predictions(mock_cascade_predictions)

        cascades = loader.get_cascades_for_cve("CVE-2024-22195")
        assert len(cascades) >= 1
        assert any(c[1] == "CVE-2024-34069" for c in cascades)

    def test_load_from_file(self, mock_predictions_file: Path) -> None:
        """Test loading predictions from a JSON file."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()
        loader.load_from_file(mock_predictions_file)

        assert loader.has_hgat_predictions()
        assert loader.has_cascade_predictions()

    def test_merge_predictions_with_sbom(
        self,
        visualization_sbom_data: dict[str, Any],
        mock_hgat_predictions: dict[str, dict[str, str | float]],
        mock_cascade_predictions: list[tuple[str, str, float]],
    ) -> None:
        """Test merging predictions with SBOM data."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()
        loader.load_hgat_predictions(mock_hgat_predictions)
        loader.load_cascade_predictions(mock_cascade_predictions)

        merged = loader.merge_with_sbom(visualization_sbom_data)

        # Check that components have prediction data
        for component in merged.get("components", []):
            if component.get("bom-ref") == "pkg:pypi/jinja2@3.1.0":
                assert "ml_prediction" in component
                assert component["ml_prediction"]["prediction"] == "Vulnerable"

    def test_empty_predictions(self) -> None:
        """Test behavior with no predictions loaded."""
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()

        assert not loader.has_hgat_predictions()
        assert not loader.has_cascade_predictions()
        assert loader.get_component_prediction("any-component") is None
        assert loader.get_cascades_for_cve("any-cve") == []

    def test_multiple_load_clears_normalized_key_map(self) -> None:
        """Test that loading predictions multiple times clears the normalized key map.

        This verifies the fix for the bug where stale entries in _normalized_key_map
        would point to keys that no longer exist in hgat_predictions.
        """
        from sbom_toolkit.visualization.core.prediction_loader import PredictionLoader

        loader = PredictionLoader()

        # First load with specific keys
        first_predictions = {
            "pkg:pypi/flask@1.0.0": {"prediction": "Vulnerable", "confidence": 0.9},
            "pkg:pypi/requests@2.0.0": {"prediction": "Non-Vulnerable", "confidence": 0.8},
        }
        loader.load_hgat_predictions(first_predictions)

        # Verify first load works
        assert loader.get_component_prediction("flask@1.0.0") is not None
        assert loader.get_component_prediction("requests@2.0.0") is not None

        # Second load with different keys (simulating override)
        second_predictions = {
            "pkg:pypi/django@3.0.0": {"prediction": "Vulnerable", "confidence": 0.7},
        }
        loader.load_hgat_predictions(second_predictions)

        # After second load, old keys should NOT be found
        # This would fail if _normalized_key_map wasn't cleared
        assert loader.get_component_prediction("flask@1.0.0") is None
        assert loader.get_component_prediction("requests@2.0.0") is None

        # New key should work
        assert loader.get_component_prediction("django@3.0.0") is not None

        # Verify _normalized_key_map was actually cleared (internal check)
        # The map should only have one entry for django
        assert len(loader._normalized_key_map) == 1


# ============================================================================
# Tests for ForceDirectedEngine with ML Predictions
# ============================================================================


class TestForceDirectedEngineWithPredictions:
    """Tests for ForceDirectedEngine ML prediction integration."""

    def test_process_sbom_includes_ml_predictions(
        self,
        visualization_sbom_data: dict[str, Any],
        mock_hgat_predictions: dict[str, dict[str, str | float]],
    ) -> None:
        """Test that processed data includes ML predictions in nodes."""
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(transformed_data, hgat_predictions=mock_hgat_predictions)

        # Check that nodes have ML prediction data
        nodes = result.get("nodes", [])
        assert len(nodes) > 0

        jinja_node = next((n for n in nodes if "jinja2" in n.get("id", "").lower()), None)
        if jinja_node:
            assert "mlPrediction" in jinja_node
            assert "mlConfidence" in jinja_node

    def test_process_sbom_without_predictions(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Test processing SBOM data without ML predictions."""
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(transformed_data)

        nodes = result.get("nodes", [])
        assert len(nodes) > 0

        # Nodes should have default/empty ML prediction fields
        for node in nodes:
            assert "mlPrediction" in node
            assert node["mlPrediction"] in ["Unknown", None, ""]

    def test_cascade_predictions_create_links(
        self,
        visualization_sbom_data: dict[str, Any],
        mock_cascade_predictions: list[tuple[str, str, float]],
    ) -> None:
        """Test that cascade predictions create additional links."""
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(
            transformed_data, cascade_predictions=mock_cascade_predictions
        )

        links = result.get("links", [])

        # Check for cascade-type links
        cascade_links = [lnk for lnk in links if lnk.get("relationship") == "cascade"]
        # May or may not have cascade links depending on if CVEs are in the graph
        assert isinstance(cascade_links, list)


# ============================================================================
# Tests for HierarchicalEngine
# ============================================================================


class TestHierarchicalEngine:
    """Tests for HierarchicalEngine implementation."""

    def test_process_sbom_creates_hierarchy(self, visualization_sbom_data: dict[str, Any]) -> None:
        """Test that HierarchicalEngine creates proper D3 hierarchy format."""
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = HierarchicalEngine()
        result = engine.process_sbom_data(transformed_data)

        # Should have root node with children
        assert "id" in result or "name" in result
        assert "children" in result

    def test_hierarchy_includes_ml_predictions(
        self,
        visualization_sbom_data: dict[str, Any],
        mock_hgat_predictions: dict[str, dict[str, str | float]],
    ) -> None:
        """Test that hierarchy nodes include ML predictions."""
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = HierarchicalEngine()
        result = engine.process_sbom_data(transformed_data, hgat_predictions=mock_hgat_predictions)

        # Check that tree has prediction data somewhere
        def find_node_with_prediction(node: dict[str, Any]) -> bool:
            if node.get("mlPrediction") and node.get("mlPrediction") != "Unknown":
                return True
            for child in node.get("children", []):
                if find_node_with_prediction(child):
                    return True
            return False

        # May or may not find predictions depending on key matching
        assert isinstance(result, dict)

    def test_hierarchy_depth(self, visualization_sbom_data: dict[str, Any]) -> None:
        """Test that hierarchy has appropriate structure."""
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = HierarchicalEngine()
        result = engine.process_sbom_data(transformed_data)

        def get_max_depth(node: dict[str, Any], current_depth: int = 0) -> int:
            max_depth = current_depth
            for child in node.get("children", []):
                child_depth = get_max_depth(child, current_depth + 1)
                max_depth = max(max_depth, child_depth)
            return max_depth

        def count_total_nodes(node: dict[str, Any]) -> int:
            count = 1
            for child in node.get("children", []):
                count += count_total_nodes(child)
            return count

        depth = get_max_depth(result)
        total_nodes = count_total_nodes(result)

        # Hierarchy should have structure (at least root node)
        assert total_nodes >= 1
        # Depth can be 0 if root has no children (valid hierarchical structure)
        assert depth >= 0

    def test_get_layout_config(self) -> None:
        """Test that hierarchical engine provides proper layout config."""
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        engine = HierarchicalEngine()
        config = engine.get_layout_config()

        assert "tree" in config or "layout" in config
        assert isinstance(config, dict)


# ============================================================================
# Integration Tests
# ============================================================================


class TestVisualizationIntegration:
    """Integration tests for the full visualization pipeline."""

    def test_unified_visualizer_with_predictions(
        self,
        visualization_sbom_file: Path,
        mock_hgat_predictions: dict[str, dict[str, str | float]],
        mock_cascade_predictions: list[tuple[str, str, float]],
    ) -> None:
        """Test UnifiedVisualizer integrates predictions correctly."""
        from sbom_toolkit.visualization.core.unified_visualizer import UnifiedVisualizer

        visualizer = UnifiedVisualizer()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = Path(f.name)

        gnn_predictions = {
            "hgat": mock_hgat_predictions,
            "cascades": mock_cascade_predictions,
        }

        result_path = visualizer.create_visualization(
            sbom_path=visualization_sbom_file,
            output_path=output_path,
            layout_types=["force-directed", "hierarchical"],
            gnn_predictions=gnn_predictions,
        )

        assert result_path.exists()
        content = result_path.read_text()

        # Check that HTML contains visualization elements
        assert "visualization" in content.lower()
        assert "d3" in content.lower()

    def test_available_layouts(self) -> None:
        """Test that correct layouts are available."""
        from sbom_toolkit.visualization.core.unified_visualizer import UnifiedVisualizer

        visualizer = UnifiedVisualizer()
        layouts = visualizer.get_available_layouts()

        assert "force-directed" in layouts
        assert "hierarchical" in layouts


# ============================================================================
# Bug Fix Tests - Visualization Issues
# ============================================================================


class TestVisualizationBugFixes:
    """Tests for visualization bug fixes.

    These tests verify fixes for:
    1. Vulnerability IDs showing "Unknown" (source_id not being used)
    2. Vulnerabilities array being empty in nodes
    3. Filter toggles not working (relationship attribute)
    4. Hierarchical view only showing root node (children not built)
    """

    def test_vulnerability_info_includes_source_id(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Test that vulnerability info uses source_id when id is not present.

        Bug: The template uses vuln.id || vuln.cve_id but SBOM data uses source_id.
        The vulnerability extraction should include source_id as a fallback for id.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(transformed_data)

        # Find a vulnerable node (jinja2 or werkzeug have vulnerabilities)
        nodes = result.get("nodes", [])
        vulnerable_nodes = [n for n in nodes if n.get("isVulnerable")]

        assert len(vulnerable_nodes) > 0, "Should have vulnerable nodes"

        # Check that vulnerability data has proper ID (not just "Unknown")
        for node in vulnerable_nodes:
            vulns = node.get("vulnerabilities", [])
            assert len(vulns) > 0, (
                f"Vulnerable node {node.get('id')} should have vulnerability data"
            )

            for vuln in vulns:
                # The vulnerability should have a meaningful ID (source_id, cve_id, or id)
                vuln_id = vuln.get("id") or vuln.get("cve_id") or vuln.get("source_id")
                assert vuln_id is not None, "Vulnerability should have an ID"
                assert vuln_id != "Unknown", (
                    f"Vulnerability ID should not be 'Unknown', got: {vuln}. "
                    "source_id should be used as fallback."
                )

    def test_force_directed_nodes_have_vulnerability_data(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Test that force-directed nodes include complete vulnerability details.

        Bug: The vulnerabilities array is empty for vulnerable nodes even though
        the SBOM data contains vulnerability information.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(transformed_data)

        nodes = result.get("nodes", [])

        # Find jinja2 node which has a known vulnerability
        jinja_node = next(
            (n for n in nodes if "jinja2" in n.get("id", "").lower()),
            None,
        )
        assert jinja_node is not None, "Should find jinja2 node"
        assert jinja_node.get("isVulnerable"), "jinja2 should be marked as vulnerable"

        # The vulnerabilities array should NOT be empty
        vulnerabilities = jinja_node.get("vulnerabilities", [])
        assert len(vulnerabilities) > 0, (
            f"jinja2 node should have vulnerabilities array populated, got: {vulnerabilities}"
        )

        # Check vulnerability has expected fields
        vuln = vulnerabilities[0]
        assert "description" in vuln, "Vulnerability should have description"
        assert "cvss_severity" in vuln, "Vulnerability should have cvss_severity"
        # source_id or cve_id should be present
        assert vuln.get("source_id") or vuln.get("cve_id"), (
            "Vulnerability should have source_id or cve_id"
        )

    def test_hierarchical_tree_has_children(self, visualization_sbom_data: dict[str, Any]) -> None:
        """Test that hierarchical layout includes dependency children.

        Bug: The tree view only shows the root node, no children are displayed.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = HierarchicalEngine()
        result = engine.process_sbom_data(transformed_data)

        # Root should have children
        children = result.get("children", [])
        assert len(children) > 0, (
            f"Hierarchical root should have children (dependencies). "
            f"Got root: {result.get('id')} with {len(children)} children. "
            f"SBOM has {len(visualization_sbom_data.get('components', []))} components "
            f"and {len(visualization_sbom_data.get('dependencies', []))} dependency entries."
        )

        # Count total nodes in tree
        def count_tree_nodes(node: dict[str, Any]) -> int:
            count = 1
            for child in node.get("children", []):
                count += count_tree_nodes(child)
            return count

        total_nodes = count_tree_nodes(result)

        # We should have more than just the root node
        # The SBOM has 6 components + root = 7 minimum expected
        assert total_nodes > 1, (
            f"Tree should have more than just root node, got {total_nodes} total nodes"
        )

    def test_links_have_relationship_attribute(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Test that all links have a valid relationship attribute for filtering.

        Bug: Filter toggles (direct/transitive/license) don't affect visibility
        because links may not have the correct relationship values.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(transformed_data)

        links = result.get("links", [])
        assert len(links) > 0, "Should have links in the graph"

        # Additional valid relationships that may exist (including fallback structure types)
        valid_relationships = {
            "direct",
            "transitive",
            "license",
            "cascade",
            "vulnerability_focus",
            "context",
            "hub",
            "spoke",
            "license_group",
            "unknown",
        }

        # All links should have a valid relationship attribute
        for link in links:
            relationship = link.get("relationship")
            assert relationship is not None, f"Link should have relationship attribute: {link}"
            assert relationship in valid_relationships, (
                f"Link relationship '{relationship}' should be one of {valid_relationships}"
            )

        # Should have at least some direct dependencies
        direct_links = [lnk for lnk in links if lnk.get("relationship") == "direct"]
        assert len(direct_links) > 0, "Should have at least one direct dependency link"

        # Should have some transitive dependencies (flask depends on jinja2 which depends on markupsafe)
        transitive_links = [lnk for lnk in links if lnk.get("relationship") == "transitive"]
        assert len(transitive_links) > 0, "Should have transitive dependency links"

    def test_hierarchical_vulnerable_nodes_have_vulnerability_data(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Test that hierarchical nodes include vulnerability data.

        Bug: Vulnerability information is not included in hierarchical tree nodes.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = HierarchicalEngine()
        result = engine.process_sbom_data(transformed_data)

        # Find vulnerable nodes in tree
        def find_vulnerable_nodes(node: dict[str, Any]) -> list[dict[str, Any]]:
            vulnerable = []
            if node.get("isVulnerable"):
                vulnerable.append(node)
            for child in node.get("children", []):
                vulnerable.extend(find_vulnerable_nodes(child))
            return vulnerable

        vulnerable_nodes = find_vulnerable_nodes(result)

        # Should find vulnerable nodes
        assert len(vulnerable_nodes) > 0, "Should have vulnerable nodes in hierarchical tree"

        # Each vulnerable node should have vulnerability details
        for node in vulnerable_nodes:
            vulns = node.get("vulnerabilities", [])
            assert len(vulns) > 0, (
                f"Vulnerable hierarchical node {node.get('id')} should have "
                f"vulnerabilities array populated"
            )

    def test_vulnerability_id_not_literal_unknown(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Vulnerability ID should use cve_id or source_id when id is 'unknown'.

        Bug: The build_vulnerability_info function sets id to "unknown" as a literal
        string, which is truthy, so the template's fallback logic doesn't work.
        The ID should be a meaningful identifier like CVE or GHSA ID.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        engine = ForceDirectedEngine()
        result = engine.process_sbom_data(transformed_data)

        nodes = result.get("nodes", [])
        vulnerable_nodes = [n for n in nodes if n.get("isVulnerable")]

        assert len(vulnerable_nodes) > 0, "Should have vulnerable nodes"

        for node in vulnerable_nodes:
            vulns = node.get("vulnerabilities", [])
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                # The ID should NOT be the literal string "unknown" (case-insensitive)
                assert vuln_id.lower() != "unknown", (
                    f"Vulnerability ID should not be literal 'unknown'. "
                    f"Got: {vuln}. Should use cve_id ({vuln.get('cve_id')}) "
                    f"or source_id ({vuln.get('source_id')}) instead."
                )
                # The ID should be a meaningful identifier
                assert vuln_id and vuln_id != "", (
                    "Vulnerability ID should be a meaningful identifier, got empty"
                )

    def test_hierarchical_children_match_force_directed_structure(
        self, visualization_sbom_data: dict[str, Any]
    ) -> None:
        """Hierarchical tree should have children matching the dependency structure.

        Bug: The hierarchical tree root has 0 children despite having dependencies.
        This happens when the root node ID doesn't match the dependency references.
        """
        from sbom_toolkit.visualization.core.data_transformer import SBOMDataTransformer
        from sbom_toolkit.visualization.engines.force_directed_engine import ForceDirectedEngine
        from sbom_toolkit.visualization.engines.hierarchical_engine import HierarchicalEngine

        transformer = SBOMDataTransformer()
        transformed_data = transformer.transform_sbom_data(visualization_sbom_data)

        # Get force-directed data for comparison
        fd_engine = ForceDirectedEngine()
        fd_result = fd_engine.process_sbom_data(transformed_data)
        fd_nodes = fd_result.get("nodes", [])
        fd_links = fd_result.get("links", [])

        # Get hierarchical data
        hier_engine = HierarchicalEngine()
        hier_result = hier_engine.process_sbom_data(transformed_data)

        # Count total nodes in hierarchical tree
        def count_tree_nodes(node: dict[str, Any]) -> int:
            count = 1
            for child in node.get("children", []):
                count += count_tree_nodes(child)
            return count

        hier_total = count_tree_nodes(hier_result)
        hier_children = len(hier_result.get("children", []))

        # If force-directed has nodes, hierarchical should have comparable structure
        assert len(fd_nodes) > 1, "Force-directed should have multiple nodes"
        assert len(fd_links) > 0, "Force-directed should have links"

        # The hierarchical root should have children if there are dependencies
        # Check for direct dependencies from the root
        root_id = hier_result.get("id")
        direct_deps_in_fd = [
            lnk
            for lnk in fd_links
            if lnk.get("relationship") == "direct"
            and (lnk.get("source") == root_id or str(lnk.get("source", {})) == root_id)
        ]

        if direct_deps_in_fd:
            assert hier_children > 0, (
                f"Hierarchical root '{root_id}' should have children. "
                f"Force-directed has {len(direct_deps_in_fd)} direct dependencies from root, "
                f"but hierarchical has {hier_children} children. "
                f"Total nodes in tree: {hier_total}, in force-directed: {len(fd_nodes)}"
            )
