import json
from pathlib import Path

import numpy as np

# Optional dependencies with graceful fallbacks
try:
    import torch
    from torch_geometric.data import Data

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None  # type: ignore[assignment]
    Data = None  # type: ignore[assignment]

# Check if required dependencies are available
if not TORCH_AVAILABLE:
    raise ImportError(
        "Missing required dependencies for ML processing. "
        "Install with: pip install torch torch-geometric"
    )

# Define feature dimensions
NUM_VULN_FEATURES = 4  # count, max_cvss, avg_cvss, has_critical
NUM_META_FEATURES = 2  # is_library, is_direct_dependency
NUM_LICENSE_FEATURES = 5  # count, is_mit, is_apache, is_bsd, is_gpl
TOTAL_FEATURES = NUM_VULN_FEATURES + NUM_META_FEATURES + NUM_LICENSE_FEATURES

# --- Feature Extraction Helper Functions ---


def extract_vulnerability_features(component_data):
    """Extract vulnerability features from component data.

    Args:
        component_data (dict): Component data from SBOM.

    Returns:
        np.ndarray: Array of vulnerability features.
    """
    features = np.zeros(NUM_VULN_FEATURES)
    vulns = component_data.get("vulnerabilities", [])
    if not vulns:
        return features

    features[0] = len(vulns)
    scores = [v.get("cvss_score") for v in vulns if v.get("cvss_score") is not None]
    if scores:
        features[1] = max(scores)
        features[2] = sum(scores) / len(scores)
    has_critical = any(v.get("cvss_severity") == "CRITICAL" for v in vulns)
    features[3] = 1.0 if has_critical else 0.0

    return features


def extract_metadata_features(component_data, is_direct):
    """Extract metadata features from component data.

    Args:
        component_data (dict): Component data from SBOM.
        is_direct (bool): Whether the component is a direct dependency.

    Returns:
        np.ndarray: Array of metadata features.
    """
    features = np.zeros(NUM_META_FEATURES)
    if component_data.get("type") == "library":
        features[0] = 1.0

    features[1] = 1.0 if is_direct else 0.0
    return features


def extract_license_features(component_data):
    """Extract license features from component data.

    Args:
        component_data (dict): Component data from SBOM.

    Returns:
        np.ndarray: Array of license features.
    """
    features = np.zeros(NUM_LICENSE_FEATURES)
    licenses = component_data.get("licenses", [])
    if not licenses:
        return features

    features[0] = len(licenses)

    license_ids = set()
    for lic_info in licenses:
        if "license" in lic_info and "id" in lic_info["license"]:
            license_ids.add(lic_info["license"]["id"].lower())
        elif "license" in lic_info and "name" in lic_info["license"]:
            name_lower = lic_info["license"]["name"].lower()
            if "mit" in name_lower:
                license_ids.add("mit")
            if "apache" in name_lower:
                license_ids.add("apache-2.0")
            if "bsd" in name_lower:
                license_ids.add("bsd-3-clause")
            if "gpl" in name_lower:
                license_ids.add("gpl-3.0-only")
    if "mit" in license_ids:
        features[1] = 1.0
    if "apache-2.0" in license_ids:
        features[2] = 1.0
    if "bsd-3-clause" in license_ids or "bsd-2-clause" in license_ids:
        features[3] = 1.0
    if "gpl-3.0-only" in license_ids or "gpl-2.0-only" in license_ids:
        features[4] = 1.0

    return features


# --- Main Conversion Function ---


def sbom_to_graph_data(sbom_path: Path):
    """Converts an enriched SBOM JSON file to a PyTorch Geometric Data object.

    Args:
        sbom_path (Path): Path to the enriched SBOM JSON file.

    Returns:
        Data: PyTorch Geometric Data object representing the SBOM graph.
    """
    try:
        with open(sbom_path, encoding="utf-8") as f:
            sbom_data = json.load(f)
    except Exception as e:
        print(f"Error loading SBOM {sbom_path}: {e}")
        return None

    components = sbom_data.get("components", [])
    dependencies = sbom_data.get("dependencies", [])
    if not components:
        print(f"Warning: No components found in {sbom_path}. Skipping.")
        return None

    node_keys = []
    component_dict = {}
    for comp in components:
        key = comp.get("bom-ref")
        if not key:
            key = comp.get("purl")
        if not key:
            key = f"{comp.get('name')}=={comp.get('version', 'unknown')}"

        if key in component_dict:
            print(
                f"Warning: Duplicate node key '{key}' found in {sbom_path}. Check bom-ref/purl uniqueness."
            )
            continue

        node_keys.append(key)
        component_dict[key] = comp

    node_mapping = {key: i for i, key in enumerate(node_keys)}
    num_nodes = len(node_keys)

    direct_deps_keys = set()
    all_dependent_keys = set()
    for dep in dependencies:
        source_key = dep.get("ref")
        if source_key:
            direct_deps_keys.add(source_key)
            if "dependsOn" in dep:
                for target_key in dep["dependsOn"]:
                    all_dependent_keys.add(target_key)

    node_features = []
    node_is_vulnerable = np.zeros(num_nodes, dtype=np.int64)

    for i, key in enumerate(node_keys):
        comp_data = component_dict[key]
        is_direct = key in direct_deps_keys

        vuln_feat = extract_vulnerability_features(comp_data)
        meta_feat = extract_metadata_features(comp_data, is_direct)
        lic_feat = extract_license_features(comp_data)

        features = np.concatenate([vuln_feat, meta_feat, lic_feat])
        node_features.append(features)

        if comp_data.get("vulnerabilities"):
            node_is_vulnerable[i] = 1

    x = torch.tensor(np.array(node_features), dtype=torch.float)

    edge_list = []
    for dep in dependencies:
        source_key = dep.get("ref")
        if source_key not in node_mapping:
            continue
        source_idx = node_mapping[source_key]

        if "dependsOn" in dep:
            for target_key in dep["dependsOn"]:
                if target_key not in node_mapping:
                    continue
                target_idx = node_mapping[target_key]
                edge_list.append([source_idx, target_idx])
                edge_list.append([target_idx, source_idx])

    if not edge_list:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    else:
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()

    y = torch.tensor(node_is_vulnerable, dtype=torch.long)

    data = Data(x=x, edge_index=edge_index, y=y)
    data.sbom_path = str(sbom_path)
    data.node_keys = node_keys

    return data


class SBOMMLProcessor:
    """Processor for ML operations on SBOM data."""

    def __init__(self):
        """Initialize ML processor."""
        pass

    def convert_sbom_to_graph(self, sbom_path: Path):
        """Convert SBOM to graph data for ML processing.

        Args:
            sbom_path: Path to SBOM file

        Returns:
            PyTorch Geometric Data object
        """
        return sbom_to_graph_data(sbom_path)

    def process_sbom_directory(self, sbom_dir: Path):
        """Process all SBOMs in a directory for ML training.

        Args:
            sbom_dir: Directory containing SBOM files

        Returns:
            List of processed graph data objects
        """
        graph_data_list = []
        for sbom_file in sbom_dir.glob("*.json"):
            graph_data = self.convert_sbom_to_graph(sbom_file)
            if graph_data is not None:
                graph_data_list.append(graph_data)
        return graph_data_list


# Additional ML functionality can be added here from gnn_train.py and gnn_predict.py
# This provides a consolidated interface for all ML operations on SBOMs
