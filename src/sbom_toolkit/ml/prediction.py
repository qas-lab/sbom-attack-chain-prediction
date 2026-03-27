import argparse
import pprint
from pathlib import Path
from typing import Any, cast

# Optional dependencies with graceful fallbacks
try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.data import Data
    from torch_geometric.nn import GCNConv

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None  # type: ignore[assignment]
    F = None  # type: ignore[assignment]
    Data = None  # type: ignore[assignment]
    GCNConv = None  # type: ignore[assignment]

# Check if required dependencies are available
if not TORCH_AVAILABLE:
    raise ImportError(
        "Missing required dependencies for ML prediction. "
        "Install with: pip install torch torch-geometric"
    )

# Import necessary functions/constants from sbom_processor
try:
    from .processing import TOTAL_FEATURES, sbom_to_graph_data
except ImportError:
    print("Error: Could not import from sbom_processor.py.")
    print("Ensure sbom_processor.py is in the same directory or your PYTHONPATH.")
    # Define TOTAL_FEATURES as a fallback if import fails, based on previous reading
    TOTAL_FEATURES = 11

    # Define a dummy sbom_to_graph_data if import fails
    def sbom_to_graph_data(sbom_path: Path) -> Data | None:
        print("Warning: Using dummy sbom_to_graph_data due to import error.")
        return None


# Define the GCN model architecture (must match the trained model)
class VulnerabilityGCN(torch.nn.Module):
    dropout: float

    def __init__(
        self,
        in_channels: int,
        hidden_channels: int,
        out_channels: int,
        dropout: float = 0.5,
    ):
        super().__init__()
        # Using default hidden_channels=64, out_channels=2 as in gnn_train.py
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, out_channels)
        # `torch.nn.Module` has a custom `__setattr__` that some type checkers treat as
        # restrictive for non-Module attributes. Assign via `Any` while keeping an
        # explicit attribute annotation above.
        self_any = cast(Any, self)
        self_any.dropout = float(dropout)  # Dropout is used during training, not eval usually

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        # No dropout during evaluation/prediction
        # x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        # No dropout during evaluation/prediction
        # x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv3(x, edge_index)
        return x  # Output raw logits


# Define type alias for the prediction result
PredictionResult = dict[str, dict[str, str | float]]


def predict_vulnerabilities(
    *,
    sbom_path: Path,
    model_path: Path,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Predict vulnerable components for an enriched SBOM using a trained GCN model.

    Returns a CLI-friendly summary shape consumed by `sbom ml predict`.
    """
    raw = predict_sbom(sbom_path=sbom_path, model_path=model_path)
    if raw is None:
        raise RuntimeError("GCN prediction failed")

    components: dict[str, dict[str, str | float]] = {}
    vulnerable: list[dict[str, str | float]] = []
    for name, info in raw.items():
        score = float(info.get("confidence", 0.0))
        label = "Vulnerable" if score >= threshold else "Non-Vulnerable"
        components[name] = {"prediction": label, "score": score}
        if label == "Vulnerable":
            vulnerable.append({"name": name, "score": score})

    vulnerable.sort(key=lambda x: cast(float, x["score"]), reverse=True)

    return {
        "model_type": "gcn",
        "threshold": float(threshold),
        "total_components": len(components),
        "predicted_vulnerable": len(vulnerable),
        "top_predictions": vulnerable,
        "components": components,
    }


def predict_sbom(
    sbom_path: str | Path, model_path: str | Path = "best_model.pt"
) -> PredictionResult | None:
    """
    Loads a trained GCN model, processes an SBOM file, and predicts vulnerability.

    Args:
        sbom_path (Union[str, Path]): Path to the enriched SBOM JSON file.
        model_path (Union[str, Path], optional): Path to the trained model state
                                                dictionary (.pt file).
                                                Defaults to 'best_model.pt' in the
                                                current directory.

    Returns:
        Optional[PredictionResult]: A dictionary mapping node identifiers (e.g., bom-ref)
                                     to their predicted class ('Vulnerable'/'Non-Vulnerable')
                                     and confidence score (probability of being vulnerable),
                                     or None if an error occurs.
                                     Example:
                                     {
                                         'pkg:npm/example@1.0.0': {'prediction': 'Vulnerable', 'confidence': 0.85},
                                         'pkg:pypi/requests@2.28.1': {'prediction': 'Non-Vulnerable', 'confidence': 0.10}
                                     }
    """
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # --- Ensure paths are Path objects ---
    sbom_file = Path(sbom_path)
    model_file = Path(model_path)

    # --- Load Model ---
    try:
        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found at {model_file}")
        # Instantiate the model
        # Ensure parameters match the saved model (hidden_channels=64, out_channels=2)
        model = VulnerabilityGCN(in_channels=TOTAL_FEATURES, hidden_channels=64, out_channels=2)
        # Load state dict using map_location for device compatibility
        model.load_state_dict(torch.load(model_file, map_location=device))
        model.eval()  # Set model to evaluation mode
        model.to(device)
        print(f"Model loaded successfully from {model_file}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

    # --- Load and Process SBOM Data ---
    if not sbom_file.exists():
        print(f"Error: SBOM file not found at {sbom_file}")
        return None

    try:
        data = sbom_to_graph_data(sbom_file)
        if data is None:
            print(f"Could not process SBOM file: {sbom_file}")
            return None
        # Ensure data is on the correct device
        data = data.to(str(device))
        print(
            f"SBOM graph loaded successfully for {sbom_file}. Nodes: {data.num_nodes}, Edges: {data.num_edges}"
        )
    except Exception as e:
        print(f"Error processing SBOM {sbom_file}: {e}")
        return None

    # --- Run Prediction ---
    if data.num_nodes == 0:
        print("Warning: SBOM graph has no nodes. No predictions to make.")
        return {}  # Return empty dict for empty graph

    predictions_dict: PredictionResult = {}
    # --- Debug: Identify indices for specific nodes ---
    nodes_to_inspect = ["Flask==1.1.2", "Jinja2==2.11.1", "Werkzeug==1.0.1"]
    node_indices_to_inspect = {}
    node_identifiers = getattr(data, "node_keys", [])
    if node_identifiers:
        for i, identifier in enumerate(node_identifiers):
            if identifier in nodes_to_inspect:
                node_indices_to_inspect[identifier] = i
    print(f"--- Debug: Indices for inspection: {node_indices_to_inspect} ---")
    # --- End Debug ---

    try:
        with torch.no_grad():
            # --- Debug: Log features for specific nodes BEFORE prediction ---
            if node_indices_to_inspect and data.x is not None:
                print("--- Debug: Feature Vectors for Inspection ---")
                for node_id, index in node_indices_to_inspect.items():
                    if index < data.x.shape[0]:  # Check index bounds
                        feature_vector = data.x[index].cpu().numpy()
                        print(f"  Node: {node_id} (Index: {index})")
                        print(f"  Features: {feature_vector}")
                    else:
                        print(f"  Node: {node_id} - Index {index} out of bounds for data.x")
                print("------------------------------------------")
            # --- End Debug ---

            out = model(data.x, data.edge_index)
            probabilities = F.softmax(out, dim=1)  # Probabilities for each class
            predicted_classes = out.argmax(dim=1)  # Predicted class index (0 or 1)

            vuln_probabilities = (
                probabilities[:, 1].cpu().numpy()
            )  # Probability of class 1 (vulnerable)
            class_indices = predicted_classes.cpu().numpy()

            # Adjust 'node_keys' if the attribute name is different in your Data object
            node_identifiers = getattr(data, "node_keys", None)
            if node_identifiers is None or len(node_identifiers) != data.num_nodes:
                # Fallback to using simple indices if identifiers are missing/mismatched
                print(
                    "Warning: Node identifiers ('node_keys') not found or mismatched in Data object. Using node indices."
                )
                # Ensure data.num_nodes is not None before using in range
                if data.num_nodes is not None:
                    node_identifiers = [f"Node_{i}" for i in range(data.num_nodes)]
                else:
                    # This case should theoretically not be reached due to earlier checks
                    print(
                        "Error: data.num_nodes is None unexpectedly. Cannot generate fallback identifiers."
                    )
                    return None  # Or handle error appropriately

            for i, identifier in enumerate(node_identifiers):
                pred_label = "Vulnerable" if class_indices[i] == 1 else "Non-Vulnerable"
                confidence = float(vuln_probabilities[i])  # Convert numpy float to python float
                predictions_dict[identifier] = {
                    "prediction": pred_label,
                    "confidence": confidence,
                }

    except AttributeError as e:
        print(
            f"Error accessing data attributes during prediction: {e}. Make sure 'x' and 'edge_index' exist."
        )
        return None
    except Exception as e:
        print(f"Error during model prediction: {e}")
        return None

    return predictions_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Predict component vulnerabilities using a trained GCN model."
    )
    parser.add_argument(
        "sbom_file", type=str, help="Path to the enriched SBOM JSON file to predict on."
    )
    parser.add_argument(
        "--model",
        type=str,
        default="best_model.pt",
        help="Path to the trained model file (default: best_model.pt in the current directory).",
    )

    args = parser.parse_args()

    # Call the refactored function
    results = predict_sbom(sbom_path=args.sbom_file, model_path=args.model)

    if results is not None:
        if results:
            print("\n--- Prediction Results ---")
            pprint.pprint(results)  # Pretty print the dictionary
        else:
            print("\n--- No predictions were generated (e.g., empty graph). ---")
    else:
        print("\n--- Prediction failed. See errors above. ---")
