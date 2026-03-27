"""
HGAT prediction for a single enriched SBOM JSON.

CLI usage:
  python -m sbom_toolkit.ml.hgat_predict /absolute/path/to/enriched_sbom.json \
      --model /path/to/outputs/models/hgat_best.pt
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, cast

try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.data import HeteroData

    TORCH_AVAILABLE = True
except Exception:
    torch = None  # type: ignore[assignment]
    F = None  # type: ignore[assignment]
    HeteroData = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

from .hetero_processing import sbom_to_hetero_data
from .hgat import HeteroGAT


def _select_device(force_cpu: bool = False) -> torch.device:
    """Choose a safe device. Falls back to CPU if CUDA kernels are unusable.

    Attempts a tiny CUDA op to ensure kernel availability; if it fails, uses CPU.
    """
    if force_cpu:
        return torch.device("cpu")
    try:
        if torch.cuda.is_available():
            # Try a trivial CUDA kernel op; if it fails, fall back to CPU
            a = torch.randn(1, device="cuda")
            b = torch.randn(1, device="cuda")
            _ = a + b
            return torch.device("cuda")
    except Exception:
        pass
    return torch.device("cpu")


def predict_sbom_hgat(
    sbom_path: Path, model_path: Path | None = None, *, cpu: bool = False
) -> dict[str, dict[str, float | str]]:
    """Run HGAT on a single SBOM and return component predictions.

    Args:
        sbom_path: Path to enriched SBOM JSON.
        model_path: Path to saved model (defaults to outputs/models/hgat_best.pt).

    Returns:
        Mapping: component_identifier -> {"prediction": label, "confidence": float}
    """
    if not TORCH_AVAILABLE:
        raise ImportError(
            "Missing torch/torch-geometric. Install with: pip install torch torch-geometric"
        )

    if model_path is None:
        # Default under local outputs directory
        model_path = Path("outputs/models/hgat_best.pt")

    data = sbom_to_hetero_data(sbom_path)
    if data is None:
        return {}

    device = _select_device(force_cpu=cpu)
    payload = torch.load(model_path, map_location=device)
    in_dims = payload.get(
        "in_dims", {"component": int(data["component"].x.size(1)), "cve": 8, "cwe": 1}
    )

    model = HeteroGAT(in_dims)  # use defaults for hidden, heads, etc.
    model.load_state_dict(payload["model_state"])  # type: ignore[index]
    model.eval()
    model = model.to(device)

    # Torch Geometric Data/HeteroData.to stubs accept int | str; pass str(device)
    batch = data.to(str(device))
    logits = model.component_logits(batch.x_dict, batch.edge_index_dict)
    if logits.size(0) == 0:
        return {}
    probs = F.softmax(logits, dim=1)[:, 1].detach().cpu().numpy()
    preds = logits.argmax(dim=1).detach().cpu().numpy()

    node_keys = getattr(data["component"], "node_keys", None)
    if not node_keys or len(node_keys) != logits.size(0):
        # Fallback to indices
        node_keys = [f"Node_{i}" for i in range(int(logits.size(0)))]

    out: dict[str, dict[str, float | str]] = {}
    for i, key in enumerate(node_keys):
        label = "Vulnerable" if int(preds[i]) == 1 else "Non-Vulnerable"
        out[str(key)] = {"prediction": label, "confidence": float(probs[i])}
    return out


def predict_with_hgat(
    *,
    sbom_path: Path,
    model_path: Path,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Predict vulnerable components for an enriched SBOM using a trained HGAT model.

    Returns a CLI-friendly summary shape consumed by `sbom ml predict`.
    """
    raw = predict_sbom_hgat(sbom_path=sbom_path, model_path=model_path)

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
        "model_type": "hgat",
        "threshold": float(threshold),
        "total_components": len(components),
        "predicted_vulnerable": len(vulnerable),
        "top_predictions": vulnerable,
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="HGAT prediction on a single SBOM")
    parser.add_argument("sbom_path", type=str, help="Path to enriched SBOM JSON")
    parser.add_argument(
        "--model",
        type=str,
        default="outputs/models/hgat_best.pt",
        help="Path to trained HGAT model file",
    )
    parser.add_argument("--cpu", action="store_true", help="Force CPU for prediction")
    args = parser.parse_args()

    results = predict_sbom_hgat(Path(args.sbom_path), Path(args.model), cpu=bool(args.cpu))
    if not results:
        print("No predictions generated.")
        return
    for k, v in results.items():
        print(f"{k}\t{v['prediction']}\t{v['confidence']:.4f}")


if __name__ == "__main__":
    main()
