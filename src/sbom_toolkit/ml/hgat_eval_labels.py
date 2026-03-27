"""
Evaluate HGAT node classification using labels embedded in enriched SBOMs.

This treats data["component"].y as ground truth (1 if component has any
vulnerabilities, else 0). It loads SBOMs from a directory, runs HGAT, and
computes basic metrics (accuracy, precision, recall, F1). Results are saved as
JSON with an aggregate summary.

CLI:
  python -m sbom_toolkit.ml.hgat_eval_labels \
    --sboms-dir outputs/scans \
    --model outputs/models/hgat_best.pt \
    --out-dir outputs/evaluations/gold/hgat_label_eval \
    --limit 200 \
    --cpu
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.data import HeteroData

    from .hetero_processing import sbom_to_hetero_data
    from .hgat import HeteroGAT

    TORCH_AVAILABLE = True
except Exception:
    torch = None  # type: ignore[assignment]
    F = None  # type: ignore[assignment]
    HeteroData = None  # type: ignore[assignment]
    sbom_to_hetero_data = None  # type: ignore[assignment]
    HeteroGAT = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

# Cast optional imports to Any for the type checker
torch = cast(Any, torch)
F = cast(Any, F)
HeteroData = cast(Any, HeteroData)
sbom_to_hetero_data = cast(Any, sbom_to_hetero_data)
HeteroGAT = cast(Any, HeteroGAT)


@dataclass
class Metrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def accuracy(self) -> float | None:
        total = self.tp + self.fp + self.tn + self.fn
        if total == 0:
            return None
        return float(self.tp + self.tn) / float(total)

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        if denom == 0:
            return None
        return float(self.tp) / float(denom)

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        if denom == 0:
            return None
        return float(self.tp) / float(denom)

    @property
    def f1(self) -> float | None:
        p = self.precision
        r = self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2.0 * p * r / (p + r)


def _select_device(force_cpu: bool) -> torch.device:
    if force_cpu:
        return torch.device("cpu")
    try:
        if torch.cuda.is_available():
            a = torch.randn(1, device="cuda")
            b = torch.randn(1, device="cuda")
            _ = a + b
            return torch.device("cuda")
    except Exception:
        pass
    return torch.device("cpu")


def _apply_ablation(data: HeteroData, mode: str) -> HeteroData:
    """Apply simple ablations by zeroing selected node types/edges.

    Modes:
      - none: no changes
      - no_cve_cwe: remove CVE/CWE signal by emptying nodes and edges
      - no_dep: remove component->component dependency edges
    """
    m = mode.strip().lower()
    if m == "none":
        return data

    if m == "no_cve_cwe":
        try:
            # Empty HAS_VULNERABILITY and HAS_CWE edges
            data[("component", "HAS_VULNERABILITY", "cve")].edge_index = torch.empty(
                (2, 0), dtype=torch.long
            )
        except Exception:
            pass
        try:
            data[("cve", "HAS_CWE", "cwe")].edge_index = torch.empty((2, 0), dtype=torch.long)
        except Exception:
            pass
        try:
            # Empty CVE/CWE node features but preserve expected dims
            data["cve"].x = torch.empty((0, 8), dtype=torch.float32)
        except Exception:
            pass
        try:
            data["cwe"].x = torch.empty((0, 1), dtype=torch.float32)
        except Exception:
            pass
        return data

    if m == "no_dep":
        try:
            data[("component", "DEPENDS_ON", "component")].edge_index = torch.empty(
                (2, 0), dtype=torch.long
            )
        except Exception:
            pass
        return data

    return data


def _evaluate_dataset(
    sboms_dir: Path,
    model_path: Path,
    out_dir: Path,
    limit: int | None,
    cpu: bool,
    ablate: str,
) -> dict[str, Any]:
    device = _select_device(force_cpu=cpu)
    payload = torch.load(model_path, map_location=device)
    in_dims = payload.get("in_dims")

    per_file: list[dict[str, Any]] = []
    agg = Metrics(tp=0, fp=0, tn=0, fn=0)

    done = 0
    for sbom_path in sorted(sboms_dir.glob("*.json")):
        if limit is not None and done >= limit:
            break
        data = sbom_to_hetero_data(sbom_path)
        if data is None:
            continue
        if data["component"].x.size(0) == 0:
            continue

        data = _apply_ablation(data, ablate)

        model = HeteroGAT(
            in_dims or {"component": int(data["component"].x.size(1)), "cve": 8, "cwe": 1}
        )
        model.load_state_dict(payload["model_state"])  # type: ignore[index]
        model.eval()
        model = model.to(device)

        batch = data.to(str(device))
        logits = model.component_logits(batch.x_dict, batch.edge_index_dict)
        probs = F.softmax(logits, dim=1)[:, 1].detach().cpu().numpy()
        preds = logits.argmax(dim=1).detach().cpu().numpy()
        y_true = data["component"].y.detach().cpu().numpy()

        # Sanity alignment
        n = min(len(preds), len(y_true))
        preds = preds[:n]
        y_true = y_true[:n]
        probs = probs[:n]

        tp = int(((preds == 1) & (y_true == 1)).sum())
        fp = int(((preds == 1) & (y_true == 0)).sum())
        tn = int(((preds == 0) & (y_true == 0)).sum())
        fn = int(((preds == 0) & (y_true == 1)).sum())

        m = Metrics(tp=tp, fp=fp, tn=tn, fn=fn)
        agg.tp += tp
        agg.fp += fp
        agg.tn += tn
        agg.fn += fn

        per_file.append(
            {
                "sbom_path": str(sbom_path),
                "num_components": int(n),
                "ablate": ablate,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "accuracy": m.accuracy,
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
            }
        )
        done += 1

    summary = {
        "num_sboms": len(per_file),
        "ablate": ablate,
        "tp": agg.tp,
        "fp": agg.fp,
        "tn": agg.tn,
        "fn": agg.fn,
        "accuracy": Metrics(tp=agg.tp, fp=agg.fp, tn=agg.tn, fn=agg.fn).accuracy,
        "precision": Metrics(tp=agg.tp, fp=agg.fp, tn=agg.tn, fn=agg.fn).precision,
        "recall": Metrics(tp=agg.tp, fp=agg.fp, tn=agg.tn, fn=agg.fn).recall,
        "f1": Metrics(tp=agg.tp, fp=agg.fp, tn=agg.tn, fn=agg.fn).f1,
        "reports": per_file,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / f"summary_{ablate}.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate HGAT classification vs SBOM labels")
    parser.add_argument(
        "--sboms-dir", type=str, default="outputs/scans", help="Directory of enriched SBOM JSONs"
    )
    parser.add_argument(
        "--model", type=str, default="outputs/models/hgat_best.pt", help="Model checkpoint path"
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="outputs/evaluations/gold/hgat_label_eval",
        help="Output directory",
    )
    parser.add_argument(
        "--limit", type=int, default=200, help="Max number of SBOMs to evaluate (None for all)"
    )
    parser.add_argument("--cpu", action="store_true", help="Force CPU")
    parser.add_argument(
        "--ablate",
        type=str,
        default="none",
        choices=["none", "no_cve_cwe", "no_dep"],
        help="Ablation mode",
    )
    args = parser.parse_args()

    if not TORCH_AVAILABLE:
        raise ImportError(
            "Missing torch/torch-geometric. Install with: pip install torch torch-geometric"
        )

    sboms_dir = Path(args.sboms_dir)
    model_path = Path(args.model)
    out_dir = Path(args.out_dir)

    if not sboms_dir.exists():
        raise FileNotFoundError(f"SBOM directory not found: {sboms_dir}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    _ = _evaluate_dataset(
        sboms_dir,
        model_path,
        out_dir,
        args.limit if args.limit > 0 else None,
        bool(args.cpu),
        args.ablate,
    )


if __name__ == "__main__":
    main()
