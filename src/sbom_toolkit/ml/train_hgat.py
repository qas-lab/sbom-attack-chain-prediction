"""
Train an HGAT on heterogeneous SBOM graphs for component vulnerability classification.

Workflow:
- Load enriched SBOMs from OutputManager(...).dirs["scans"] (or --scan-dir)
- Convert each SBOM to HeteroData via hetero_processing.sbom_to_hetero_data
- Split graphs 70/15/15 by SBOM (not by nodes)
- Train CrossEntropyLoss on component logits
- Save best model + training curves under outputs/models/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import torch
    from torch import Tensor
    from torch_geometric.data import HeteroData
    from torch_geometric.loader import DataLoader

    TORCH_AVAILABLE = True
except Exception:
    torch = None  # type: ignore[assignment]
    Tensor = None  # type: ignore[assignment]
    HeteroData = None  # type: ignore[assignment]
    DataLoader = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

try:
    import matplotlib.pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except Exception:
    plt = None  # type: ignore[assignment]
    MATPLOTLIB_AVAILABLE = False

from ..shared.output import OutputManager
from .hetero_processing import load_enriched_sboms
from .hgat import HeteroGAT
from .processing import TOTAL_FEATURES as COMPONENT_FEATURE_DIM


def _device() -> torch.device:
    if not TORCH_AVAILABLE:
        raise ImportError(
            "Missing torch/torch-geometric. Install with: pip install torch torch-geometric"
        )
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _infer_in_dims(graphs: list[HeteroData]) -> dict[str, int]:
    """Infer per-type input dims across all graphs with safe fallbacks."""
    dims = {
        "component": COMPONENT_FEATURE_DIM,
        "cve": 8,  # [score + 6 sev + recency]
        "cwe": 1,  # 1-dim degree
    }
    for g in graphs:
        for t in ("component", "cve", "cwe"):
            x = g[t].x if t in g.node_types else None
            if x is not None and x.numel() > 0 and x.dim() == 2:
                dims[t] = int(x.size(1))
    return dims


def _split_indices(n: int) -> tuple[list[int], list[int], list[int]]:
    import random

    idx = list(range(n))
    random.shuffle(idx)
    n_train = int(0.7 * n)
    n_val = int(0.15 * n)
    train = idx[:n_train]
    val = idx[n_train : n_train + n_val]
    test = idx[n_train + n_val :]
    return train, val, test


def _epoch_pass(
    model: HeteroGAT,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer | None,
    device: torch.device,
) -> tuple[float, float]:
    train_mode = optimizer is not None
    model.train(mode=bool(train_mode))

    total_loss = 0.0
    correct = 0
    total = 0
    criterion = torch.nn.CrossEntropyLoss()

    for batch in loader:
        # Torch Geometric HeteroData .to expects int | str per type stubs
        batch = batch.to(str(device))
        logits = model.component_logits(batch.x_dict, batch.edge_index_dict)
        y = batch["component"].y if "component" in batch.node_types else None
        if y is None:
            continue
        if logits.size(0) == 0:
            continue
        loss = criterion(logits, y)

        if train_mode:
            assert optimizer is not None
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        total_loss += float(loss.item())
        preds = logits.argmax(dim=1)
        correct += int((preds == y).sum().item())
        total += int(y.size(0))

    avg_loss = total_loss / max(1, len(loader))
    acc = float(correct) / float(total) if total > 0 else 0.0
    return avg_loss, acc


def train_hgat_model(
    *,
    data_dir: Path,
    output_dir: Path,
    max_epochs: int = 30,
    hidden_dim: int = 64,
    heads: int = 2,
    num_layers: int = 2,
    dropout: float = 0.2,
    verbose: bool = True,
) -> Path:
    """Train HGAT on enriched SBOM graphs and write the best checkpoint to disk.

    Args:
        data_dir: Directory containing enriched SBOM JSON files.
        output_dir: Directory to write model artifacts.
        max_epochs: Maximum number of epochs.
        hidden_dim: Hidden dimension size.
        heads: Number of attention heads.
        num_layers: Number of HGAT layers.
        dropout: Dropout probability.
        verbose: If True, print progress information.

    Returns:
        Path to the saved best model checkpoint (`output_dir / "hgat_best.pt"`).
    """
    device = _device()

    output_dir.mkdir(parents=True, exist_ok=True)
    graphs = load_enriched_sboms(data_dir)
    if not graphs:
        raise FileNotFoundError(f"No enriched SBOM JSON files found under: {data_dir}")

    in_dims = _infer_in_dims(graphs)
    model = HeteroGAT(
        in_dims,
        hidden_dim=hidden_dim,
        heads=heads,
        num_layers=num_layers,
        dropout=dropout,
    )
    model = model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)

    train_idx, val_idx, test_idx = _split_indices(len(graphs))
    train_loader = DataLoader([graphs[i] for i in train_idx], batch_size=2, shuffle=True)
    val_loader = DataLoader([graphs[i] for i in val_idx], batch_size=2)
    test_loader = DataLoader([graphs[i] for i in test_idx], batch_size=2)

    best_val = float("inf")
    best_path = output_dir / "hgat_best.pt"
    history: dict[str, list[float]] = {
        "train_loss": [],
        "val_loss": [],
        "train_acc": [],
        "val_acc": [],
    }

    for epoch in range(1, max(1, max_epochs) + 1):
        tr_loss, tr_acc = _epoch_pass(model, train_loader, optimizer, device)
        va_loss, va_acc = _epoch_pass(model, val_loader, None, device)
        history["train_loss"].append(tr_loss)
        history["val_loss"].append(va_loss)
        history["train_acc"].append(tr_acc)
        history["val_acc"].append(va_acc)

        if verbose:
            print(
                f"Epoch {epoch:03d} - train_loss={tr_loss:.4f} val_loss={va_loss:.4f} "
                f"train_acc={tr_acc:.3f} val_acc={va_acc:.3f}"
            )

        if va_loss < best_val:
            best_val = va_loss
            torch.save({"model_state": model.state_dict(), "in_dims": in_dims}, best_path)

    # Final test evaluation using best model if saved
    if best_path.exists():
        payload = torch.load(best_path, map_location=device)
        model.load_state_dict(payload["model_state"])  # type: ignore[index]
    te_loss, te_acc = _epoch_pass(model, test_loader, None, device)
    if verbose:
        print(f"Test - loss={te_loss:.4f} acc={te_acc:.3f}")

    # Plots
    if MATPLOTLIB_AVAILABLE:
        try:
            import matplotlib.pyplot as plt  # re-import to satisfy type checkers

            plt.figure(figsize=(10, 4))
            plt.subplot(1, 2, 1)
            plt.plot(history["train_loss"], label="train")
            plt.plot(history["val_loss"], label="val")
            plt.title("Loss")
            plt.legend()
            plt.subplot(1, 2, 2)
            plt.plot(history["train_acc"], label="train")
            plt.plot(history["val_acc"], label="val")
            plt.title("Accuracy")
            plt.legend()
            plt.tight_layout()
            plt.savefig(output_dir / "hgat_training_curves.png")
            plt.close()
        except Exception:
            pass

    return best_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train HGAT on enriched SBOMs")
    parser.add_argument("--output-base", type=str, default="outputs", help="Base output dir")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Batch size (graphs)")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--weight-decay", type=float, default=5e-4, help="Weight decay")
    parser.add_argument("--hidden-dim", type=int, default=64, help="Hidden dim")
    parser.add_argument("--heads", type=int, default=2, help="Attention heads")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout")
    # Nice-to-have: allow overriding scan dir
    parser.add_argument("--scan-dir", type=str, default=None, help="Override scans dir")

    args = parser.parse_args(argv)

    try:
        device = _device()
    except ImportError as e:
        print(str(e))
        return 1

    out = OutputManager(Path(args.output_base))
    scan_dir = Path(args.scan_dir) if args.scan_dir else out.dirs["scans"]
    model_dir = out.dirs["models"]
    model_dir.mkdir(parents=True, exist_ok=True)

    graphs = load_enriched_sboms(scan_dir)
    if not graphs:
        print(f"No enriched SBOMs found under: {scan_dir}")
        return 1

    in_dims = _infer_in_dims(graphs)
    model = HeteroGAT(in_dims, hidden_dim=args.hidden_dim, heads=args.heads, dropout=args.dropout)
    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    train_idx, val_idx, test_idx = _split_indices(len(graphs))
    train_loader = DataLoader(
        [graphs[i] for i in train_idx], batch_size=max(1, args.batch_size), shuffle=True
    )
    val_loader = DataLoader([graphs[i] for i in val_idx], batch_size=max(1, args.batch_size))
    test_loader = DataLoader([graphs[i] for i in test_idx], batch_size=max(1, args.batch_size))

    best_val = float("inf")
    best_path = model_dir / "hgat_best.pt"
    history = {"train_loss": [], "val_loss": [], "train_acc": [], "val_acc": []}

    for epoch in range(1, max(1, args.epochs) + 1):
        tr_loss, tr_acc = _epoch_pass(model, train_loader, optimizer, device)
        va_loss, va_acc = _epoch_pass(model, val_loader, None, device)
        history["train_loss"].append(tr_loss)
        history["val_loss"].append(va_loss)
        history["train_acc"].append(tr_acc)
        history["val_acc"].append(va_acc)

        print(
            f"Epoch {epoch:03d} - train_loss={tr_loss:.4f} val_loss={va_loss:.4f} "
            f"train_acc={tr_acc:.3f} val_acc={va_acc:.3f}"
        )

        if va_loss < best_val:
            best_val = va_loss
            torch.save({"model_state": model.state_dict(), "in_dims": in_dims}, best_path)

    # Final test evaluation using best model if saved
    if best_path.exists():
        payload = torch.load(best_path, map_location=device)
        model.load_state_dict(payload["model_state"])  # type: ignore[index]
    te_loss, te_acc = _epoch_pass(model, test_loader, None, device)
    print(f"Test - loss={te_loss:.4f} acc={te_acc:.3f}")

    # Plots
    if MATPLOTLIB_AVAILABLE:
        try:
            import matplotlib.pyplot as plt  # re-import to satisfy type checkers

            plt.figure(figsize=(10, 4))
            plt.subplot(1, 2, 1)
            plt.plot(history["train_loss"], label="train")
            plt.plot(history["val_loss"], label="val")
            plt.title("Loss")
            plt.legend()
            plt.subplot(1, 2, 2)
            plt.plot(history["train_acc"], label="train")
            plt.plot(history["val_acc"], label="val")
            plt.title("Accuracy")
            plt.legend()
            plt.tight_layout()
            plt.savefig(model_dir / "hgat_training_curves.png")
            plt.close()
        except Exception:
            pass

    # Persist model path for callers
    print(f"Saved best model to: {best_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
