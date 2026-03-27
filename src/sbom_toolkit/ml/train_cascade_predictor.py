"""
Training script for cascade vulnerability predictor.

Usage:
    python -m sbom_toolkit.ml.train_cascade_predictor \
        --external-chains data/external_chains \
        --incidents supply-chain-seeds/incidents.json \
        --cve-cache data/cve_cache \
        --output outputs/models/cascade_predictor.pt \
        --epochs 100 \
        --batch-size 16
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False

try:
    import matplotlib.pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    plt = None  # type: ignore[assignment]
    MATPLOTLIB_AVAILABLE = False

from .cascade_data_loader import CascadeDataLoader
from .cascade_predictor import CascadePredictor, CascadeTrainer


def prepare_data(
    loader: CascadeDataLoader,
    val_split: float = 0.2,
    test_split: float = 0.1,
) -> tuple[
    tuple[np.ndarray, np.ndarray],
    tuple[np.ndarray, np.ndarray],
    tuple[np.ndarray, np.ndarray],
]:
    """Prepare train/val/test splits.

    Args:
        loader: Loaded cascade data loader
        val_split: Fraction for validation
        test_split: Fraction for test

    Returns:
        (X_train, y_train), (X_val, y_val), (X_test, y_test)
    """
    if not NUMPY_AVAILABLE:
        raise ImportError("NumPy required")

    pairs, labels = loader.generate_training_pairs(negative_ratio=2.0)

    # Extract features
    X_rows: list[np.ndarray] = []
    y_labels: list[int] = []
    for (cve1, cve2), label in zip(pairs, labels, strict=True):
        try:
            feat = loader.get_pair_features(cve1, cve2)
            X_rows.append(feat)
            y_labels.append(label)
        except Exception as e:
            print(f"Warning: Could not get pair features: {e}")
            continue

    X = np.stack(X_rows)
    y = np.array(y_labels, dtype=np.int64)

    # Shuffle and split
    rng = np.random.RandomState(42)
    indices = rng.permutation(len(X))
    X = X[indices]
    y = y[indices]

    n = len(X)
    n_test = int(n * test_split)
    n_val = int(n * val_split)
    n_train = n - n_test - n_val

    X_train, y_train = X[:n_train], y[:n_train]
    X_val, y_val = X[n_train : n_train + n_val], y[n_train : n_train + n_val]
    X_test, y_test = X[n_train + n_val :], y[n_train + n_val :]

    return (X_train, y_train), (X_val, y_val), (X_test, y_test)


def plot_training_curves(history: dict[str, Any], output_dir: Path) -> None:
    """Plot and save training curves."""
    if not MATPLOTLIB_AVAILABLE:
        return

    try:
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))

        # Loss
        axes[0].plot(history["train_loss"], label="Train Loss")
        if history["val_loss"]:
            axes[0].plot(history["val_loss"], label="Val Loss")
        axes[0].set_xlabel("Epoch")
        axes[0].set_ylabel("Loss")
        axes[0].set_title("Training and Validation Loss")
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)

        # AUC
        axes[1].plot(history["train_auc"], label="Train AUC")
        if history["val_auc"]:
            axes[1].plot(history["val_auc"], label="Val AUC")
        axes[1].set_xlabel("Epoch")
        axes[1].set_ylabel("AUC-ROC")
        axes[1].set_title("Training and Validation AUC")
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(output_dir / "cascade_training_curves.png", dpi=150)
        plt.close()
    except Exception as e:
        print(f"Warning: Could not plot training curves: {e}")


def main(argv: list[str] | None = None) -> int:
    """Main training function."""
    parser = argparse.ArgumentParser(description="Train cascade vulnerability predictor")
    parser.add_argument(
        "--external-chains",
        type=str,
        default="data/external_chains",
        help="Path to external_chains JSON file",
    )
    parser.add_argument(
        "--incidents",
        type=str,
        default="supply-chain-seeds/incidents.json",
        help="Path to incidents.json file",
    )
    parser.add_argument(
        "--cve-cache",
        type=str,
        default="data/cve_cache",
        help="Directory containing cached CVE JSON files",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="outputs/models/cascade_predictor.pt",
        help="Output model path",
    )
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Training batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--val-split", type=float, default=0.2, help="Validation split fraction")
    parser.add_argument("--test-split", type=float, default=0.1, help="Test split fraction")
    parser.add_argument(
        "--early-stopping",
        type=int,
        default=20,
        help="Early stopping patience (epochs)",
    )
    parser.add_argument("--cpu", action="store_true", help="Force CPU training")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")

    args = parser.parse_args(argv)

    if not NUMPY_AVAILABLE:
        print("Error: NumPy is required. Install: pip install numpy")
        return 1

    # Load data
    if not args.quiet:
        print("=== Loading Attack Chain Data ===")

    loader = CascadeDataLoader(
        external_chains_path=Path(args.external_chains),
        incidents_path=Path(args.incidents),
        cve_cache_dir=Path(args.cve_cache),
    )

    stats = loader.load_all()
    if not args.quiet:
        for key, value in stats.items():
            print(f"  {key}: {value}")

    if stats["total_training_pairs"] < 10:
        print("Error: Insufficient training data (need at least 10 pairs)")
        return 1

    # Prepare data splits
    if not args.quiet:
        print("\n=== Preparing Data Splits ===")

    (X_train, y_train), (X_val, y_val), (X_test, y_test) = prepare_data(
        loader, val_split=args.val_split, test_split=args.test_split
    )

    if not args.quiet:
        print(f"  Train: {len(X_train)} samples ({y_train.sum()} positive)")
        print(f"  Val:   {len(X_val)} samples ({y_val.sum()} positive)")
        print(f"  Test:  {len(X_test)} samples ({y_test.sum()} positive)")

    # Initialize model and trainer
    if not args.quiet:
        print("\n=== Initializing Model ===")

    device = "cpu" if args.cpu else ("cuda" if __import__("torch").cuda.is_available() else "cpu")
    if not args.quiet:
        print(f"  Device: {device}")

    model = CascadePredictor(input_dim=22, hidden_dims=(64, 32, 16), dropout=0.3)
    trainer = CascadeTrainer(model, learning_rate=args.lr, device=device)

    if not args.quiet:
        print(f"  Parameters: {sum(p.numel() for p in model.parameters())}")

    # Train
    if not args.quiet:
        print("\n=== Training ===")

    history = trainer.train(
        X_train,
        y_train,
        X_val,
        y_val,
        epochs=args.epochs,
        batch_size=args.batch_size,
        early_stopping_patience=args.early_stopping,
        verbose=not args.quiet,
    )

    # Evaluate on test set
    if not args.quiet:
        print("\n=== Test Set Evaluation ===")

    test_loss, test_auc = trainer.evaluate(X_test, y_test)
    if not args.quiet:
        print(f"  Test Loss: {test_loss:.4f}")
        print(f"  Test AUC:  {test_auc:.4f}")

    # Save model
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    trainer.save(output_path)

    if not args.quiet:
        print(f"\n=== Model saved to {output_path} ===")

    # Plot training curves
    plot_training_curves(history, output_path.parent)

    # Summary report
    if not args.quiet:
        print("\n=== Training Summary ===")
        print(f"  Best Val AUC: {max(history['val_auc']):.4f}")
        print(f"  Final Test AUC: {test_auc:.4f}")
        print(f"  Total Epochs: {len(history['train_loss'])}")

        if test_auc > 0.75:
            print("\n✓ Model shows strong predictive performance!")
        elif test_auc > 0.65:
            print("\n~ Model shows moderate predictive performance.")
        else:
            print("\n✗ Model performance is weak. Consider:")
            print("    - Adding more training data")
            print("    - Feature engineering (e.g., CWE embeddings)")
            print("    - Different architecture (Siamese network, GNN)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
