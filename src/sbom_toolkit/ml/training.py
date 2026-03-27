"""
GCN-based vulnerability prediction training module.

This module provides functionality to train a Graph Convolutional Network (GCN)
for predicting vulnerable components in SBOMs.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

# Optional dependencies with graceful fallbacks
try:
    import matplotlib.pyplot as plt
    import seaborn as sns

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None  # type: ignore[assignment]
    sns = None  # type: ignore[assignment]

try:
    import torch
    import torch.nn.functional as F
    from torch_geometric.data import Data
    from torch_geometric.loader import DataLoader
    from torch_geometric.nn import GCNConv

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None  # type: ignore[assignment]
    F = None  # type: ignore[assignment]
    Data = None  # type: ignore[assignment]
    DataLoader = None  # type: ignore[assignment]
    GCNConv = None  # type: ignore[assignment]

try:
    from sklearn.metrics import (
        auc,
        classification_report,
        confusion_matrix,
        precision_recall_curve,
        roc_curve,
    )

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    auc = None  # type: ignore[assignment]
    classification_report = None  # type: ignore[assignment]
    confusion_matrix = None  # type: ignore[assignment]
    precision_recall_curve = None  # type: ignore[assignment]
    roc_curve = None  # type: ignore[assignment]


def check_dependencies() -> None:
    """Check if all required dependencies are available."""
    if not TORCH_AVAILABLE:
        raise ImportError(
            "PyTorch and PyTorch Geometric are required for ML training. "
            "Install with: pip install torch torch-geometric"
        )
    if not SKLEARN_AVAILABLE:
        raise ImportError(
            "scikit-learn is required for ML training. Install with: pip install scikit-learn"
        )


def _safe_torch_load(path: Path) -> dict[str, Any]:
    """Load a PyTorch state dict with compatibility for older versions.

    The `weights_only` parameter was added in PyTorch 1.13. This function
    provides a fallback for older versions.

    Args:
        path: Path to the saved model file.

    Returns:
        The loaded state dictionary.
    """
    if torch is None:
        raise ImportError("PyTorch is required but not available")

    # Check if weights_only parameter is supported (PyTorch >= 1.13)
    try:
        return torch.load(path, weights_only=True)
    except TypeError:
        # Fallback for older PyTorch versions that don't support weights_only
        return torch.load(path)


@dataclass
class TrainingConfig:
    """Configuration for model training."""

    data_dir: Path = field(default_factory=lambda: Path("scanned_sboms"))
    output_dir: Path = field(default_factory=lambda: Path("outputs/models"))
    batch_size: int = 4
    learning_rate: float = 0.01
    weight_decay: float = 5e-4
    hidden_channels: int = 64
    dropout: float = 0.5
    max_epochs: int = 100
    patience: int = 5
    train_split: float = 0.7
    val_split: float = 0.15
    random_seed: int | None = None


@dataclass
class TrainingResults:
    """Results from a training run."""

    train_losses: list[float] = field(default_factory=list)
    val_losses: list[float] = field(default_factory=list)
    train_accuracies: list[float] = field(default_factory=list)
    val_accuracies: list[float] = field(default_factory=list)
    test_loss: float = 0.0
    test_accuracy: float = 0.0
    test_report: dict[str, Any] = field(default_factory=dict)
    epochs_trained: int = 0
    best_val_loss: float = float("inf")


class VulnerabilityGCN(torch.nn.Module):
    """Graph Convolutional Network for vulnerability prediction."""

    dropout: float

    def __init__(
        self,
        in_channels: int,
        hidden_channels: int,
        out_channels: int,
        dropout: float = 0.5,
    ):
        super().__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, out_channels)
        # Store dropout as instance attribute
        object.__setattr__(self, "dropout", float(dropout))

    def forward(self, x: "torch.Tensor", edge_index: "torch.Tensor") -> "torch.Tensor":
        """Forward pass through the network."""
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv3(x, edge_index)
        return x


class GCNTrainer:
    """Trainer for the VulnerabilityGCN model."""

    def __init__(self, config: TrainingConfig):
        """Initialize the trainer with configuration."""
        check_dependencies()
        self.config = config
        self.model: VulnerabilityGCN | None = None
        self.optimizer: Any = None
        self.criterion: Any = None
        self.train_loader: Any = None
        self.val_loader: Any = None
        self.test_loader: Any = None
        self.results = TrainingResults()

        # Set random seed if specified
        if config.random_seed is not None:
            np.random.seed(config.random_seed)
            torch.manual_seed(config.random_seed)

    def load_data(self) -> int:
        """Load and prepare training data.

        Returns:
            Number of graphs loaded.
        """
        from .processing import TOTAL_FEATURES, sbom_to_graph_data

        # Collect all enriched files
        sbom_files = list(self.config.data_dir.glob("*_enriched*"))
        print(f"Found {len(sbom_files)} enriched SBOM files in {self.config.data_dir}")

        graph_data_list: list[Data] = []
        for sbom_file in sbom_files:
            data = sbom_to_graph_data(sbom_file)
            if data is not None:
                graph_data_list.append(data)
            else:
                print(f"Skipped {sbom_file} (could not convert to graph data)")

        if not graph_data_list:
            raise ValueError(
                f"No graph data loaded from {self.config.data_dir}. "
                "Check that enriched SBOM files exist."
            )

        print(f"Loaded {len(graph_data_list)} graphs.")

        # Split data
        train_size = int(self.config.train_split * len(graph_data_list))
        val_size = int(self.config.val_split * len(graph_data_list))

        indices = list(range(len(graph_data_list)))
        np.random.shuffle(indices)
        train_indices = indices[:train_size]
        val_indices = indices[train_size : train_size + val_size]
        test_indices = indices[train_size + val_size :]

        # Create data loaders
        self.train_loader = DataLoader(
            [graph_data_list[i] for i in train_indices],
            batch_size=self.config.batch_size,
            shuffle=True,
        )
        self.val_loader = DataLoader(
            [graph_data_list[i] for i in val_indices],
            batch_size=self.config.batch_size,
            shuffle=False,
        )
        self.test_loader = DataLoader(
            [graph_data_list[i] for i in test_indices],
            batch_size=self.config.batch_size,
            shuffle=False,
        )

        # Initialize model
        self.model = VulnerabilityGCN(
            in_channels=TOTAL_FEATURES,
            hidden_channels=self.config.hidden_channels,
            out_channels=2,
            dropout=self.config.dropout,
        )
        self.optimizer = torch.optim.Adam(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )
        self.criterion = torch.nn.CrossEntropyLoss()

        return len(graph_data_list)

    def _train_epoch(self) -> tuple[float, float, Any, dict[str, Any]]:
        """Train for one epoch."""
        if self.model is None or self.train_loader is None:
            raise RuntimeError("Model not initialized. Call load_data() first.")

        self.model.train()
        total_loss = 0.0
        all_preds: list[int] = []
        all_labels: list[int] = []

        for batch in self.train_loader:
            self.optimizer.zero_grad()
            out = self.model(batch.x, batch.edge_index)
            loss = self.criterion(out, batch.y)
            loss.backward()
            self.optimizer.step()
            total_loss += loss.item()

            pred = out.argmax(dim=1)
            all_preds.extend(pred.cpu().numpy().tolist())
            all_labels.extend(batch.y.cpu().numpy().tolist())

        accuracy = float(np.mean(np.array(all_preds) == np.array(all_labels)))
        conf_matrix = confusion_matrix(all_labels, all_preds) if confusion_matrix else None
        report = (
            classification_report(all_labels, all_preds, output_dict=True)
            if classification_report
            else {}
        )

        return total_loss / len(self.train_loader), accuracy, conf_matrix, report

    def _validate(self) -> tuple[float, float, Any, dict[str, Any]]:
        """Validate the model."""
        if self.model is None or self.val_loader is None:
            raise RuntimeError("Model not initialized. Call load_data() first.")

        self.model.eval()
        total_loss = 0.0
        all_preds: list[int] = []
        all_labels: list[int] = []

        with torch.no_grad():
            for batch in self.val_loader:
                out = self.model(batch.x, batch.edge_index)
                loss = self.criterion(out, batch.y)
                total_loss += loss.item()

                pred = out.argmax(dim=1)
                all_preds.extend(pred.cpu().numpy().tolist())
                all_labels.extend(batch.y.cpu().numpy().tolist())

        accuracy = float(np.mean(np.array(all_preds) == np.array(all_labels)))
        conf_matrix = confusion_matrix(all_labels, all_preds) if confusion_matrix else None
        report = (
            classification_report(all_labels, all_preds, output_dict=True)
            if classification_report
            else {}
        )

        return total_loss / len(self.val_loader), accuracy, conf_matrix, report

    def _test(self) -> tuple[float, float, Any, dict[str, Any], np.ndarray, np.ndarray]:
        """Test the model."""
        if self.model is None or self.test_loader is None:
            raise RuntimeError("Model not initialized. Call load_data() first.")

        self.model.eval()
        total_loss = 0.0
        all_preds: list[int] = []
        all_labels: list[int] = []
        all_scores: list[float] = []

        with torch.no_grad():
            for batch in self.test_loader:
                out = self.model(batch.x, batch.edge_index)
                loss = self.criterion(out, batch.y)
                total_loss += loss.item()

                scores = F.softmax(out, dim=1)[:, 1]
                pred = out.argmax(dim=1)

                all_preds.extend(pred.cpu().numpy().tolist())
                all_labels.extend(batch.y.cpu().numpy().tolist())
                all_scores.extend(scores.cpu().numpy().tolist())

        accuracy = float(np.mean(np.array(all_preds) == np.array(all_labels)))
        conf_matrix = confusion_matrix(all_labels, all_preds) if confusion_matrix else None
        report = (
            classification_report(all_labels, all_preds, output_dict=True)
            if classification_report
            else {}
        )

        return (
            total_loss / len(self.test_loader),
            accuracy,
            conf_matrix,
            report,
            np.array(all_labels),
            np.array(all_scores),
        )

    def train(self, verbose: bool = True) -> TrainingResults:
        """Run the full training loop.

        Args:
            verbose: Whether to print progress.

        Returns:
            Training results.
        """
        if self.model is None:
            raise RuntimeError("Model not initialized. Call load_data() first.")

        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        best_val_loss = float("inf")
        patience_counter = 0
        train_conf_matrix = None
        val_conf_matrix = None

        for epoch in range(1, self.config.max_epochs + 1):
            train_loss, train_acc, train_conf_matrix, train_report = self._train_epoch()
            val_loss, val_acc, val_conf_matrix, val_report = self._validate()

            self.results.train_losses.append(train_loss)
            self.results.val_losses.append(val_loss)
            self.results.train_accuracies.append(train_acc)
            self.results.val_accuracies.append(val_acc)

            if verbose:
                print(f"Epoch {epoch}:")
                print(f"  Train - Loss: {train_loss:.4f}, Accuracy: {train_acc:.4f}")
                print(f"  Val   - Loss: {val_loss:.4f}, Accuracy: {val_acc:.4f}")

            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                model_path = self.config.output_dir / "best_model.pt"
                torch.save(self.model.state_dict(), model_path)
            else:
                patience_counter += 1
                if patience_counter >= self.config.patience:
                    if verbose:
                        print(f"Early stopping triggered after {epoch} epochs")
                    break

            self.results.epochs_trained = epoch

        self.results.best_val_loss = best_val_loss

        # Load best model and evaluate on test set
        model_path = self.config.output_dir / "best_model.pt"
        if model_path.exists():
            self.model.load_state_dict(_safe_torch_load(model_path))

        test_loss, test_acc, test_conf_matrix, test_report, test_labels, test_scores = self._test()
        self.results.test_loss = test_loss
        self.results.test_accuracy = test_acc
        self.results.test_report = test_report

        if verbose:
            print("\nFinal Test Results:")
            print(f"  Test - Loss: {test_loss:.4f}, Accuracy: {test_acc:.4f}")

        # Generate plots if matplotlib is available
        if MATPLOTLIB_AVAILABLE:
            self._plot_metrics()
            if train_conf_matrix is not None:
                self._plot_confusion_matrix(train_conf_matrix, "Training Confusion Matrix")
            if val_conf_matrix is not None:
                self._plot_confusion_matrix(val_conf_matrix, "Validation Confusion Matrix")
            if test_conf_matrix is not None:
                self._plot_enhanced_confusion_matrix(test_conf_matrix, "Test Confusion Matrix")
            self._plot_roc_curve(test_labels, test_scores, "Test ROC Curve")
            self._plot_precision_recall_curve(
                test_labels, test_scores, "Test Precision-Recall Curve"
            )

        return self.results

    def _plot_metrics(self) -> None:
        """Plot training metrics."""
        if plt is None:
            return

        plt.figure(figsize=(12, 5))

        plt.subplot(1, 2, 1)
        plt.plot(self.results.train_losses, label="Train Loss")
        plt.plot(self.results.val_losses, label="Validation Loss")
        plt.xlabel("Epoch")
        plt.ylabel("Loss")
        plt.legend()
        plt.title("Training and Validation Loss")

        plt.subplot(1, 2, 2)
        plt.plot(self.results.train_accuracies, label="Train Accuracy")
        plt.plot(self.results.val_accuracies, label="Validation Accuracy")
        plt.xlabel("Epoch")
        plt.ylabel("Accuracy")
        plt.legend()
        plt.title("Training and Validation Accuracy")

        plt.tight_layout()
        plt.savefig(self.config.output_dir / "training_metrics.png")
        plt.close()

    def _plot_confusion_matrix(self, conf_matrix: np.ndarray, title: str) -> None:
        """Plot a confusion matrix."""
        if plt is None:
            return

        plt.figure(figsize=(8, 6))
        plt.imshow(conf_matrix, interpolation="nearest", cmap="Blues")
        plt.title(title)
        plt.colorbar()
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.savefig(self.config.output_dir / f"{title.lower().replace(' ', '_')}.png")
        plt.close()

    def _plot_enhanced_confusion_matrix(self, conf_matrix: np.ndarray, title: str) -> None:
        """Plot an enhanced confusion matrix with annotations."""
        if plt is None or sns is None:
            return

        plt.figure(figsize=(10, 8))
        sns.heatmap(
            conf_matrix,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["No Vulnerability", "Vulnerability"],
            yticklabels=["No Vulnerability", "Vulnerability"],
        )
        plt.title(title)
        plt.xlabel("Predicted")
        plt.ylabel("True")
        plt.tight_layout()
        plt.savefig(self.config.output_dir / f"{title.lower().replace(' ', '_')}_enhanced.png")
        plt.close()

    def _plot_roc_curve(self, y_true: np.ndarray, y_scores: np.ndarray, title: str) -> None:
        """Plot ROC curve."""
        if not (roc_curve and auc and plt):
            return

        fpr, tpr, _ = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (AUC = {roc_auc:.2f})")
        plt.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title(title)
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(self.config.output_dir / f"{title.lower().replace(' ', '_')}.png")
        plt.close()

    def _plot_precision_recall_curve(
        self, y_true: np.ndarray, y_scores: np.ndarray, title: str
    ) -> None:
        """Plot precision-recall curve."""
        if not (precision_recall_curve and auc and plt):
            return

        precision, recall, _ = precision_recall_curve(y_true, y_scores)
        pr_auc = auc(recall, precision)

        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, color="blue", lw=2, label=f"PR curve (AUC = {pr_auc:.2f})")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title(title)
        plt.legend(loc="lower left")
        plt.tight_layout()
        plt.savefig(self.config.output_dir / f"{title.lower().replace(' ', '_')}.png")
        plt.close()


def run_training(
    data_dir: Path | str | None = None,
    output_dir: Path | str | None = None,
    **kwargs: Any,
) -> TrainingResults:
    """Run the training pipeline.

    Args:
        data_dir: Directory containing enriched SBOM files.
        output_dir: Directory for output files.
        **kwargs: Additional configuration options.

    Returns:
        Training results.
    """
    config = TrainingConfig()

    if data_dir is not None:
        config.data_dir = Path(data_dir)
    if output_dir is not None:
        config.output_dir = Path(output_dir)

    # Apply any additional config options
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    trainer = GCNTrainer(config)
    trainer.load_data()
    return trainer.train()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train GCN model for vulnerability prediction")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("scanned_sboms"),
        help="Directory containing enriched SBOM files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs/models"),
        help="Directory for output files",
    )
    parser.add_argument("--epochs", type=int, default=100, help="Maximum number of epochs")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.01, help="Learning rate")
    parser.add_argument("--patience", type=int, default=5, help="Early stopping patience")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")

    args = parser.parse_args()

    results = run_training(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        max_epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        patience=args.patience,
        random_seed=args.seed,
    )

    print(f"\nTraining completed after {results.epochs_trained} epochs")
    print(f"Best validation loss: {results.best_val_loss:.4f}")
    print(f"Test accuracy: {results.test_accuracy:.4f}")
