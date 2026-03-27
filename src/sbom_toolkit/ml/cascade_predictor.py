"""
Cascaded vulnerability predictor using few-shot learning.

This module implements a lightweight model for predicting CVE co-occurrence
patterns (attack chains) based on limited training data. The approach uses
a simple MLP on CVE pair features to predict whether two CVEs are likely
to be chained together in an attack.

For more sophisticated approaches, consider:
- Siamese networks with contrastive loss
- Metric learning (triplet loss)
- Graph neural networks with meta-learning
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]
    F = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False

try:
    from sklearn.metrics import roc_auc_score

    SKLEARN_AVAILABLE = True
except ImportError:
    roc_auc_score = None  # type: ignore[assignment]
    precision_recall_curve = None  # type: ignore[assignment]
    auc = None  # type: ignore[assignment]
    SKLEARN_AVAILABLE = False


class CascadePredictor(nn.Module):
    """MLP for predicting CVE cascade likelihood.

    Architecture:
        Input: 22-dim CVE pair features
        Hidden: 64 -> 32 -> 16
        Output: 1-dim probability (sigmoid)
    """

    def __init__(
        self,
        input_dim: int = 22,
        hidden_dims: tuple[int, ...] = (64, 32, 16),
        dropout: float = 0.3,
    ) -> None:
        super().__init__()

        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch required. Install: pip install torch")

        layers = []
        prev_dim = input_dim

        for hidden_dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, hidden_dim))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(dropout))
            prev_dim = hidden_dim

        layers.append(nn.Linear(prev_dim, 1))

        self.mlp = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: (batch_size, 22) tensor of pair features

        Returns:
            logits: (batch_size,) tensor of raw scores
        """
        return self.mlp(x).squeeze(-1)

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Predict probabilities.

        Args:
            x: (batch_size, 22) tensor of pair features

        Returns:
            probs: (batch_size,) tensor of probabilities [0, 1]
        """
        with torch.no_grad():
            logits = self.forward(x)
            return torch.sigmoid(logits)


class CascadeTrainer:
    """Trainer for cascade prediction model."""

    def __init__(
        self,
        model: CascadePredictor,
        learning_rate: float = 0.001,
        weight_decay: float = 1e-4,
        device: str = "cpu",
    ) -> None:
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch required. Install: pip install torch")
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required. Install: pip install numpy")

        self.model = model
        self.device = torch.device(device)
        self.model.to(self.device)

        self.optimizer = torch.optim.Adam(
            model.parameters(), lr=learning_rate, weight_decay=weight_decay
        )
        self.criterion = nn.BCEWithLogitsLoss()

        self.history: dict[str, list[float]] = {
            "train_loss": [],
            "train_auc": [],
            "val_loss": [],
            "val_auc": [],
        }

    def train_epoch(
        self, X: np.ndarray, y: np.ndarray, batch_size: int = 32
    ) -> tuple[float, float]:
        """Train for one epoch.

        Args:
            X: (N, 22) array of features
            y: (N,) array of labels

        Returns:
            avg_loss: Average loss
            auc_score: AUC-ROC score
        """
        self.model.train()

        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).float().to(self.device)

        indices = torch.randperm(len(X_t))
        total_loss = 0.0
        num_batches = 0

        for i in range(0, len(X_t), batch_size):
            batch_idx = indices[i : i + batch_size]
            X_batch = X_t[batch_idx]
            y_batch = y_t[batch_idx]

            self.optimizer.zero_grad()
            logits = self.model(X_batch)
            loss = self.criterion(logits, y_batch)
            loss.backward()
            self.optimizer.step()

            total_loss += loss.item()
            num_batches += 1

        denom = float(num_batches) if num_batches > 0 else 1.0
        avg_loss = total_loss / denom

        # Compute AUC on full training set
        with torch.no_grad():
            self.model.eval()
            logits_all = self.model(X_t)
            probs = torch.sigmoid(logits_all).cpu().numpy()
            auc_score = self._compute_auc(y, probs)

        return avg_loss, auc_score

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> tuple[float, float]:
        """Evaluate on validation/test set.

        Args:
            X: (N, 22) array of features
            y: (N,) array of labels

        Returns:
            avg_loss: Average loss
            auc_score: AUC-ROC score
        """
        self.model.eval()

        X_t = torch.from_numpy(X).float().to(self.device)
        y_t = torch.from_numpy(y).float().to(self.device)

        with torch.no_grad():
            logits = self.model(X_t)
            loss = self.criterion(logits, y_t)
            probs = torch.sigmoid(logits).cpu().numpy()
            auc_score = self._compute_auc(y, probs)

        return float(loss.item()), auc_score

    def _compute_auc(self, y_true: np.ndarray, y_pred: np.ndarray) -> float:
        """Compute AUC-ROC score."""
        if not SKLEARN_AVAILABLE or roc_auc_score is None:
            return 0.0
        try:
            return float(roc_auc_score(y_true, y_pred))
        except Exception:
            return 0.0

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray | None = None,
        y_val: np.ndarray | None = None,
        epochs: int = 50,
        batch_size: int = 32,
        early_stopping_patience: int = 10,
        verbose: bool = True,
    ) -> dict[str, Any]:
        """Full training loop with early stopping.

        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            epochs: Maximum number of epochs
            batch_size: Batch size
            early_stopping_patience: Stop if no improvement for N epochs
            verbose: Print progress

        Returns:
            Training history dictionary
        """
        best_val_auc = 0.0
        patience_counter = 0

        for epoch in range(1, epochs + 1):
            train_loss, train_auc = self.train_epoch(X_train, y_train, batch_size)
            self.history["train_loss"].append(train_loss)
            self.history["train_auc"].append(train_auc)

            # Validation
            if X_val is not None and y_val is not None:
                val_loss, val_auc = self.evaluate(X_val, y_val)
                self.history["val_loss"].append(val_loss)
                self.history["val_auc"].append(val_auc)

                if verbose:
                    print(
                        f"Epoch {epoch:03d}: "
                        f"train_loss={train_loss:.4f} train_auc={train_auc:.4f} | "
                        f"val_loss={val_loss:.4f} val_auc={val_auc:.4f}"
                    )

                # Early stopping
                if val_auc > best_val_auc:
                    best_val_auc = val_auc
                    patience_counter = 0
                else:
                    patience_counter += 1

                if patience_counter >= early_stopping_patience:
                    if verbose:
                        print(f"Early stopping at epoch {epoch}")
                    break
            else:
                if verbose:
                    print(
                        f"Epoch {epoch:03d}: train_loss={train_loss:.4f} train_auc={train_auc:.4f}"
                    )

        return self.history

    def save(self, path: Path) -> None:
        """Save model checkpoint."""
        torch.save(
            {
                "model_state_dict": self.model.state_dict(),
                "optimizer_state_dict": self.optimizer.state_dict(),
                "history": self.history,
            },
            path,
        )

    def load(self, path: Path) -> None:
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        self.history = checkpoint.get("history", self.history)


def predict_cascades_in_sbom(
    model: CascadePredictor,
    sbom_cves: list[str],
    cve_features_dict: dict[str, Any],
    threshold: float = 0.5,
    top_k: int = 10,
) -> list[tuple[str, str, float]]:
    """Predict likely CVE cascades within an SBOM.

    Args:
        model: Trained cascade predictor
        sbom_cves: List of CVE IDs present in the SBOM
        cve_features_dict: Dictionary mapping CVE ID to feature vector
        threshold: Minimum probability threshold
        top_k: Return top-k most likely cascades

    Returns:
        List of (cve1, cve2, probability) tuples, sorted by probability descending
    """
    if not TORCH_AVAILABLE or not NUMPY_AVAILABLE:
        raise ImportError("PyTorch and NumPy required")

    if len(sbom_cves) < 2:
        return []

    model.eval()

    # Determine model device
    device = next(model.parameters()).device

    # Generate all pairs with full 22-dim features (including interaction features)
    pairs: list[tuple[str, str]] = []
    features: list[np.ndarray] = []

    for i, cve1 in enumerate(sbom_cves):
        for cve2 in sbom_cves[i + 1 :]:
            if cve1 not in cve_features_dict or cve2 not in cve_features_dict:
                continue
            pairs.append((cve1, cve2))

            # Get individual CVE features (9-dim each)
            feat1 = cve_features_dict[cve1]
            feat2 = cve_features_dict[cve2]

            # Compute interaction features (4-dim)
            # Must match get_pair_features() in cascade_data_loader.py
            cvss_diff = abs(feat1[0] - feat2[0])
            cvss_product = feat1[0] * feat2[0]
            year_diff = abs(feat1[5] - feat2[5])
            both_exploited = feat1[6] * feat2[6]

            interaction = np.array(
                [cvss_diff, cvss_product, year_diff, both_exploited], dtype=np.float32
            )

            # Concatenate: 9 + 9 + 4 = 22 dims
            feat = np.concatenate([feat1, feat2, interaction])
            features.append(feat)

    if not features:
        return []

    X = np.stack(features)
    X_t = torch.from_numpy(X).float().to(device)

    with torch.no_grad():
        probs = model.predict_proba(X_t).cpu().numpy()

    # Filter and sort
    results = [
        (cve1, cve2, float(prob))
        for (cve1, cve2), prob in zip(pairs, probs, strict=False)
        if prob >= threshold
    ]
    results.sort(key=lambda x: x[2], reverse=True)

    return results[:top_k]


if __name__ == "__main__":
    # Quick architecture test
    if TORCH_AVAILABLE:
        model = CascadePredictor()
        print("=== Cascade Predictor Architecture ===")
        print(model)
        print(f"\nTotal parameters: {sum(p.numel() for p in model.parameters())}")

        # Test forward pass
        dummy_input = torch.randn(4, 22)
        output = model(dummy_input)
        print(f"\nTest forward pass: input shape={dummy_input.shape}, output shape={output.shape}")
    else:
        print("PyTorch not available")
