# SBOM Attack Chain Prediction

## Overview

This project applies graph neural networks to software supply chain security.
The core contribution is a dual-model approach for vulnerability analysis:

1. **HGAT Node Classifier**: A Heterogeneous Graph Attention Network that classifies software components as vulnerable or non-vulnerable by learning from the graph structure of SBOM dependency relationships, CVE associations, and CWE mappings.

2. **MLP Link Predictor**: A Multi-Layer Perceptron that predicts CVE attack chains—pairs of vulnerabilities likely to be exploited together—using few-shot learning on documented attack chain data.

These models operate on heterogeneous graphs constructed from Software Bills of Materials (SBOMs), enabling automated vulnerability prediction and attack path discovery in software supply chains.

## Installation

```bash
# Clone the repository
git clone https://github.com/qas-lab/sbom-attack-chain-prediction.git
cd sbom-attack-chain-prediction

# Install using uv (recommended)
uv sync

# With development dependencies
uv sync --group dev
```

### Requirements

- Python 3.13+
- PyTorch and PyTorch Geometric (required for GNN models)
- NumPy, scikit-learn (for evaluation metrics)

### API Keys (Optional)

```bash
export NVD_API_KEY="your-nvd-api-key"      # Enhanced CVE data
export OPENAI_API_KEY="your-openai-key"    # MCP chat interface
```

---

## Dataset

The training data and model checkpoints are archived on Harvard Dataverse:

> **Dataset DOI:** [10.7910/DVN/A6CZRB](https://doi.org/10.7910/DVN/A6CZRB)

### Downloading the Dataset

```bash
# Download from Harvard Dataverse (default)
uv run python scripts/download_data.py

# Download from GitHub Releases instead
uv run python scripts/download_data.py --source github

# Download specific files only
uv run python scripts/download_data.py --files sboms.tar.gz models.tar.gz

# Extract from manually downloaded archives
uv run python scripts/download_data.py --local /path/to/downloads/
```

### Dataset Contents

| Archive | Size | Description |
|---------|------|-------------|
| `sboms.tar.gz` | 31 MB | ~5,350 SBOMs (CycloneDX JSON) |
| `scans.tar.gz` | 7.4 MB | ~2,700 enriched vulnerability scans |
| `models.tar.gz` | 752 KB | Trained HGAT and cascade predictor checkpoints |
| `evaluations.tar.gz` | 2.7 MB | Evaluation results and metrics |
| `reference_data.tar.gz` | 2.9 MB | Attack chain data and vulnerability caches |

---

## Graph Neural Network Models

### HGAT Node Classifier

The Heterogeneous Graph Attention Network (HGAT) performs node-level vulnerability classification on SBOM-derived graphs.

#### Architecture

```
Input → Linear Projection → [GAT Layer + ReLU + Dropout] × L → Classification Head → Output
```

| Component | Specification |
|-----------|---------------|
| Node Types | `component`, `cve`, `cwe` |
| Edge Types | `DEPENDS_ON`, `HAS_VULNERABILITY`, `HAS_CWE` |
| Hidden Dimension | 64 (configurable) |
| Attention Heads | 2 (configurable) |
| Layers | 2 (configurable) |
| Dropout | 0.2 |
| Aggregation | Sum |
| Output | Binary classification (vulnerable / non-vulnerable) |

#### Message Passing

The model uses `HeteroConv` with `GATConv` for each edge type:

- **component → DEPENDS_ON → component**: Propagates dependency risk
- **component → HAS_VULNERABILITY → cve**: Links components to known CVEs
- **cve → HAS_CWE → cwe**: Connects CVEs to weakness categories

Each layer applies multi-head attention with dropout, followed by ReLU activation. The final `component` embeddings pass through a linear head for binary classification.

#### Training

```bash
# Train HGAT on enriched SBOM data
uv run python -m sbom_toolkit.ml.train_hgat \
    --scan-dir outputs/scans \
    --epochs 30 \
    --hidden-dim 64 \
    --heads 2

# Evaluate on labeled SBOMs
uv run python -m sbom_toolkit.ml.hgat_eval_labels \
    --sboms-dir outputs/scans \
    --model outputs/models/hgat_best.pt
```

Training uses a 70/15/15 split by SBOM (not by node) with CrossEntropyLoss and Adam optimizer (lr=0.001, weight_decay=5e-4).

#### Inference

```bash
# Predict on a single SBOM
uv run python -m sbom_toolkit.ml.hgat_predict \
    path/to/enriched_sbom.json \
    --model outputs/models/hgat_best.pt
```

Returns per-component predictions with confidence scores.

---

### MLP Link Predictor (CascadePredictor)

The CascadePredictor performs link prediction to identify CVE pairs likely to be chained in attacks.

#### Architecture

```
Input (22-dim) → [Linear → ReLU → Dropout] × 3 → Linear → Sigmoid → Output
```

| Layer | Dimensions |
|-------|------------|
| Input | 22 |
| Hidden 1 | 64 |
| Hidden 2 | 32 |
| Hidden 3 | 16 |
| Output | 1 (probability) |
| Dropout | 0.3 |

#### Feature Engineering

Each CVE pair is represented by a 22-dimensional feature vector:

**Per-CVE Features (9 dimensions each, ×2 = 18):**
- CVSS score (normalized 0-1)
- Severity one-hot encoding (CRITICAL, HIGH, MEDIUM, LOW)
- Publication year (normalized)
- Exploited-in-wild flag (from CISA KEV)
- Reference count (log-normalized)
- CWE count (normalized)

**Interaction Features (4 dimensions):**
- CVSS score difference
- CVSS score product
- Publication year difference
- Both-exploited indicator

#### Training Data

The model uses few-shot learning on documented attack chains:

- **Positive pairs**: CVEs appearing together in documented attack chains
- **Negative pairs**: Randomly sampled CVE pairs not in known chains (2:1 ratio)
- **Sources**: External attack chain datasets, incident reports

```bash
# Train cascade predictor
uv run python -m sbom_toolkit.ml.train_cascade_predictor \
    --external-chains data/external_chains \
    --incidents supply-chain-seeds/incidents.json \
    --epochs 50
```

Training uses BCEWithLogitsLoss with early stopping (patience=10) and AUC-ROC for validation.

#### Inference

```python
import torch
from sbom_toolkit.ml.cascade_predictor import CascadePredictor, predict_cascades_in_sbom

model = CascadePredictor()
model.load_state_dict(torch.load("outputs/models/cascade_predictor.pt")["model_state_dict"])

# Predict attack chains within an SBOM
cascades = predict_cascades_in_sbom(
    model=model,
    sbom_cves=["CVE-2021-44228", "CVE-2022-22965", ...],
    cve_features_dict=features,
    threshold=0.5,
    top_k=10
)
# Returns: [(cve1, cve2, probability), ...]
```

---

## Replication Instructions

### 1. Download and Setup

```bash
# Clone repository
git clone https://github.com/qas-lab/sbom-attack-chain-prediction.git
cd sbom-attack-chain-prediction

# Install dependencies
uv sync

# Download dataset
uv run python scripts/download_data.py
```

### 2. Train HGAT Model

```bash
# Train the heterogeneous graph attention network
uv run python -m sbom_toolkit.ml.train_hgat \
    --scan-dir outputs/scans \
    --epochs 30 \
    --hidden-dim 64 \
    --heads 2 \
    --learning-rate 0.001

# Output: outputs/models/hgat_best.pt
```

### 3. Train Cascade Predictor

```bash
# Train the CVE attack chain predictor
uv run python -m sbom_toolkit.ml.train_cascade_predictor \
    --external-chains data/external_chains \
    --incidents supply-chain-seeds/incidents.json \
    --epochs 50

# Output: outputs/models/cascade_predictor.pt
```

### 4. Evaluate Models

```bash
# Evaluate HGAT on test set
uv run python -m sbom_toolkit.ml.hgat_eval_labels \
    --sboms-dir outputs/scans \
    --model outputs/models/hgat_best.pt

# Results saved to: outputs/evaluations/
```

### 5. Run Predictions

```bash
# Predict vulnerabilities on a new SBOM
uv run python -m sbom_toolkit.ml.hgat_predict \
    data/scanned_sboms/example_enriched.json \
    --model outputs/models/hgat_best.pt
```

---

## Supporting Modules

The toolkit includes infrastructure for data collection and analysis:

**SBOM Pipeline**: Generates SBOMs from GitHub repositories using Syft, CycloneDX, or cdxgen, then enriches them with vulnerability data from OSV. This provides the raw data for graph construction.

**Knowledge Graph**: Constructs heterogeneous graphs from SBOM data, NVD CVE records, and CWE/CAPEC taxonomies. The graph structure feeds directly into the HGAT model.

**Visualization**: Force-directed and hierarchical views for dependency analysis. Nodes are colored by vulnerability status (blue=safe, red=vulnerable, yellow=transitive risk).

**MCP Chat Interface**: Conversational AI interface for querying the knowledge graph and model predictions using the Model Context Protocol.

---

## CLI Reference

```bash
# Full pipeline: generate SBOM, scan, build knowledge graph
sbom pipeline https://github.com/example/project

# Train GNN models
sbom ml train-hgat --data-dir outputs/scans --epochs 30
uv run python -m sbom_toolkit.ml.train_cascade_predictor \
    --external-chains data/external_chains \
    --incidents supply-chain-seeds/incidents.json \
    --epochs 50

# Run predictions
sbom ml predict enriched_sbom.json --model-type hgat --model outputs/models/hgat_best.pt

# Interactive analysis
sbom intelligence mcp-chat --kg-file knowledge_graph.json
```

---

## Model Outputs

Training artifacts are saved to `outputs/models/`:

- `hgat_best.pt`: Best HGAT checkpoint (model state + input dimensions)
- `hgat_training_curves.png`: Loss and accuracy plots
- `cascade_predictor.pt`: Cascade predictor checkpoint

Prediction results include:
- Per-component vulnerability classification with confidence scores
- Ranked CVE pairs with attack chain likelihood probabilities

---

## Testing

```bash
# Run test suite
uv run pytest tests/

# Run with coverage
uv run pytest tests/ --cov=sbom_toolkit --cov-report=html
```

---

## Citation

If you use this software or dataset, please cite:

```bibtex
@inproceedings{BairdMoin2026,
  author    = {Laura Baird and Armin Moin},
  title     = {Towards Predicting Multi-Vulnerability Attack Chains in Software Supply Chains from Software Bill of Materials Graphs},
  booktitle = {Proceedings of the 34th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering Companion (FSE Companion '26)},
  year      = {2026},
  doi       = {10.1145/3803437.3805583},
  address   = {Montreal, QC, Canada},
  publisher = {ACM}
}
```

## License

This project is licensed under the [MIT License](LICENSE).
Dataset available under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/)
via [Harvard Dataverse](https://doi.org/10.7910/DVN/A6CZRB).
