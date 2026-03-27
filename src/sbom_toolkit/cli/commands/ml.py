"""
ML training commands for SBOM toolkit CLI.
"""

import sys
from pathlib import Path

from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


@click.group(name="ml")
def ml_group() -> None:
    """Machine learning commands for vulnerability prediction."""
    pass


@ml_group.command(name="train-gcn")
@click.option(
    "--data-dir",
    "-d",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("scanned_sboms"),
    help="Directory containing enriched SBOM files",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("outputs/models"),
    help="Directory for output files (model, plots)",
)
@click.option("--epochs", type=int, default=100, help="Maximum number of training epochs")
@click.option("--batch-size", type=int, default=4, help="Training batch size")
@click.option("--learning-rate", "--lr", type=float, default=0.01, help="Learning rate")
@click.option("--patience", type=int, default=5, help="Early stopping patience")
@click.option("--hidden-dim", type=int, default=64, help="Hidden layer dimension")
@click.option("--dropout", type=float, default=0.5, help="Dropout rate")
@click.option("--seed", type=int, default=None, help="Random seed for reproducibility")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output")
def train_gcn(
    data_dir: Path,
    output_dir: Path,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    patience: int,
    hidden_dim: int,
    dropout: float,
    seed: int | None,
    quiet: bool,
) -> None:
    """Train GCN model for vulnerability prediction.

    This command trains a Graph Convolutional Network (GCN) to predict
    which components in an SBOM are likely to have vulnerabilities.

    Example:
        sbom ml train-gcn --data-dir scanned_sboms --epochs 50
    """
    # Validate data directory exists
    if not data_dir.exists():
        click.echo(f"Error: Data directory does not exist: {data_dir}", err=True)
        click.echo("Please provide a valid directory containing enriched SBOM files.", err=True)
        sys.exit(1)

    try:
        from ...ml.training import GCNTrainer, TrainingConfig

        config = TrainingConfig(
            data_dir=data_dir,
            output_dir=output_dir,
            max_epochs=epochs,
            batch_size=batch_size,
            learning_rate=learning_rate,
            patience=patience,
            hidden_channels=hidden_dim,
            dropout=dropout,
            random_seed=seed,
        )

        if not quiet:
            click.echo("Training GCN model...")
            click.echo(f"  Data directory: {data_dir}")
            click.echo(f"  Output directory: {output_dir}")
            click.echo(f"  Max epochs: {epochs}")
            click.echo(f"  Batch size: {batch_size}")
            click.echo(f"  Learning rate: {learning_rate}")
            click.echo("")

        trainer = GCNTrainer(config)
        num_graphs = trainer.load_data()

        if not quiet:
            click.echo(f"Loaded {num_graphs} graphs from {data_dir}")
            click.echo("Starting training...\n")

        results = trainer.train(verbose=not quiet)

        if not quiet:
            click.echo("\n" + "=" * 50)
            click.echo("Training Complete!")
            click.echo("=" * 50)
            click.echo(f"  Epochs trained: {results.epochs_trained}")
            click.echo(f"  Best validation loss: {results.best_val_loss:.4f}")
            click.echo(f"  Test accuracy: {results.test_accuracy:.4f}")
            click.echo(f"  Model saved to: {output_dir / 'best_model.pt'}")

    except ImportError as e:
        click.echo("Error: Missing required dependencies for ML training.", err=True)
        click.echo(f"Details: {e}", err=True)
        click.echo(
            "Install with: pip install torch torch-geometric scikit-learn matplotlib seaborn",
            err=True,
        )
        sys.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error during training: {e}", err=True)
        sys.exit(1)


@ml_group.command(name="train-hgat")
@click.option(
    "--data-dir",
    "-d",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("outputs/sboms"),
    help="Directory containing enriched SBOM files",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("outputs/models"),
    help="Directory for output files",
)
@click.option("--epochs", type=int, default=100, help="Maximum number of training epochs")
@click.option("--hidden-dim", type=int, default=64, help="Hidden layer dimension")
@click.option("--heads", type=int, default=2, help="Number of attention heads")
@click.option("--num-layers", type=int, default=2, help="Number of HGAT layers")
@click.option("--dropout", type=float, default=0.2, help="Dropout rate")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output")
def train_hgat(
    data_dir: Path,
    output_dir: Path,
    epochs: int,
    hidden_dim: int,
    heads: int,
    num_layers: int,
    dropout: float,
    quiet: bool,
) -> None:
    """Train HGAT (Heterogeneous Graph Attention Network) model.

    This command trains an HGAT model that can handle heterogeneous graphs
    with different node types (components, CVEs, CWEs).

    Example:
        sbom ml train-hgat --data-dir outputs/sboms --epochs 50
    """
    # Validate data directory exists
    if not data_dir.exists():
        click.echo(f"Error: Data directory does not exist: {data_dir}", err=True)
        click.echo("Please provide a valid directory containing enriched SBOM files.", err=True)
        sys.exit(1)

    try:
        from ...ml.train_hgat import train_hgat_model

        if not quiet:
            click.echo("Training HGAT model...")
            click.echo(f"  Data directory: {data_dir}")
            click.echo(f"  Output directory: {output_dir}")
            click.echo(f"  Max epochs: {epochs}")
            click.echo("")

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        train_hgat_model(
            data_dir=data_dir,
            output_dir=output_dir,
            max_epochs=epochs,
            hidden_dim=hidden_dim,
            heads=heads,
            num_layers=num_layers,
            dropout=dropout,
            verbose=not quiet,
        )

        if not quiet:
            click.echo("\nTraining complete!")
            click.echo(f"  Model saved to: {output_dir / 'hgat_best.pt'}")

    except ImportError as e:
        click.echo("Error: Missing required dependencies.", err=True)
        click.echo(f"Details: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error during training: {e}", err=True)
        sys.exit(1)


@ml_group.command(name="predict")
@click.argument("sbom_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--model",
    "-m",
    type=click.Path(exists=True, path_type=Path),
    default=Path("outputs/models/best_model.pt"),
    help="Path to trained model file",
)
@click.option(
    "--model-type",
    type=click.Choice(["gcn", "hgat"]),
    default="gcn",
    help="Type of model to use for prediction",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file for predictions")
@click.option("--threshold", type=float, default=0.5, help="Prediction threshold")
@click.option("--quiet", "-q", is_flag=True, help="Suppress detailed output")
def predict(
    sbom_file: Path,
    model: Path,
    model_type: str,
    output: Path | None,
    threshold: float,
    quiet: bool,
) -> None:
    """Predict vulnerabilities in an SBOM using a trained model.

    Example:
        sbom ml predict my_sbom_enriched.json --model outputs/models/best_model.pt
    """
    try:
        if model_type == "gcn":
            from ...ml.prediction import predict_vulnerabilities

            predictions = predict_vulnerabilities(
                sbom_path=sbom_file,
                model_path=model,
                threshold=threshold,
            )
        else:
            from ...ml.hgat_predict import predict_with_hgat

            predictions = predict_with_hgat(
                sbom_path=sbom_file,
                model_path=model,
                threshold=threshold,
            )

        if not quiet:
            click.echo(f"Predictions for {sbom_file.name}:")
            click.echo(f"  Total components: {predictions.get('total_components', 'N/A')}")
            click.echo(f"  Predicted vulnerable: {predictions.get('predicted_vulnerable', 'N/A')}")
            click.echo("")

            # Show top predictions if available
            top_predictions = predictions.get("top_predictions", [])
            if top_predictions:
                click.echo("Top vulnerable components:")
                for pred in top_predictions[:10]:
                    name = pred.get("name", "Unknown")
                    score = pred.get("score", 0)
                    click.echo(f"  - {name}: {score:.3f}")

        if output:
            import json

            with open(output, "w") as f:
                json.dump(predictions, f, indent=2)
            if not quiet:
                click.echo(f"\nPredictions saved to {output}")

    except ImportError as e:
        click.echo("Error: Missing required dependencies.", err=True)
        click.echo(f"Details: {e}", err=True)
        sys.exit(1)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error during prediction: {e}", err=True)
        sys.exit(1)


# Alias for convenience
train = train_gcn
