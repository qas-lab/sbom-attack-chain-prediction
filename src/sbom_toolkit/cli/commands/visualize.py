"""
Visualization commands for SBOM toolkit CLI.

Supports ML prediction integration:
- HGAT model predictions for component vulnerability
- MLP cascade predictions for CVE attack chains
"""

import json
import sys
from pathlib import Path
from typing import Any

from ...shared.exceptions import SBOMToolkitError
from ...visualization import (
    create_d3_visualization,
    create_unified_visualization,
    get_available_layouts,
)
from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


def _load_predictions(
    hgat_model_path: Path | None,
    cascade_model_path: Path | None,
    predictions_file: Path | None,
    sbom_path: Path,
) -> dict[str, Any] | None:
    """Load ML predictions from models or pre-computed file.

    Args:
        hgat_model_path: Path to HGAT model file
        cascade_model_path: Path to cascade predictor model file
        predictions_file: Path to pre-computed predictions JSON file
        sbom_path: Path to SBOM file (for running predictions)

    Returns:
        Dictionary with predictions in format expected by visualizer
    """
    predictions: dict[str, Any] = {}

    # Load from pre-computed file if provided
    if predictions_file and predictions_file.exists():
        with open(predictions_file) as f:
            file_data = json.load(f)

        if "hgat_predictions" in file_data:
            predictions["hgat"] = file_data["hgat_predictions"]
        if "cascade_predictions" in file_data:
            cascades = file_data["cascade_predictions"]
            if cascades and isinstance(cascades[0], dict):
                predictions["cascades"] = [
                    (c["cve1"], c["cve2"], c["probability"]) for c in cascades
                ]
            else:
                predictions["cascades"] = cascades

        return predictions if predictions else None

    # Try to run HGAT predictions if model provided
    if hgat_model_path and hgat_model_path.exists():
        try:
            from ...ml.hgat_predict import predict_sbom_hgat

            hgat_results = predict_sbom_hgat(sbom_path, hgat_model_path)
            if hgat_results:
                predictions["hgat"] = hgat_results
        except ImportError:
            pass  # ML dependencies not available
        except Exception:
            pass  # Model prediction failed

    # Cascade predictions require CVE features which need additional setup
    # For now, only support pre-computed cascade predictions via file

    return predictions if predictions else None


@click.command()
@click.argument("sbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", "-o", default="out", help="Output directory for visualizations")
@click.option(
    "--layout",
    "-l",
    type=click.Choice(["force-directed", "hierarchical"]),
    default="force-directed",
    help="Visualization layout type",
)
@click.option(
    "--hgat-model",
    type=click.Path(exists=True, path_type=Path),
    help="Path to HGAT model for vulnerability predictions",
)
@click.option(
    "--predictions-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to pre-computed predictions JSON file",
)
@click.option("--open-browser", is_flag=True, help="Open visualization in browser after creation")
@click.pass_context
def visualize(
    ctx: Any,
    sbom_path: Path,
    output_dir: str,
    layout: str,
    hgat_model: Path | None,
    predictions_file: Path | None,
    open_browser: bool,
) -> None:
    """Create interactive D3.js visualization of SBOM with ML predictions."""
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        # Check if SBOM already contains vulnerability data
        with open(sbom_path) as f:
            sbom_data = json.load(f)

        # Check if any component has vulnerability data
        has_vulnerability_data = False
        for component in sbom_data.get("components", []):
            if "vulnerabilities" in component and component["vulnerabilities"]:
                has_vulnerability_data = True
                break

        actual_sbom_path = sbom_path
        if not has_vulnerability_data:
            click.echo("🔍 No vulnerability data found, enriching SBOM...")
            from ...pipeline.security.scanning import process_single_sbom

            enriched_output_path = output_dir_path / f"{sbom_path.stem}_enriched.json"
            success = process_single_sbom(sbom_path, enriched_output_path)
            enriched_path = enriched_output_path if success else None

            if enriched_path:
                actual_sbom_path = enriched_path
                click.echo(f"✓ Created enriched SBOM: {enriched_path}")
            else:
                click.echo("⚠ Failed to enrich SBOM, using original data")

        # Load ML predictions if available
        predictions = _load_predictions(
            hgat_model_path=hgat_model,
            cascade_model_path=None,
            predictions_file=predictions_file,
            sbom_path=actual_sbom_path,
        )

        if predictions:
            hgat_count = len(predictions.get("hgat", {}))
            cascade_count = len(predictions.get("cascades", []))
            click.echo(f"🤖 Loaded ML predictions: {hgat_count} HGAT, {cascade_count} cascades")

        # Generate output file name
        output_path = output_dir_path / f"{actual_sbom_path.stem}_{layout}_visualization.html"

        # Use D3.js visualization system
        html_path = create_d3_visualization(
            sbom_path=actual_sbom_path,
            output_path=output_path,
            layout_type=layout,
            gnn_predictions=predictions,
        )

        click.echo(f"✓ Visualization created: {html_path}")

        # Open in browser if requested
        if open_browser:
            import webbrowser

            webbrowser.open(f"file://{html_path.absolute()}")
            click.echo("Opened visualization in browser")

        logger.info(f"Visualization created for {sbom_path} at {html_path}")

    except SBOMToolkitError as e:
        logger.error(f"Visualization failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)


@click.command()
@click.argument("sbom_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", "-o", default="out", help="Output directory for visualizations")
@click.option(
    "--layouts",
    "-l",
    multiple=True,
    type=click.Choice(["force-directed", "hierarchical"]),
    help="Visualization layout types to include (can specify multiple)",
)
@click.option("--output-name", help="Custom output file name (default: auto-generated)")
@click.option(
    "--hgat-model",
    type=click.Path(exists=True, path_type=Path),
    help="Path to HGAT model for vulnerability predictions",
)
@click.option(
    "--cascade-model",
    type=click.Path(exists=True, path_type=Path),
    help="Path to cascade predictor model for attack chain predictions",
)
@click.option(
    "--predictions-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to pre-computed predictions JSON file",
)
@click.option("--open-browser", is_flag=True, help="Open visualization in browser after creation")
@click.pass_context
def unified_viz(
    ctx: Any,
    sbom_path: Path,
    output_dir: str,
    layouts: tuple[str, ...],
    output_name: str | None,
    hgat_model: Path | None,
    cascade_model: Path | None,
    predictions_file: Path | None,
    open_browser: bool,
) -> None:
    """Create unified interactive visualization with ML predictions and multiple layouts."""
    logger = ctx.obj["logger"]

    try:
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        # If no layouts specified, use all available
        layout_list: list[str]
        if not layouts:
            layout_list = get_available_layouts()
            click.echo(f"📊 No layouts specified, using available: {', '.join(layout_list)}")
        else:
            layout_list = list(layouts)
            click.echo(f"📊 Creating visualization with layouts: {', '.join(layout_list)}")

        # Check if SBOM already contains vulnerability data
        with open(sbom_path) as f:
            sbom_data = json.load(f)

        # Check if any component has vulnerability data
        has_vulnerability_data = False
        for component in sbom_data.get("components", []):
            if "vulnerabilities" in component and component["vulnerabilities"]:
                has_vulnerability_data = True
                break

        actual_sbom_path = sbom_path
        if not has_vulnerability_data:
            click.echo("🔍 No vulnerability data found, enriching SBOM...")
            from ...pipeline.security.scanning import process_single_sbom

            enriched_output_path = output_dir_path / f"{sbom_path.stem}_enriched.json"
            success = process_single_sbom(sbom_path, enriched_output_path)
            enriched_path = enriched_output_path if success else None

            if enriched_path:
                actual_sbom_path = enriched_path
                click.echo(f"✓ Created enriched SBOM: {enriched_path}")
            else:
                click.echo("⚠ Failed to enrich SBOM, using original data")

        # Load ML predictions if available
        predictions = _load_predictions(
            hgat_model_path=hgat_model,
            cascade_model_path=cascade_model,
            predictions_file=predictions_file,
            sbom_path=actual_sbom_path,
        )

        if predictions:
            hgat_count = len(predictions.get("hgat", {}))
            cascade_count = len(predictions.get("cascades", []))
            click.echo(f"🤖 Loaded ML predictions: {hgat_count} HGAT, {cascade_count} cascades")

        # Generate output file name
        if output_name:
            if not output_name.endswith(".html"):
                output_name += ".html"
            output_path = output_dir_path / output_name
        else:
            output_path = output_dir_path / f"{actual_sbom_path.stem}_unified_visualization.html"

        # Create unified visualization with predictions
        html_path = create_unified_visualization(
            sbom_path=actual_sbom_path,
            output_path=output_path,
            layout_types=layout_list,
            gnn_predictions=predictions,
        )

        click.echo(f"✓ Unified visualization created: {html_path}")
        click.echo(f"   Available layouts: {', '.join(layout_list)}")
        if predictions:
            click.echo("   ML predictions integrated")

        # Open in browser if requested
        if open_browser:
            import webbrowser

            webbrowser.open(f"file://{html_path.absolute()}")
            click.echo("📱 Opened visualization in browser")

        logger.info(f"Unified visualization created for {sbom_path} at {html_path}")

    except SBOMToolkitError as e:
        logger.error(f"Unified visualization failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)
