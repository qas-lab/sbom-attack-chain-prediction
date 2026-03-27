"""
Predict cascaded vulnerabilities in an SBOM using the trained cascade predictor.

This script takes an enriched SBOM, extracts CVEs, and predicts which CVE pairs
are likely to be exploited together in an attack chain.

Usage:
    python -m sbom_toolkit.ml.predict_sbom_cascades \
        --sbom outputs/scans/my_project_enriched.json \
        --model outputs/models/cascade_predictor.pt \
        --cve-cache data/cve_cache \
        --threshold 0.5 \
        --top-k 10
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import torch

    TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False

from .cascade_data_loader import CascadeDataLoader
from .cascade_predictor import CascadePredictor, predict_cascades_in_sbom


def extract_cves_from_sbom(sbom_path: Path) -> tuple[set[str], dict[str, list[str]]]:
    """Extract CVEs from an enriched SBOM.

    Args:
        sbom_path: Path to enriched SBOM JSON

    Returns:
        all_cves: Set of all CVE IDs in SBOM
        component_to_cves: Mapping from component key to CVE list
    """
    try:
        with open(sbom_path, encoding="utf-8") as f:
            sbom = json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to load SBOM: {e}") from e

    components = sbom.get("components", [])
    if not isinstance(components, list):
        raise ValueError("SBOM missing 'components' array")

    all_cves: set[str] = set()
    component_to_cves: dict[str, list[str]] = {}

    for comp in components:
        if not isinstance(comp, dict):
            continue

        comp_key = comp.get("purl") or comp.get("bom-ref") or comp.get("name", "unknown")
        vulns = comp.get("vulnerabilities", [])

        if not isinstance(vulns, list):
            continue

        cve_list = []
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            cve_id = vuln.get("cve_id") or vuln.get("id") or vuln.get("source_id")
            if cve_id and isinstance(cve_id, str):
                all_cves.add(cve_id)
                cve_list.append(cve_id)

        if cve_list:
            component_to_cves[comp_key] = cve_list

    return all_cves, component_to_cves


def format_cascade_report(
    predictions: list[tuple[str, str, float]],
    component_to_cves: dict[str, list[str]],
) -> str:
    """Format cascade predictions as a readable report.

    Args:
        predictions: List of (cve1, cve2, probability) tuples
        component_to_cves: Component-to-CVE mapping

    Returns:
        Formatted report string
    """
    if not predictions:
        return "No high-probability cascades detected."

    lines = []
    lines.append("=" * 80)
    lines.append("PREDICTED VULNERABILITY CASCADES")
    lines.append("=" * 80)
    lines.append("")

    for i, (cve1, cve2, prob) in enumerate(predictions, 1):
        lines.append(f"{i}. {cve1} ⟶ {cve2}")
        lines.append(f"   Cascade Probability: {prob:.4f}")

        # Find components affected by each CVE
        comps1 = [k for k, v in component_to_cves.items() if cve1 in v]
        comps2 = [k for k, v in component_to_cves.items() if cve2 in v]

        if comps1:
            lines.append(f"   {cve1} affects: {', '.join(comps1[:3])}")
            if len(comps1) > 3:
                lines.append(f"      ... and {len(comps1) - 3} more")

        if comps2:
            lines.append(f"   {cve2} affects: {', '.join(comps2[:3])}")
            if len(comps2) > 3:
                lines.append(f"      ... and {len(comps2) - 3} more")

        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Main prediction function."""
    parser = argparse.ArgumentParser(description="Predict cascaded vulnerabilities in SBOM")
    parser.add_argument(
        "--sbom",
        type=str,
        required=True,
        help="Path to enriched SBOM JSON file",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="outputs/models/cascade_predictor.pt",
        help="Path to trained cascade predictor model",
    )
    parser.add_argument(
        "--cve-cache",
        type=str,
        default="data/cve_cache",
        help="Directory containing cached CVE JSON files",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Minimum probability threshold for reporting",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="Maximum number of cascades to report",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Optional: Save results to JSON file",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )

    args = parser.parse_args(argv)

    if not TORCH_AVAILABLE or not NUMPY_AVAILABLE:
        print("Error: PyTorch and NumPy required. Install: pip install torch numpy")
        return 1

    sbom_path = Path(args.sbom)
    model_path = Path(args.model)
    cve_cache_dir = Path(args.cve_cache)

    if not sbom_path.exists():
        print(f"Error: SBOM not found: {sbom_path}")
        return 1

    if not model_path.exists():
        print(f"Error: Model not found: {model_path}")
        print("Train the model first using train_cascade_predictor.py")
        return 1

    # Extract CVEs from SBOM
    if not args.quiet:
        print(f"Loading SBOM: {sbom_path}")

    try:
        all_cves, component_to_cves = extract_cves_from_sbom(sbom_path)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    if not all_cves:
        print("No CVEs found in SBOM. Nothing to predict.")
        return 0

    if not args.quiet:
        print(f"Found {len(all_cves)} unique CVEs in {len(component_to_cves)} components")

    if len(all_cves) < 2:
        print("Insufficient CVEs for cascade prediction (need at least 2)")
        return 0

    # Load CVE features
    if not args.quiet:
        print("Loading CVE features...")

    loader = CascadeDataLoader(cve_cache_dir=cve_cache_dir)
    loader.all_cves = all_cves
    n_features = loader.load_cve_features()

    if not args.quiet:
        print(f"Loaded features for {n_features}/{len(all_cves)} CVEs")

    # Prepare feature dictionary
    cve_features_dict = {}
    for cve_id in all_cves:
        if cve_id in loader.cve_features:
            cve_features_dict[cve_id] = loader.cve_features[cve_id].to_vector()

    # Load model
    if not args.quiet:
        print(f"Loading model: {model_path}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = CascadePredictor()

    try:
        checkpoint = torch.load(model_path, map_location=device)
        model.load_state_dict(checkpoint["model_state_dict"])
        model.to(device)
        model.eval()
    except Exception as e:
        print(f"Error loading model: {e}")
        return 1

    # Predict cascades
    if not args.quiet:
        print("Predicting vulnerability cascades...")

    predictions = predict_cascades_in_sbom(
        model,
        list(all_cves),
        cve_features_dict,
        threshold=args.threshold,
        top_k=args.top_k,
    )

    # Format and display report
    report = format_cascade_report(predictions, component_to_cves)
    print("\n" + report)

    # Save to JSON if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        results = {
            "sbom_path": str(sbom_path),
            "num_cves": len(all_cves),
            "num_components": len(component_to_cves),
            "threshold": args.threshold,
            "top_k": args.top_k,
            "predictions": [
                {
                    "cve1": cve1,
                    "cve2": cve2,
                    "probability": float(prob),
                    "rank": i + 1,
                }
                for i, (cve1, cve2, prob) in enumerate(predictions)
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        if not args.quiet:
            print(f"\nResults saved to: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
