"""
Prediction loader for ML model outputs.

This module provides functionality to load and normalize predictions from
HGAT (component vulnerability predictions) and MLP cascade predictor
(CVE attack chain predictions) models for use in visualization.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any


class PredictionLoader:
    """Loads and normalizes ML predictions for visualization integration.

    Handles:
    - HGAT predictions: {component: {"prediction": label, "confidence": float}}
    - Cascade predictions: [(cve1, cve2, probability), ...]

    Normalizes component identifiers to match between SBOM data and model outputs.
    """

    def __init__(self) -> None:
        """Initialize the prediction loader."""
        self.logger = logging.getLogger(__name__)
        self.hgat_predictions: dict[str, dict[str, str | float]] = {}
        self.cascade_predictions: list[tuple[str, str, float]] = []
        self._normalized_key_map: dict[str, str] = {}

    def load_hgat_predictions(self, predictions: dict[str, dict[str, str | float]]) -> None:
        """Load HGAT predictions from a dictionary.

        Args:
            predictions: Dictionary mapping component identifiers to predictions.
                Format: {component_id: {"prediction": "Vulnerable"|"Non-Vulnerable", "confidence": float}}

        Note:
            Calling this method multiple times replaces all previous predictions.
            The normalized key map is cleared and rebuilt to avoid stale entries.
        """
        self.hgat_predictions = predictions.copy()

        # Clear and rebuild normalized key map to avoid stale entries
        # from previous loads pointing to keys that no longer exist
        self._normalized_key_map.clear()
        for key in predictions:
            normalized = self._normalize_component_key(key)
            self._normalized_key_map[normalized] = key

        self.logger.info(f"Loaded {len(predictions)} HGAT predictions")

    def load_cascade_predictions(self, predictions: list[tuple[str, str, float]]) -> None:
        """Load cascade predictions.

        Args:
            predictions: List of (cve1, cve2, probability) tuples representing
                predicted attack chains between CVEs.
        """
        self.cascade_predictions = list(predictions)
        self.logger.info(f"Loaded {len(predictions)} cascade predictions")

    def load_from_file(self, file_path: Path) -> None:
        """Load predictions from a JSON file.

        Expected file format:
        {
            "hgat_predictions": {component: {prediction, confidence}, ...},
            "cascade_predictions": [{cve1, cve2, probability}, ...],
            "model_info": {...}  # Optional metadata
        }

        Args:
            file_path: Path to predictions JSON file.

        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file is not valid JSON.
        """
        self.logger.info(f"Loading predictions from {file_path}")

        with open(file_path) as f:
            data = json.load(f)

        # Load HGAT predictions
        if "hgat_predictions" in data:
            self.load_hgat_predictions(data["hgat_predictions"])

        # Load cascade predictions (convert from dict format if needed)
        if "cascade_predictions" in data:
            cascades = data["cascade_predictions"]
            if cascades and isinstance(cascades[0], dict):
                # Convert from dict format: {cve1, cve2, probability}
                self.cascade_predictions = [
                    (c["cve1"], c["cve2"], c["probability"]) for c in cascades
                ]
            else:
                # Already in tuple format
                self.cascade_predictions = [tuple(c) for c in cascades]
            self.logger.info(f"Loaded {len(self.cascade_predictions)} cascade predictions")

        # Log model info if present
        if "model_info" in data:
            self.logger.info(f"Predictions from: {data['model_info']}")

    def has_hgat_predictions(self) -> bool:
        """Check if HGAT predictions are loaded.

        Returns:
            True if predictions are available.
        """
        return len(self.hgat_predictions) > 0

    def has_cascade_predictions(self) -> bool:
        """Check if cascade predictions are loaded.

        Returns:
            True if predictions are available.
        """
        return len(self.cascade_predictions) > 0

    def get_component_prediction(self, component_id: str) -> dict[str, str | float] | None:
        """Get HGAT prediction for a component.

        Tries multiple key formats to find a match:
        - Exact match
        - Normalized key (pkg:pypi/name@version -> name@version)
        - Version separator variants (@ vs ==)

        Args:
            component_id: Component identifier (e.g., "pkg:pypi/flask@2.0.0")

        Returns:
            Prediction dict with "prediction" and "confidence" keys, or None if not found.
        """
        # Try exact match first
        if component_id in self.hgat_predictions:
            return self.hgat_predictions[component_id]

        # Try normalized key lookup
        normalized = self._normalize_component_key(component_id)
        if normalized in self._normalized_key_map:
            original_key = self._normalized_key_map[normalized]
            return self.hgat_predictions.get(original_key)

        # Try alternative formats
        alternatives = self._generate_key_alternatives(component_id)
        for alt in alternatives:
            if alt in self.hgat_predictions:
                return self.hgat_predictions[alt]
            # Also check normalized version
            alt_normalized = self._normalize_component_key(alt)
            if alt_normalized in self._normalized_key_map:
                original_key = self._normalized_key_map[alt_normalized]
                return self.hgat_predictions.get(original_key)

        return None

    def get_cascades_for_cve(self, cve_id: str) -> list[tuple[str, str, float]]:
        """Get cascade predictions involving a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            List of (cve1, cve2, probability) tuples where the given CVE is cve1.
        """
        return [c for c in self.cascade_predictions if c[0] == cve_id]

    def get_all_cascades_for_cve(self, cve_id: str) -> list[tuple[str, str, float]]:
        """Get all cascade predictions involving a specific CVE (as source or target).

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-12345")

        Returns:
            List of (cve1, cve2, probability) tuples where the given CVE appears.
        """
        return [c for c in self.cascade_predictions if c[0] == cve_id or c[1] == cve_id]

    def merge_with_sbom(self, sbom_data: dict[str, Any]) -> dict[str, Any]:
        """Merge predictions into SBOM data.

        Adds ml_prediction field to each component in the SBOM.

        Args:
            sbom_data: SBOM data dictionary.

        Returns:
            Modified SBOM data with predictions added to components.
        """
        merged = sbom_data.copy()
        components = merged.get("components", [])

        for component in components:
            # Get component identifier
            component_id = component.get("bom-ref")
            if not component_id:
                name = component.get("name", "")
                version = component.get("version", "")
                component_id = f"{name}@{version}" if version else name

            # Get prediction for this component
            prediction = self.get_component_prediction(component_id)

            if prediction:
                component["ml_prediction"] = {
                    "prediction": prediction.get("prediction", "Unknown"),
                    "confidence": prediction.get("confidence", 0.0),
                }
            else:
                component["ml_prediction"] = {
                    "prediction": "Unknown",
                    "confidence": 0.0,
                }

            # Add cascade information for components with vulnerabilities
            vulnerabilities = component.get("vulnerabilities", [])
            if vulnerabilities and self.has_cascade_predictions():
                cascade_info = []
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cve_id") or vuln.get("id", "")
                    if cve_id:
                        cascades = self.get_all_cascades_for_cve(cve_id)
                        for c in cascades:
                            cascade_info.append(
                                {
                                    "source_cve": c[0],
                                    "target_cve": c[1],
                                    "probability": c[2],
                                }
                            )
                if cascade_info:
                    component["cascade_predictions"] = cascade_info

        merged["components"] = components
        return merged

    def get_predictions_summary(self) -> dict[str, Any]:
        """Get summary of loaded predictions.

        Returns:
            Dictionary with prediction statistics.
        """
        vulnerable_count = 0
        non_vulnerable_count = 0
        high_confidence_count = 0

        for pred in self.hgat_predictions.values():
            if pred.get("prediction") == "Vulnerable":
                vulnerable_count += 1
            else:
                non_vulnerable_count += 1
            if pred.get("confidence", 0) >= 0.8:
                high_confidence_count += 1

        return {
            "hgat_total": len(self.hgat_predictions),
            "hgat_vulnerable": vulnerable_count,
            "hgat_non_vulnerable": non_vulnerable_count,
            "hgat_high_confidence": high_confidence_count,
            "cascade_total": len(self.cascade_predictions),
            "cascade_high_probability": sum(1 for c in self.cascade_predictions if c[2] >= 0.7),
        }

    def _normalize_component_key(self, key: str) -> str:
        """Normalize a component identifier for flexible matching.

        Handles various formats:
        - pkg:pypi/name@version -> name@version
        - name==version -> name@version
        - Name@Version -> name@version (lowercase)

        Args:
            key: Component identifier.

        Returns:
            Normalized key string.
        """
        normalized = key.lower()

        # Remove purl prefix (pkg:pypi/, pkg:npm/, etc.)
        purl_pattern = r"^pkg:[a-z]+/"
        normalized = re.sub(purl_pattern, "", normalized)

        # Normalize version separator (== to @)
        normalized = normalized.replace("==", "@")

        return normalized

    def _generate_key_alternatives(self, key: str) -> list[str]:
        """Generate alternative key formats for lookup.

        Args:
            key: Original component identifier.

        Returns:
            List of alternative key formats to try.
        """
        alternatives = []

        # Extract name and version
        name = ""
        version = ""

        # Try to parse purl format
        if key.startswith("pkg:"):
            # pkg:pypi/name@version
            match = re.match(r"pkg:[a-z]+/([^@]+)@?(.*)$", key, re.IGNORECASE)
            if match:
                name = match.group(1)
                version = match.group(2) or ""
        elif "==" in key:
            # name==version
            parts = key.split("==", 1)
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
        elif "@" in key:
            # name@version
            parts = key.split("@", 1)
            name = parts[0]
            version = parts[1] if len(parts) > 1 else ""
        else:
            name = key

        if name:
            if version:
                alternatives.append(f"{name}@{version}")
                alternatives.append(f"{name}=={version}")
                alternatives.append(f"pkg:pypi/{name}@{version}")
                alternatives.append(f"{name.lower()}@{version}")
                alternatives.append(f"{name.lower()}=={version}")
            else:
                alternatives.append(name)
                alternatives.append(name.lower())

        return alternatives


def load_predictions_for_visualization(
    hgat_predictions: dict[str, dict[str, str | float]] | None = None,
    cascade_predictions: list[tuple[str, str, float]] | None = None,
    predictions_file: Path | None = None,
) -> PredictionLoader:
    """Convenience function to create and load a PredictionLoader.

    Args:
        hgat_predictions: Optional HGAT predictions dict.
        cascade_predictions: Optional cascade predictions list.
        predictions_file: Optional path to predictions JSON file.

    Returns:
        Configured PredictionLoader instance.
    """
    loader = PredictionLoader()

    if predictions_file:
        loader.load_from_file(predictions_file)

    if hgat_predictions:
        loader.load_hgat_predictions(hgat_predictions)

    if cascade_predictions:
        loader.load_cascade_predictions(cascade_predictions)

    return loader
