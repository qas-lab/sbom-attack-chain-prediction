"""
Data loader for cascaded vulnerability prediction.

This module loads attack chain datasets (external_chains, incidents.json) and
converts them into training data for CVE-CVE link prediction. The key insight
is that CVEs appearing together in documented attack chains are likely to be
exploited together.

Strategy for few-shot learning:
1. Positive pairs: CVEs that appear in the same attack chain
2. Negative pairs: CVEs from different chains or random CVE pairs
3. Features: CVE attributes (CVSS, CWE, temporal, textual embeddings)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    NUMPY_AVAILABLE = False


@dataclass
class AttackChain:
    """Represents a documented attack chain."""

    chain_id: str
    title: str
    cve_ids: list[str]
    cwes: list[str]
    description: str
    source: str  # 'external' or 'incidents'

    def get_cve_pairs(self) -> list[tuple[str, str]]:
        """Generate all pairwise CVE combinations in this chain.

        Note: Pairs are sorted alphabetically to ensure consistency with
        negative sampling in generate_training_pairs().
        """
        pairs = []
        for i, cve1 in enumerate(self.cve_ids):
            for cve2 in self.cve_ids[i + 1 :]:
                # Sort pair to ensure consistency
                pairs.append(tuple(sorted([cve1, cve2])))  # type: ignore[arg-type]
        return pairs


@dataclass
class CVEFeatures:
    """Feature vector for a single CVE."""

    cve_id: str
    cvss_score: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cwes: list[str]
    published_year: int
    exploited_in_wild: bool  # from CISA KEV
    num_references: int

    def to_vector(self) -> np.ndarray:
        """Convert to numerical feature vector.

        Returns:
            9-dim vector: [cvss, sev_onehot(4), year_norm, exploited, num_refs_norm, cwe_count]
        """
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required for feature vectors")

        # CVSS score
        cvss = float(self.cvss_score if self.cvss_score > 0 else 5.0)

        # Severity one-hot
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sev_onehot = [0.0] * 4
        sev_onehot[sev_map.get(self.severity.upper(), 2)] = 1.0

        # Year normalized (2015-2025 -> 0-1)
        year_norm = (float(self.published_year) - 2015.0) / 10.0
        year_norm = max(0.0, min(1.0, year_norm))

        # Exploited flag
        exploited = 1.0 if self.exploited_in_wild else 0.0

        # References (log-normalized)
        refs_norm = min(1.0, np.log1p(float(self.num_references)) / 5.0)

        # CWE count
        cwe_count = float(len(self.cwes)) / 5.0  # normalize by typical max

        features = np.array(
            [cvss / 10.0, *sev_onehot, year_norm, exploited, refs_norm, cwe_count],
            dtype=np.float32,
        )
        return features


class CascadeDataLoader:
    """Loads and processes attack chain data for link prediction."""

    def __init__(
        self,
        external_chains_path: Path | None = None,
        incidents_path: Path | None = None,
        cve_cache_dir: Path | None = None,
    ) -> None:
        self.external_chains_path = external_chains_path or Path("data/external_chains")
        self.incidents_path = incidents_path or Path("supply-chain-seeds/incidents.json")
        self.cve_cache_dir = cve_cache_dir or Path("data/cve_cache")

        self.chains: list[AttackChain] = []
        self.cve_features: dict[str, CVEFeatures] = {}
        self.all_cves: set[str] = set()

    def load_external_chains(self) -> int:
        """Load external_chains JSON data.

        Returns:
            Number of chains loaded.
        """
        if not self.external_chains_path.exists():
            return 0

        try:
            with open(self.external_chains_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return 0

        cases = data.get("cases", [])
        for case in cases:
            if not isinstance(case, dict):
                continue
            cve_ids = case.get("cve_ids", [])
            if len(cve_ids) < 2:  # Need at least 2 CVEs for a chain
                continue

            chain = AttackChain(
                chain_id=case.get("case_slug", ""),
                title=case.get("title", ""),
                cve_ids=[str(c).strip() for c in cve_ids],
                cwes=[],  # Not always present in external_chains
                description=case.get("chain_description", ""),
                source="external",
            )
            self.chains.append(chain)
            self.all_cves.update(chain.cve_ids)

        return len([c for c in self.chains if c.source == "external"])

    def load_incidents(self) -> int:
        """Load incidents.json data.

        Returns:
            Number of incidents loaded.
        """
        if not self.incidents_path.exists():
            return 0

        try:
            with open(self.incidents_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return 0

        if not isinstance(data, list):
            return 0

        for incident in data:
            if not isinstance(incident, dict):
                continue
            cve_ids = incident.get("cves", [])
            if len(cve_ids) < 2:
                continue

            chain = AttackChain(
                chain_id=incident.get("incident_id", ""),
                title=incident.get("title", ""),
                cve_ids=[str(c).strip() for c in cve_ids],
                cwes=incident.get("cwes", []),
                description=incident.get("summary", ""),
                source="incidents",
            )
            self.chains.append(chain)
            self.all_cves.update(chain.cve_ids)

        return len([c for c in self.chains if c.source == "incidents"])

    def load_cve_features(self) -> int:
        """Load CVE features from cached CVE JSON files.

        Returns:
            Number of CVEs with features loaded.
        """
        if not self.cve_cache_dir.exists():
            return 0

        for cve_id in self.all_cves:
            cve_file = self.cve_cache_dir / f"{cve_id}.json"
            if not cve_file.exists():
                # Create default features
                self.cve_features[cve_id] = CVEFeatures(
                    cve_id=cve_id,
                    cvss_score=5.0,
                    severity="MEDIUM",
                    cwes=[],
                    published_year=2020,
                    exploited_in_wild=False,
                    num_references=0,
                )
                continue

            try:
                with open(cve_file, encoding="utf-8") as f:
                    cve_data = json.load(f)

                # Extract features from NVD-style JSON
                cvss_score = self._extract_cvss(cve_data)
                severity = self._extract_severity(cve_data, cvss_score)
                cwes = self._extract_cwes(cve_data)
                year = self._extract_year(cve_data)
                refs = len(cve_data.get("references", []))

                self.cve_features[cve_id] = CVEFeatures(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    cwes=cwes,
                    published_year=year,
                    exploited_in_wild=False,  # TODO: check CISA KEV
                    num_references=refs,
                )
            except Exception:
                # Fallback to defaults
                self.cve_features[cve_id] = CVEFeatures(
                    cve_id=cve_id,
                    cvss_score=5.0,
                    severity="MEDIUM",
                    cwes=[],
                    published_year=2020,
                    exploited_in_wild=False,
                    num_references=0,
                )

        return len(self.cve_features)

    def _extract_cvss(self, cve_data: dict[str, Any]) -> float:
        """Extract CVSS score from CVE JSON."""
        # Try multiple paths
        metrics = cve_data.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                if score is not None:
                    return float(score)
        return 5.0  # Default

    def _extract_severity(self, cve_data: dict[str, Any], cvss_score: float) -> str:
        """Extract severity from CVE JSON or infer from CVSS."""
        metrics = cve_data.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics and metrics[version]:
                severity = metrics[version][0].get("cvssData", {}).get("baseSeverity")
                if severity:
                    return str(severity).upper()

        # Infer from score
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _extract_cwes(self, cve_data: dict[str, Any]) -> list[str]:
        """Extract CWE IDs from CVE JSON."""
        cwes = []
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            if isinstance(weakness, dict):
                descriptions = weakness.get("description", [])
                for desc in descriptions:
                    if isinstance(desc, dict) and desc.get("lang") == "en":
                        value = desc.get("value", "")
                        if value.startswith("CWE-"):
                            cwes.append(value)
        return cwes

    def _extract_year(self, cve_data: dict[str, Any]) -> int:
        """Extract publication year from CVE JSON."""
        published = cve_data.get("published", "")
        if isinstance(published, str) and len(published) >= 4:
            try:
                return int(published[:4])
            except Exception:
                pass
        return 2020  # Default

    def generate_training_pairs(
        self, negative_ratio: float = 2.0
    ) -> tuple[list[tuple[str, str]], list[int]]:
        """Generate positive and negative CVE pairs for training.

        Args:
            negative_ratio: Number of negative samples per positive sample.

        Returns:
            pairs: List of (cve1, cve2) tuples
            labels: List of labels (1 = positive chain, 0 = negative)
        """
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required for training data generation")

        positive_pairs: list[tuple[str, str]] = []
        for chain in self.chains:
            positive_pairs.extend(chain.get_cve_pairs())

        # Remove duplicates
        positive_pairs = list(set(positive_pairs))

        # Generate negative pairs
        cve_list = list(self.all_cves)
        num_negatives = int(len(positive_pairs) * negative_ratio)

        negative_pairs: list[tuple[str, str]] = []
        positive_set = set(positive_pairs)

        rng = np.random.RandomState(42)
        attempts = 0
        max_attempts = num_negatives * 10

        while len(negative_pairs) < num_negatives and attempts < max_attempts:
            idx1, idx2 = rng.choice(len(cve_list), size=2, replace=False)
            cve1, cve2 = cve_list[idx1], cve_list[idx2]
            pair = tuple(sorted([cve1, cve2]))  # type: ignore[assignment]

            if pair not in positive_set and pair not in negative_pairs:
                negative_pairs.append(pair)  # type: ignore[arg-type]

            attempts += 1

        # Combine and shuffle
        all_pairs = positive_pairs + negative_pairs
        labels = [1] * len(positive_pairs) + [0] * len(negative_pairs)

        # Shuffle
        indices = rng.permutation(len(all_pairs))
        all_pairs = [all_pairs[i] for i in indices]
        labels = [labels[i] for i in indices]

        return all_pairs, labels

    def get_pair_features(self, cve1: str, cve2: str) -> np.ndarray:
        """Get feature vector for a CVE pair.

        Concatenates individual CVE features + interaction features.

        Returns:
            Feature vector: [cve1_feat(9), cve2_feat(9), interaction(4)] = 22-dim
        """
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required for feature extraction")

        feat1 = (
            self.cve_features[cve1].to_vector()
            if cve1 in self.cve_features
            else np.zeros(9, dtype=np.float32)
        )
        feat2 = (
            self.cve_features[cve2].to_vector()
            if cve2 in self.cve_features
            else np.zeros(9, dtype=np.float32)
        )

        # Interaction features
        cvss_diff = abs(feat1[0] - feat2[0])
        cvss_product = feat1[0] * feat2[0]

        # Year proximity (normalized)
        year_diff = abs(feat1[5] - feat2[5])

        # Both exploited
        both_exploited = feat1[6] * feat2[6]

        interaction = np.array(
            [cvss_diff, cvss_product, year_diff, both_exploited], dtype=np.float32
        )

        return np.concatenate([feat1, feat2, interaction])

    def load_all(self) -> dict[str, Any]:
        """Convenience method to load all data sources.

        Returns:
            Summary statistics dictionary.
        """
        n_external = self.load_external_chains()
        n_incidents = self.load_incidents()
        n_cve_features = self.load_cve_features()

        pairs, labels = self.generate_training_pairs()
        n_positive = sum(labels)
        n_negative = len(labels) - n_positive

        return {
            "num_external_chains": n_external,
            "num_incidents": n_incidents,
            "num_unique_cves": len(self.all_cves),
            "num_cve_features_loaded": n_cve_features,
            "num_positive_pairs": n_positive,
            "num_negative_pairs": n_negative,
            "total_training_pairs": len(pairs),
        }


if __name__ == "__main__":
    # Quick test
    loader = CascadeDataLoader()
    stats = loader.load_all()

    print("=== Cascade Data Loader Statistics ===")
    for key, value in stats.items():
        print(f"{key}: {value}")

    # Show first chain
    if loader.chains:
        chain = loader.chains[0]
        print(f"\nExample chain: {chain.title}")
        print(f"CVEs: {', '.join(chain.cve_ids)}")
        print(f"Pairs: {len(chain.get_cve_pairs())}")
