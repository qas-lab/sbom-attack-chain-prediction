"""
Heterogeneous graph conversion utilities for enriched SBOMs.

This module converts a single enriched SBOM JSON file (CycloneDX schema with grype
augmentation) into a torch_geometric.data.HeteroData graph with node/edge types:

- Node types: "component", "cve", "cwe"
- Edge types:
  - ("component", "DEPENDS_ON", "component") — bidirectional edges added
  - ("component", "HAS_VULNERABILITY", "cve")
  - ("cve", "HAS_CWE", "cwe")

Features:
- component.x: 11-dim feature vector reused from processing.py
- cve.x: 8-dim vector [cvss_score, one-hot severity (6), recency_norm]
         severity order: CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE, UNKNOWN
- cwe.x: 1-dim degree (float) within this SBOM graph

Labels:
- data["component"].y: tensor[int64], 1 if component has any vulnerabilities else 0.

Metadata:
- data["component"].node_keys: list[str] of stable identifiers (purl -> bom-ref -> name@version)

The functions handle missing fields gracefully and return None on unrecoverable
parse errors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Optional dependencies with graceful fallbacks
try:
    import torch
    from torch import Tensor
    from torch_geometric.data import HeteroData

    TORCH_AVAILABLE = True
except Exception:  # pragma: no cover - import guard
    torch = None  # type: ignore[assignment]
    Tensor = None  # type: ignore[assignment]
    HeteroData = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

try:
    # Reuse the 11-dim component features from the homogeneous pipeline
    from .processing import (
        extract_license_features,
        extract_metadata_features,
        extract_vulnerability_features,
    )

    HAVE_COMPONENT_FEATURES = True
except Exception:
    HAVE_COMPONENT_FEATURES = False


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class _ParsedSBOM:
    components: list[dict[str, Any]]
    dependencies: list[dict[str, Any]]


def _safe_load_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _component_key(comp: dict[str, Any]) -> str:
    """Return stable component key: purl -> bom-ref -> name@version."""
    purl = comp.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    bom_ref = comp.get("bom-ref")
    if isinstance(bom_ref, str) and bom_ref:
        return bom_ref
    name = str(comp.get("name", "unknown"))
    version = str(comp.get("version", "unknown"))
    return f"{name}@{version}"


def _parse_dates(vuln: dict[str, Any]) -> float:
    """Return normalized recency in days (0..1) if any date is available, else 0.0.

    Tries fields commonly present in enriched SBOMs: 'published_date', 'modified_date',
    'published', 'modified', 'updated'. Normalization uses a 10-year window (3650 days).
    """
    date_fields = [
        "published_date",
        "modified_date",
        "published",
        "modified",
        "updated",
    ]

    def _parse(s: Any) -> datetime | None:
        if not isinstance(s, str) or not s:
            return None
        # Try fromisoformat first; fallback to trimming Z suffix
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            pass
        # Try common RFC3339/ISO forms
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                if dt.tzinfo is None:
                    # Assume UTC if tz not provided
                    return dt.replace(tzinfo=UTC)
                return dt
            except Exception:
                continue
        return None

    now = datetime.now(UTC)
    candidate: datetime | None = None
    for key in date_fields:
        dt = _parse(vuln.get(key))
        if dt is not None:
            candidate = dt if candidate is None else max(candidate, dt)
    if candidate is None:
        return 0.0
    days = max(0.0, (now - candidate).total_seconds() / 86400.0)
    norm = min(1.0, days / 3650.0)  # 10 years window
    return float(norm)


def _cve_feature(vuln: dict[str, Any]) -> list[float]:
    score = vuln.get("cvss_score")
    try:
        score_f = float(score) if score is not None else 0.0
    except Exception:
        score_f = 0.0

    sev = str(vuln.get("cvss_severity", "UNKNOWN")).upper()
    one_hot = [0.0] * len(SEVERITIES)
    one_hot[SEVERITY_INDEX.get(sev, SEVERITY_INDEX["UNKNOWN"])] = 1.0

    recency = _parse_dates(vuln)
    # Final order: [score] + 6 severity + [recency]
    return [score_f, *one_hot, recency]


def _extract_components(sbom: dict[str, Any]) -> _ParsedSBOM | None:
    comps = sbom.get("components")
    deps = sbom.get("dependencies")
    if not isinstance(comps, list):
        return None
    if deps is None:
        deps = []
    if not isinstance(deps, list):
        deps = []
    return _ParsedSBOM(components=comps, dependencies=deps)


def sbom_to_hetero_data(sbom_path: Path) -> HeteroData | None:
    """Convert an enriched SBOM JSON to HeteroData.

    Args:
        sbom_path: Path to enriched SBOM JSON (CycloneDX with grype fields).

    Returns:
        HeteroData on success, or None on unrecoverable parse errors.
    """
    if not TORCH_AVAILABLE:
        raise ImportError(
            "Missing torch/torch-geometric. Install with: pip install torch torch-geometric"
        )
    if not HAVE_COMPONENT_FEATURES:
        raise ImportError(
            "Component feature helpers not available. Ensure sbom_toolkit.ml.processing imports."
        )

    raw = _safe_load_json(sbom_path)
    if raw is None:
        return None

    parsed = _extract_components(raw)
    if parsed is None or not parsed.components:
        return None

    # Build component nodes
    comp_keys: list[str] = []
    comp_map: dict[str, int] = {}
    comp_x: list[list[float]] = []
    comp_y: list[int] = []

    # Track direct deps (dependency roots) for metadata features
    direct_refs: set[str] = set()
    for dep in parsed.dependencies:
        ref = dep.get("ref")
        if isinstance(ref, str) and ref:
            direct_refs.add(ref)

    for comp in parsed.components:
        key = _component_key(comp)
        if key in comp_map:
            # Skip duplicate keys, favor first occurrence
            continue
        idx = len(comp_keys)
        comp_keys.append(key)
        comp_map[key] = idx

        is_direct = key in direct_refs
        vuln_feat = extract_vulnerability_features(comp)
        meta_feat = extract_metadata_features(comp, is_direct)
        license_feat = extract_license_features(comp)
        features = [float(v) for v in (list(vuln_feat) + list(meta_feat) + list(license_feat))]
        comp_x.append(features)
        comp_y.append(1 if comp.get("vulnerabilities") else 0)

    # Component dependency edges (bidirectional)
    comp_edges: list[tuple[int, int]] = []
    for dep in parsed.dependencies:
        src_key = dep.get("ref")
        if not isinstance(src_key, str) or src_key not in comp_map:
            continue
        targets = dep.get("dependsOn", [])
        if not isinstance(targets, list):
            continue
        for tgt_key in targets:
            if isinstance(tgt_key, str) and tgt_key in comp_map:
                s = comp_map[src_key]
                t = comp_map[tgt_key]
                comp_edges.append((s, t))
                comp_edges.append((t, s))  # add reverse

    # CVE nodes and edges
    cve_map: dict[str, int] = {}
    cve_x: list[list[float]] = []
    has_vuln_edges: list[tuple[int, int]] = []  # component -> cve

    # CWE nodes and edges
    cwe_map: dict[str, int] = {}
    cwe_x: list[list[float]] = []  # placeholder; will fill after degree calc
    cve_cwe_edges: list[tuple[int, int]] = []  # cve -> cwe
    cwe_degree: dict[int, int] = {}

    for comp in parsed.components:
        c_idx = comp_map.get(_component_key(comp))
        if c_idx is None:
            continue
        vulns = comp.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cve_id_raw = v.get("cve_id") or v.get("id") or v.get("source_id")
            cve_id = str(cve_id_raw) if cve_id_raw is not None else None
            if not cve_id:
                continue
            if cve_id not in cve_map:
                cve_map[cve_id] = len(cve_map)
                cve_x.append(_cve_feature(v))
            has_vuln_edges.append((c_idx, cve_map[cve_id]))

            # CWEs for this CVE
            cwes = v.get("cwe_ids") or []
            if isinstance(cwes, list):
                for cwe in cwes:
                    cwe_s = str(cwe)
                    if not cwe_s:
                        continue
                    if cwe_s not in cwe_map:
                        cwe_map[cwe_s] = len(cwe_map)
                    cwe_idx = cwe_map[cwe_s]
                    cve_idx = cve_map[cve_id]
                    cve_cwe_edges.append((cve_idx, cwe_idx))
                    cwe_degree[cwe_idx] = cwe_degree.get(cwe_idx, 0) + 1

    # CWE feature: 1-dim degree (float). If no CWEs, keep empty.
    if cwe_map:
        max_deg = max(cwe_degree.get(i, 0) for i in range(len(cwe_map))) or 1
        for i in range(len(cwe_map)):
            deg = float(cwe_degree.get(i, 0))
            # Raw degree; users can normalize later if desired
            cwe_x.append([deg / float(max_deg)])

    # Build HeteroData
    data = HeteroData()

    # Components
    comp_x_tensor = torch.tensor(comp_x, dtype=torch.float32)
    comp_y_tensor = torch.tensor(comp_y, dtype=torch.long)
    data["component"].x = comp_x_tensor
    data["component"].y = comp_y_tensor
    data["component"].node_keys = comp_keys  # metadata list[str]

    # Component edges
    if comp_edges:
        edge_index = torch.tensor(comp_edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    data[("component", "DEPENDS_ON", "component")].edge_index = edge_index

    # CVE nodes
    if cve_map:
        data["cve"].x = torch.tensor(cve_x, dtype=torch.float32)
    else:
        data["cve"].x = torch.empty((0, 8), dtype=torch.float32)

    # HAS_VULNERABILITY edges
    if has_vuln_edges:
        data[("component", "HAS_VULNERABILITY", "cve")].edge_index = (
            torch.tensor(has_vuln_edges, dtype=torch.long).t().contiguous()
        )
    else:
        data[("component", "HAS_VULNERABILITY", "cve")].edge_index = torch.empty(
            (2, 0), dtype=torch.long
        )

    # CWE nodes
    if cwe_map:
        data["cwe"].x = torch.tensor(cwe_x, dtype=torch.float32)
    else:
        data["cwe"].x = torch.empty((0, 1), dtype=torch.float32)

    # HAS_CWE edges
    if cve_cwe_edges:
        data[("cve", "HAS_CWE", "cwe")].edge_index = (
            torch.tensor(cve_cwe_edges, dtype=torch.long).t().contiguous()
        )
    else:
        data[("cve", "HAS_CWE", "cwe")].edge_index = torch.empty((2, 0), dtype=torch.long)

    # Attach source path for traceability
    data.sbom_path = str(sbom_path)

    return data


def load_enriched_sboms(scan_dir: Path) -> list[HeteroData]:
    """Load all enriched SBOM JSONs in a directory into HeteroData graphs.

    Args:
        scan_dir: Directory containing grype-enriched CycloneDX SBOM JSON files.

    Returns:
        List of HeteroData objects. Files that fail to parse are skipped.
    """
    graphs: list[HeteroData] = []
    for path in sorted(scan_dir.glob("*.json")):
        try:
            g = sbom_to_hetero_data(path)
        except Exception:
            g = None
        if g is not None:
            graphs.append(g)
    return graphs
