"""
Evaluate HGAT predictions against a curated set of multi-CVE chains.

Two modes:
1) Coverage: measure how many SBOMs/components intersect the chain CVE set.
2) Overlap/top-k: on SBOMs with chain CVEs present, run HGAT and compute whether
   top-k predicted components include those with chain CVEs (top-k recall).

CLI:
  python -m sbom_toolkit.ml.hgat_eval_external \
    --chains data/external_chains \
    --sboms-dir outputs/scans \
    --model outputs/models/hgat_best.pt \
    --out-dir outputs/evaluations/gold/external_chains_eval \
    --topk 10 \
    --limit 200 \
    --cpu
"""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import torch

    TORCH_AVAILABLE = True
except Exception:
    torch = None  # type: ignore[assignment]
    TORCH_AVAILABLE = False

from .hgat_predict import predict_sbom_hgat


@dataclass
class ChainCase:
    case_slug: str
    title: str
    cve_ids: list[str]


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _component_key(comp: Mapping[str, Any]) -> str:
    purl = comp.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    bom_ref = comp.get("bom-ref")
    if isinstance(bom_ref, str) and bom_ref:
        return bom_ref
    name = str(comp.get("name", "unknown"))
    version = str(comp.get("version", "unknown"))
    return f"{name}@{version}"


def load_external_chains(chains_path: Path) -> tuple[list[ChainCase], set[str]]:
    raw = _read_json(chains_path)
    if raw is None:
        raise ValueError(f"Failed to read chains JSON at {chains_path}")
    cases_raw = raw.get("cases", [])
    if not isinstance(cases_raw, list):
        raise ValueError("Invalid chains JSON: 'cases' must be a list")
    cases: list[ChainCase] = []
    all_cves: set[str] = set()
    for c in cases_raw:
        if not isinstance(c, dict):
            continue
        cves_raw = c.get("cve_ids", [])
        if not isinstance(cves_raw, list) or len(cves_raw) < 2:
            continue
        cve_ids = [str(x).strip() for x in cves_raw if str(x).strip()]
        case_slug = str(c.get("case_slug", ""))
        title = str(c.get("title", case_slug))
        if not case_slug or not cve_ids:
            continue
        cases.append(ChainCase(case_slug=case_slug, title=title, cve_ids=cve_ids))
        for cid in cve_ids:
            all_cves.add(cid)
    return cases, all_cves


def load_sbom_components_with_cves(
    sbom_path: Path,
) -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    sbom = _read_json(sbom_path)
    if sbom is None:
        raise ValueError(f"Could not parse SBOM JSON at {sbom_path}")
    comps = sbom.get("components")
    if not isinstance(comps, list):
        raise ValueError("SBOM missing 'components' array")
    comp_to_cves: dict[str, set[str]] = {}
    comp_to_all_cves: dict[str, list[str]] = {}
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        key = _component_key(comp)
        vulns = comp.get("vulnerabilities", [])
        cves_for_comp: set[str] = set()
        all_cves_for_comp: list[str] = []
        if isinstance(vulns, list):
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                cve_id_raw = v.get("cve_id") or v.get("id") or v.get("source_id")
                if isinstance(cve_id_raw, str) and cve_id_raw:
                    cves_for_comp.add(cve_id_raw)
                    all_cves_for_comp.append(cve_id_raw)
        comp_to_cves[key] = cves_for_comp
        comp_to_all_cves[key] = all_cves_for_comp
    return comp_to_cves, comp_to_all_cves


def _topk(items: list[tuple[str, float]], k: int) -> list[tuple[str, float]]:
    k = max(0, int(k))
    if k == 0:
        return []
    return items[:k]


def evaluate_overlap_subset(
    sboms: list[Path],
    model_path: Path,
    chain_cve_set: set[str],
    *,
    cpu: bool,
    topk: int,
    out_dir: Path,
) -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    any_hit = 0
    total_chain_components = 0
    total_topk_hits = 0

    for sbom_path in sboms:
        predictions = predict_sbom_hgat(sbom_path, model_path, cpu=cpu)
        comp_to_cves, _ = load_sbom_components_with_cves(sbom_path)

        chain_components: set[str] = set()
        for comp_key, cves in comp_to_cves.items():
            if any((c in chain_cve_set) for c in cves):
                chain_components.add(comp_key)

        scored: list[tuple[str, float]] = []
        for comp_key, pred in predictions.items():
            conf = pred.get("confidence")
            try:
                conf_f = float(conf) if conf is not None else 0.0
            except Exception:
                conf_f = 0.0
            scored.append((comp_key, conf_f))
        scored.sort(key=lambda x: x[1], reverse=True)
        top = {k for k, _ in _topk(scored, topk)}

        hits = len(chain_components.intersection(top))
        total_topk_hits += int(hits)
        total_chain_components += int(len(chain_components))
        any_hit += int(hits > 0)

        report = {
            "sbom_path": str(sbom_path),
            "num_components": int(len(comp_to_cves)),
            "num_chain_components": int(len(chain_components)),
            "topk": int(topk),
            "topk_hits": int(hits),
            "any_hit": bool(hits > 0),
        }
        reports.append(report)

        # Write per-SBOM CSV with top-k list for quick inspection
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            csv_path = out_dir / f"topk_{sbom_path.stem}.csv"
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["rank", "component", "confidence", "is_chain_component"])
                for i, (comp_key, conf) in enumerate(_topk(scored, topk), start=1):
                    writer.writerow([i, comp_key, f"{conf:.6f}", comp_key in chain_components])
        except Exception:
            # Non-fatal; continue
            pass

    denom = len(reports) if reports else 0
    coverage_any_hit = (float(any_hit) / float(denom)) if denom > 0 else None
    micro_topk_recall = (
        float(total_topk_hits) / float(total_chain_components)
        if total_chain_components > 0
        else None
    )

    return {
        "num_sboms": denom,
        "any_hit_rate": coverage_any_hit,
        "micro_topk_recall": micro_topk_recall,
        "reports": reports,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Chain-overlap and top-k evaluation for HGAT")
    parser.add_argument(
        "--chains",
        type=str,
        default="data/external_chains",
        help="Path to external chains JSON file",
    )
    parser.add_argument(
        "--sboms-dir", type=str, default="outputs/scans", help="Directory of enriched SBOM JSONs"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="outputs/models/hgat_best.pt",
        help="Path to trained HGAT model file",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="outputs/evaluations/gold/external_chains_eval",
        help="Output directory",
    )
    parser.add_argument(
        "--limit", type=int, default=200, help="Max SBOMs to examine (None for all)"
    )
    parser.add_argument(
        "--topk", type=int, default=10, help="Top-k components to check for chain coverage"
    )
    parser.add_argument("--cpu", action="store_true", help="Force CPU for prediction")
    args = parser.parse_args()

    chains_path = Path(args.chains)
    sboms_dir = Path(args.sboms_dir)
    model_path = Path(args.model)
    out_dir = Path(args.out_dir)

    if not chains_path.exists():
        raise FileNotFoundError(f"Chains file not found at {chains_path}")
    if not sboms_dir.exists():
        raise FileNotFoundError(f"SBOMs directory not found at {sboms_dir}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found at {model_path}")

    chain_cases, chain_cve_set = load_external_chains(chains_path)

    # Coverage pass over SBOMs to identify overlap subset
    candidates: list[Path] = []
    total_files = 0
    for sbom_path in sorted(sboms_dir.glob("*.json")):
        total_files += 1
        try:
            comp_to_cves, _ = load_sbom_components_with_cves(sbom_path)
        except Exception:
            continue
        overlapped = False
        for cves in comp_to_cves.values():
            if any((c in chain_cve_set) for c in cves):
                overlapped = True
                break
        if overlapped:
            candidates.append(sbom_path)
            if args.limit > 0 and len(candidates) >= args.limit:
                break

    coverage_summary = {
        "scanned": total_files,
        "overlap_candidates": len(candidates),
        "coverage_ratio": (float(len(candidates)) / float(total_files))
        if total_files > 0
        else None,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "coverage.json", "w", encoding="utf-8") as f:
        json.dump(coverage_summary, f, indent=2)

    # If we have overlap, run top-k evaluation on that subset
    overlap_summary: dict[str, Any]
    if candidates:
        overlap_summary = evaluate_overlap_subset(
            candidates,
            model_path,
            chain_cve_set,
            cpu=bool(args.cpu),
            topk=int(args.topk),
            out_dir=out_dir,
        )
    else:
        overlap_summary = {
            "num_sboms": 0,
            "any_hit_rate": None,
            "micro_topk_recall": None,
            "reports": [],
        }

    final = {
        "coverage": coverage_summary,
        "overlap_eval": overlap_summary,
    }
    with open(out_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2)


if __name__ == "__main__":
    main()
