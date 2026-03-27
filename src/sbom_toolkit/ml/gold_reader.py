"""
Reader utilities for labeled gold candidate pairs.

Scans outputs/evaluations/gold/*/candidate_pairs.json and returns a list of
(source_id, target_id, label) where label is 1 for "chain" and 0 for "no_chain".

This is kept intentionally minimal as a foundation for later link prediction work.
"""

from __future__ import annotations

import json
from pathlib import Path


def load_labeled_pairs(gold_root: Path) -> list[tuple[str, str, int]]:
    """Load labeled component pairs from gold evaluation packs.

    Args:
        gold_root: Path to outputs/evaluations/gold directory.

    Returns:
        List of (source_identifier, target_identifier, label) where label is 1 for
        "chain" and 0 for "no_chain". Entries without an explicit label are ignored.
    """
    results: list[tuple[str, str, int]] = []
    if not gold_root.exists():
        return results

    for pack_dir in sorted(gold_root.glob("*/")):
        cand = pack_dir / "candidate_pairs.json"
        if not cand.exists():
            continue
        try:
            with open(cand, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        pairs = data.get("candidate_pairs", [])
        if not isinstance(pairs, list):
            continue
        for p in pairs:
            if not isinstance(p, dict):
                continue
            label_raw = p.get("label")
            if label_raw not in ("chain", "no_chain"):
                continue
            label = 1 if label_raw == "chain" else 0
            src = p.get("source")
            tgt = p.get("target")
            if isinstance(src, str) and isinstance(tgt, str):
                results.append((src, tgt, label))

    return results
