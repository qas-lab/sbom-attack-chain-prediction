#!/usr/bin/env python3
"""Package data for dataset distribution.

Creates compressed archives of the SBOM dataset with checksums and manifest.
"""

import hashlib
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# Configuration
RELEASE_DIR = Path("data-release")
PROJECT_ROOT = Path(__file__).parent.parent

# Data directories to package
DATA_PACKAGES: dict[str, dict[str, str | list[str]]] = {
    "sboms": {
        "description": "Software Bills of Materials (CycloneDX JSON format)",
        "paths": ["data/filtered_sboms", "data/scanned_sboms"],
    },
    "scans": {
        "description": "Enriched vulnerability scan results",
        "paths": ["outputs/scans"],
    },
    "models": {
        "description": "Trained GNN model checkpoints",
        "paths": ["outputs/models"],
    },
    "evaluations": {
        "description": "Model evaluation results and metrics",
        "paths": ["outputs/evaluations"],
    },
    "reference_data": {
        "description": "Attack chain data and vulnerability caches",
        "paths": [
            "data/external_chains",
            "data/ac_data",
            "data/cve_cache",
            "data/cwe_cache",
            "data/capec_cache",
        ],
    },
}


def compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def get_dir_size(path: Path) -> int:
    """Get total size of directory in bytes."""
    total = 0
    if path.is_file():
        return path.stat().st_size
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


def format_size(size_bytes: int) -> str:
    """Format bytes as human-readable size."""
    size: int | float = size_bytes
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def count_files(path: Path) -> int:
    """Count number of files in directory."""
    if path.is_file():
        return 1
    return sum(1 for item in path.rglob("*") if item.is_file())


def create_archive(name: str, paths: list[str], release_dir: Path) -> Path | None:
    """Create a tar.gz archive from specified paths."""
    archive_path = release_dir / f"{name}.tar.gz"

    # Filter to existing paths
    existing_paths = []
    for p in paths:
        full_path = PROJECT_ROOT / p
        if full_path.exists():
            existing_paths.append(p)
        else:
            print(f"  Warning: {p} does not exist, skipping")

    if not existing_paths:
        print(f"  No valid paths for {name}, skipping archive")
        return None

    # Create archive using tar
    cmd = ["tar", "-czf", str(archive_path), "-C", str(PROJECT_ROOT), *existing_paths]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return archive_path
    except subprocess.CalledProcessError as e:
        print(f"  Error creating archive: {e.stderr.decode()}")
        return None


def generate_manifest(release_dir: Path, archives: dict[str, Path]) -> None:
    """Generate MANIFEST.md with dataset documentation."""
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    content = f"""# SBOM Attack Chain Prediction — Dataset Manifest

Generated: {timestamp}

## Overview

This dataset accompanies the SBOM attack chain prediction research project,
which applies graph neural networks to software supply chain security analysis.
The dataset contains Software Bills of Materials (SBOMs), vulnerability scan
results, trained model checkpoints, and evaluation metrics.

## Archives

| Archive | Description | Size | SHA256 |
|---------|-------------|------|--------|
"""

    checksums: list[tuple[str, str]] = []

    for name, archive_path in sorted(archives.items()):
        if archive_path and archive_path.exists():
            size = format_size(archive_path.stat().st_size)
            sha256 = compute_sha256(archive_path)
            checksums.append((archive_path.name, sha256))
            desc = DATA_PACKAGES[name]["description"]
            content += f"| `{archive_path.name}` | {desc} | {size} | `{sha256[:16]}...` |\n"

    content += """
## Archive Contents

"""

    for name, config in DATA_PACKAGES.items():
        paths = config["paths"]
        content += f"### {name}.tar.gz\n\n"
        content += f"{config['description']}\n\n"
        content += "**Included paths:**\n"
        for p in paths:
            full_path = PROJECT_ROOT / p
            if full_path.exists():
                file_count = count_files(full_path)
                size = format_size(get_dir_size(full_path))
                content += f"- `{p}/` ({file_count:,} files, {size})\n"
            else:
                content += f"- `{p}/` (not found)\n"
        content += "\n"

    content += """## Data Formats

### SBOM Files
- Format: CycloneDX JSON (spec version 1.5)
- Naming: `{commit_hash}` for filtered, `{commit_hash}_enriched` for scanned
- Contains: Components, dependencies, vulnerabilities (CVEs), and metadata

### Scan Results
- Format: JSON
- Contains: Enriched vulnerability data with CVSS scores, CWE mappings, and severity

### Model Checkpoints
- Format: PyTorch (.pt)
- Contains: Model state dict, training configuration, and input dimensions

### Evaluation Results
- Format: JSON and CSV
- Contains: Predictions, ground truth labels, and performance metrics

## Usage

1. Extract archives to the project root:
   ```bash
   for f in *.tar.gz; do tar -xzf "$f" -C /path/to/sbom-toolkit; done
   ```

2. Or use the download script:
   ```bash
   uv run python scripts/download_data.py
   ```

## Citation

If you use this dataset, please cite:

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

This dataset is released under the MIT License.
"""

    manifest_path = release_dir / "MANIFEST.md"
    manifest_path.write_text(content)
    print(f"Created {manifest_path}")

    # Write checksums file
    checksums_path = release_dir / "checksums.sha256"
    checksums_content = "\n".join(f"{sha256}  {filename}" for filename, sha256 in checksums)
    checksums_path.write_text(checksums_content + "\n")
    print(f"Created {checksums_path}")


def main() -> int:
    """Main entry point."""
    print("SBOM Attack Chain Prediction — Data Packager")
    print("=" * 50)

    # Create release directory
    release_dir = PROJECT_ROOT / RELEASE_DIR
    release_dir.mkdir(exist_ok=True)
    print(f"\nOutput directory: {release_dir}")

    # Create archives
    archives: dict[str, Path] = {}
    print("\nCreating archives...")

    for name, config in DATA_PACKAGES.items():
        print(f"\n  Packaging {name}...")
        paths = config["paths"]
        if not isinstance(paths, list):
            paths = [paths]
        archive_path = create_archive(name, paths, release_dir)
        if archive_path:
            size = format_size(archive_path.stat().st_size)
            print(f"  Created {archive_path.name} ({size})")
            archives[name] = archive_path

    # Generate manifest and checksums
    print("\nGenerating manifest and checksums...")
    generate_manifest(release_dir, archives)

    # Summary
    print("\n" + "=" * 50)
    print("Summary:")
    total_size = sum(p.stat().st_size for p in archives.values() if p and p.exists())
    print(f"  Total archives: {len(archives)}")
    print(f"  Total size: {format_size(total_size)}")
    print(f"\nFiles ready for upload in: {release_dir}/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
