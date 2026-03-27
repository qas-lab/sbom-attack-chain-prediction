#!/usr/bin/env python3
"""Download dataset for the SBOM attack chain prediction project.

Downloads and extracts dataset archives from Harvard Dataverse or GitHub Releases.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# Configuration
GITHUB_REPO = "qas-lab/sbom-attack-chain-prediction"
RELEASE_TAG = "v1.0"
GITHUB_RELEASE_BASE = f"https://github.com/{GITHUB_REPO}/releases/download/{RELEASE_TAG}"

DATAVERSE_DOI = "doi:10.7910/DVN/A6CZRB"
DATAVERSE_BASE = "https://dataverse.harvard.edu"
DATAVERSE_API = f"{DATAVERSE_BASE}/api"

# Dataset files available for download
DATASET_FILES: dict[str, dict[str, str]] = {
    "sboms.tar.gz": {
        "sha256": "5988e279e9a1db844ace1be7dba75b6cacc8f4a49195972c22a8dc94354f5130",
        "description": "Software Bills of Materials",
    },
    "scans.tar.gz": {
        "sha256": "6de91cbe682c895a8a914ea890eeb1f3bed712dbbaf0c581bec45e0bc97f44d2",
        "description": "Vulnerability scan results",
    },
    "models.tar.gz": {
        "sha256": "42a8ecc5acb7c8dd165c10043813efdc19b31e65b663010e902ebad04df2bd1d",
        "description": "Trained model checkpoints",
    },
    "evaluations.tar.gz": {
        "sha256": "1682994cea5deff200431ca9fbdd6ccdca62e040674f7f3715bd484fb5914b9f",
        "description": "Evaluation results",
    },
    "reference_data.tar.gz": {
        "sha256": "4d80a7243d4c6ef27dc189ef34b33d943675349a39191969b9e5024bd857e847",
        "description": "Reference data and caches",
    },
}

PROJECT_ROOT = Path(__file__).parent.parent


def compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with filepath.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def download_file(url: str, dest: Path, description: str) -> bool:
    """Download a file with progress indication."""
    print(f"  Downloading {description}...")

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "sbom-attack-chain-prediction/1.0"}
        )
        with urllib.request.urlopen(req) as resp, dest.open("wb") as out:
            while chunk := resp.read(8192):
                out.write(chunk)
        return True
    except urllib.error.URLError as e:
        print(f"  Error downloading: {e}")
        return False


def verify_checksum(filepath: Path, expected_sha256: str) -> bool:
    """Verify file checksum."""
    if not expected_sha256:
        print("  Warning: No checksum available, skipping verification")
        return True

    actual = compute_sha256(filepath)
    if actual != expected_sha256:
        print("  Checksum mismatch!")
        print(f"    Expected: {expected_sha256}")
        print(f"    Got:      {actual}")
        return False
    print("  Checksum verified")
    return True


def extract_archive(archive_path: Path, dest_dir: Path) -> bool:
    """Extract tar.gz archive."""
    print(f"  Extracting to {dest_dir}...")
    try:
        subprocess.run(
            ["tar", "-xzf", str(archive_path), "-C", str(dest_dir)],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error extracting: {e.stderr.decode()}")
        return False


def _urlopen(url: str) -> bytes:
    """Open a URL with a User-Agent header (required by Harvard Dataverse)."""
    req = urllib.request.Request(url, headers={"User-Agent": "sbom-attack-chain-prediction/1.0"})
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def resolve_dataverse_files() -> dict[str, int]:
    """Fetch the Dataverse dataset metadata and return a filename-to-fileId map."""
    url = f"{DATAVERSE_API}/datasets/:persistentId?persistentId={DATAVERSE_DOI}"
    try:
        data = json.loads(_urlopen(url))
    except urllib.error.URLError as e:
        print(f"  Error fetching Dataverse metadata: {e}")
        return {}

    file_map: dict[str, int] = {}
    for entry in data.get("data", {}).get("latestVersion", {}).get("files", []):
        df = entry.get("dataFile", {})
        label = df.get("filename", "")
        file_id = df.get("id")
        if label and file_id:
            file_map[label] = file_id
    return file_map


def download_from_dataverse(
    files: list[str] | None = None,
    extract: bool = True,
    verify: bool = True,
) -> int:
    """Download dataset files from Harvard Dataverse.

    Args:
        files: List of specific files to download, or None for all
        extract: Whether to extract archives after download
        verify: Whether to verify checksums

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    files_to_download = files or list(DATASET_FILES.keys())

    print("SBOM Attack Chain Prediction — Dataset Downloader")
    print(f"Source: Harvard Dataverse ({DATAVERSE_DOI})")
    print("=" * 50)

    print("\nFetching dataset metadata from Dataverse...")
    file_map = resolve_dataverse_files()
    if not file_map:
        print("Failed to resolve Dataverse file IDs. Falling back to GitHub Releases.")
        return download_from_github(files=files, extract=extract, verify=verify)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        success_count = 0

        for filename in files_to_download:
            if filename not in DATASET_FILES:
                print(f"\nUnknown file: {filename}")
                continue

            info = DATASET_FILES[filename]
            expected_sha256 = str(info.get("sha256", ""))
            description = str(info.get("description", filename))

            print(f"\n{filename}")
            print("-" * len(filename))

            file_id = file_map.get(filename)
            if file_id is None:
                print(f"  File not found on Dataverse, skipping")
                continue

            url = f"{DATAVERSE_API}/access/datafile/{file_id}"
            download_path = tmp_path / filename

            if not download_file(url, download_path, description):
                continue

            if verify and not verify_checksum(download_path, expected_sha256):
                continue

            if extract:
                if not extract_archive(download_path, PROJECT_ROOT):
                    continue

            success_count += 1

    print("\n" + "=" * 50)
    print(f"Downloaded {success_count}/{len(files_to_download)} files")

    return 0 if success_count == len(files_to_download) else 1


def download_from_github(
    files: list[str] | None = None,
    extract: bool = True,
    verify: bool = True,
) -> int:
    """Download dataset files from GitHub Releases.

    Args:
        files: List of specific files to download, or None for all
        extract: Whether to extract archives after download
        verify: Whether to verify checksums

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    files_to_download = files or list(DATASET_FILES.keys())

    print("SBOM Attack Chain Prediction — Dataset Downloader")
    print(f"Source: GitHub Releases ({GITHUB_REPO} {RELEASE_TAG})")
    print("=" * 50)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        success_count = 0

        for filename in files_to_download:
            if filename not in DATASET_FILES:
                print(f"\nUnknown file: {filename}")
                continue

            info = DATASET_FILES[filename]
            expected_sha256 = str(info.get("sha256", ""))
            description = str(info.get("description", filename))

            print(f"\n{filename}")
            print("-" * len(filename))

            # Download from GitHub Releases
            url = f"{GITHUB_RELEASE_BASE}/{filename}"
            download_path = tmp_path / filename

            if not download_file(url, download_path, description):
                continue

            # Verify
            if verify and not verify_checksum(download_path, expected_sha256):
                continue

            # Extract
            if extract:
                if not extract_archive(download_path, PROJECT_ROOT):
                    continue

            success_count += 1

    print("\n" + "=" * 50)
    print(f"Downloaded {success_count}/{len(files_to_download)} files")

    return 0 if success_count == len(files_to_download) else 1


def download_from_local(archive_dir: Path, extract: bool = True) -> int:
    """Extract archives from a local directory (for offline use).

    Args:
        archive_dir: Directory containing the downloaded .tar.gz files
        extract: Whether to extract archives

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    print(f"Extracting from local directory: {archive_dir}")
    print("=" * 50)

    success_count = 0
    archives = list(archive_dir.glob("*.tar.gz"))

    if not archives:
        print(f"No .tar.gz files found in {archive_dir}")
        return 1

    for archive_path in archives:
        print(f"\n{archive_path.name}")
        print("-" * len(archive_path.name))

        if extract:
            if extract_archive(archive_path, PROJECT_ROOT):
                success_count += 1
        else:
            success_count += 1

    print("\n" + "=" * 50)
    print(f"Processed {success_count}/{len(archives)} archives")

    return 0 if success_count == len(archives) else 1


def main() -> int:
    """Run the download script."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Download dataset from Harvard Dataverse or GitHub Releases"
    )
    parser.add_argument(
        "--files",
        nargs="+",
        choices=list(DATASET_FILES.keys()),
        help="Specific files to download (default: all)",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Download only, don't extract archives",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip checksum verification",
    )
    parser.add_argument(
        "--source",
        choices=["dataverse", "github"],
        default="dataverse",
        help="Download source (default: dataverse)",
    )
    parser.add_argument(
        "--local",
        type=Path,
        metavar="DIR",
        help="Extract from local directory instead of downloading",
    )

    args = parser.parse_args()

    if args.local:
        return download_from_local(args.local, extract=not args.no_extract)

    download_fn = download_from_dataverse if args.source == "dataverse" else download_from_github
    return download_fn(
        files=args.files,
        extract=not args.no_extract,
        verify=not args.no_verify,
    )


if __name__ == "__main__":
    sys.exit(main())
