import argparse
import json
import shutil
import time
from pathlib import Path

# --- Constants ---
# Heuristic: Minimum ratio of Python PURLs among components with PURLs
PYTHON_PURL_THRESHOLD = 0.5
# Report progress every N files processed
PROGRESS_INTERVAL = 5000


def is_python_cyclonedx_json(file_path: Path) -> tuple[bool, str]:
    """
    Checks if a file contains JSON CycloneDX SBOM data for Python by reading its content.

    Args:
        file_path (Path): The path to the file to check.

    Returns:
        Tuple[bool, str]: (True, "Success") if it matches,
                          (False, reason) otherwise.
    """
    try:
        # Attempt to read and parse as JSON
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            # Read the whole content first to handle potential BOM or leading whitespace
            content = f.read()
            # Basic check if it looks like JSON before full parsing
            if not content.strip().startswith(("{", "[")):
                return False, "Does not start with { or ["

            data = json.loads(content)  # Use loads on the read content

    except json.JSONDecodeError:
        return False, "Not valid JSON"
    except UnicodeDecodeError:
        return False, "Cannot decode as UTF-8"
    except OSError as e:
        return False, f"OS Error reading file: {e.strerror}"
    except Exception as e:
        # Catch other potential errors during file reading/parsing
        return False, f"Unexpected error reading/parsing: {type(e).__name__}"

    # Check for CycloneDX format
    if not (
        isinstance(data, dict)  # Ensure it's a JSON object
        and data.get("bomFormat") == "CycloneDX"
        and "specVersion" in data
    ):
        return False, "Not CycloneDX format"

    # Check for Python components (heuristic)
    components = data.get("components", [])
    if not isinstance(components, list):
        return False, "Invalid 'components' format"  # Should be a list

    # Skip SBOMs with no components list (or empty list)
    if not components:
        return False, "No components found"

    python_pkg_count = 0
    total_purl_components = 0
    for component in components:
        # Ensure component is a dictionary before accessing keys
        if not isinstance(component, dict):
            continue  # Skip malformed components

        purl = component.get("purl")
        if purl and isinstance(purl, str):  # Check if purl exists and is a string
            total_purl_components += 1
            if purl.startswith("pkg:pypi/") or purl.startswith("pkg:conda/"):
                python_pkg_count += 1

    if total_purl_components == 0:
        return False, "No PURLs found"  # Default to False if no PURLs

    python_ratio = python_pkg_count / total_purl_components
    if python_ratio < PYTHON_PURL_THRESHOLD:
        return (
            False,
            f"Python PURL ratio ({python_ratio:.2f}) below threshold ({PYTHON_PURL_THRESHOLD})",
        )

    # Check for dependencies with dependsOn
    dependencies = data.get("dependencies", [])
    if not isinstance(dependencies, list):
        return False, "Invalid 'dependencies' format"  # Should be a list

    has_depends_on_info = False
    for dep_entry in dependencies:
        if not isinstance(dep_entry, dict):
            continue  # Skip malformed entries
        # Check if 'dependsOn' key exists and is a non-empty list
        if (
            dep_entry.get("dependsOn")
            and isinstance(dep_entry["dependsOn"], list)
            and len(dep_entry["dependsOn"]) > 0
        ):
            has_depends_on_info = True
            break  # Found at least one entry with dependsOn

    if not has_depends_on_info:
        return False, "No dependencies with 'dependsOn' found"

    return True, "Success"


def main():
    parser = argparse.ArgumentParser(
        description="Filter Python CycloneDX JSON SBOMs by checking file content."
    )
    parser.add_argument(
        "input_dir", type=str, help="Root directory containing SBOM subfolders (0-e)."
    )
    parser.add_argument(
        "output_dir",
        type=str,
        help="Directory to save the filtered Python SBOMs.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of SBOMs to copy.")
    args = parser.parse_args()

    input_root = Path(args.input_dir)
    output_root = Path(args.output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    copied_count = 0
    processed_count = 0
    start_time = time.time()

    print(f"Scanning directories in {input_root}...")
    print(
        f"Filtering criteria: JSON, CycloneDX format, >= {PYTHON_PURL_THRESHOLD * 100}% Python PURLs"
    )
    print("This may take a significant amount of time...")

    all_files = list(input_root.rglob("*"))  # Get all files upfront
    total_files = len(all_files)
    print(f"Found {total_files} total items to check.")

    for item in all_files:
        processed_count += 1
        if processed_count % PROGRESS_INTERVAL == 0:
            elapsed_time = time.time() - start_time
            rate = processed_count / elapsed_time if elapsed_time > 0 else 0
            print(
                f"  Processed {processed_count}/{total_files} items... "
                f"({copied_count} copied) [{elapsed_time:.1f}s, {rate:.1f} items/s]"
            )

        if item.is_file():
            is_match, reason = is_python_cyclonedx_json(item)
            if is_match:
                print(f"  Found matching SBOM: {item.name} ({reason})")  # Verbose
                target_path = output_root / item.name
                if not target_path.exists():
                    try:
                        shutil.copy2(item, target_path)
                        copied_count += 1
                        print(f"    Copied to {target_path}")  # Verbose
                    except Exception as copy_err:
                        print(f"    Error copying {item.name}: {copy_err}")
                else:
                    print(f"    Skipped (already exists): {target_path}")  # Verbose

                if args.limit and copied_count >= args.limit:
                    print(f"\nReached limit of {args.limit} SBOMs.")
                    break  # Break loop
            else:
                # Optional: Log why a file didn't match
                print(f"  Skipping {item.name}: {reason}")
                pass

    end_time = time.time()
    total_time = end_time - start_time
    final_rate = processed_count / total_time if total_time > 0 else 0

    print("\nFiltering complete.")
    print(f"Processed {processed_count} total files.")
    print(f"Copied {copied_count} Python CycloneDX JSON SBOMs to {output_root}")
    print(f"Total time: {total_time:.2f} seconds ({final_rate:.2f} items/s)")


class SBOMFilterProcessor:
    """Processor for filtering and categorizing SBOM files."""

    def __init__(self, python_threshold: float = PYTHON_PURL_THRESHOLD):
        """Initialize filter processor.

        Args:
            python_threshold: Threshold for determining if an SBOM is Python-based
        """
        self.python_threshold = python_threshold

    def is_python_sbom(self, file_path: Path) -> tuple[bool, str]:
        """Check if a file contains a Python CycloneDX SBOM.

        Args:
            file_path: Path to SBOM file to check

        Returns:
            Tuple of (is_python_sbom, reason)
        """
        return is_python_cyclonedx_json(file_path)

    def filter_python_sboms(
        self, input_dir: Path, output_dir: Path, limit: int | None = None
    ) -> int:
        """Filter Python SBOMs from input directory to output directory.

        Args:
            input_dir: Directory containing SBOM files
            output_dir: Directory to save filtered SBOMs
            limit: Maximum number of SBOMs to copy

        Returns:
            Number of SBOMs copied
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        copied_count = 0
        processed_count = 0
        start_time = time.time()

        print(f"Scanning directories in {input_dir}...")
        print(
            f"Filtering criteria: JSON, CycloneDX format, >= {self.python_threshold * 100}% Python PURLs"
        )

        all_files = list(input_dir.rglob("*"))
        total_files = len(all_files)
        print(f"Found {total_files} total items to check.")

        for item in all_files:
            processed_count += 1
            if processed_count % PROGRESS_INTERVAL == 0:
                elapsed_time = time.time() - start_time
                rate = processed_count / elapsed_time if elapsed_time > 0 else 0
                print(
                    f"  Processed {processed_count}/{total_files} items... ({copied_count} copied) [{elapsed_time:.1f}s, {rate:.1f} items/s]"
                )

            if item.is_file():
                is_match, reason = self.is_python_sbom(item)
                if is_match:
                    target_path = output_dir / item.name
                    if not target_path.exists():
                        try:
                            shutil.copy2(item, target_path)
                            copied_count += 1
                        except Exception as copy_err:
                            print(f"Error copying {item.name}: {copy_err}")

                    if limit and copied_count >= limit:
                        break

        return copied_count


if __name__ == "__main__":
    main()
