"""
Enhanced SBOM vulnerability scanning using grype.

This module provides functionality to enrich a single SBOM file with vulnerability data
from grype, which internally uses OSV and other vulnerability databases.
"""

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console

# Import project's caching and output management systems
from ...shared.caching import CacheManager
from ...shared.cvss_utils import CVSSVersionHandler
from ...shared.exceptions import VulnerabilityScanError, create_error_context
from ...shared.output import OutputManager

console = Console()

# Global cache manager for vulnerability details
_cache_manager: CacheManager | None = None


def _get_cache_manager() -> CacheManager:
    """Get or create the vulnerability cache manager."""
    global _cache_manager
    if _cache_manager is None:
        # Use the project's output manager to get the cache directory
        output_manager = OutputManager()
        cache_dir = output_manager.dirs["cache"] / "vulnerabilities"
        _cache_manager = CacheManager(cache_dir)

    # At this point, _cache_manager is guaranteed to be a CacheManager
    assert _cache_manager is not None
    return _cache_manager


def clear_vulnerability_cache() -> None:
    """Clear the vulnerability details cache. Useful for testing or memory management."""
    cache_manager = _get_cache_manager()
    cache_manager.clean_cache("vuln_*.json")


def scan_sbom_with_grype(sbom_path: Path) -> dict[str, Any]:
    """Scan SBOM with grype and return the results.

    Args:
        sbom_path: Path to SBOM file to scan

    Returns:
        Dictionary containing grype scan results

    Raises:
        VulnerabilityScanError: If grype scanning fails
    """
    try:
        cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]
        console.print(f"Running: {' '.join(cmd)}", style="blue")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,  # Don't raise on non-zero exit (grype returns 1 when vulns found)
        )

        # grype returns 0 for no vulnerabilities, 1 for vulnerabilities found
        # anything else is an error
        if result.returncode not in [0, 1]:
            raise VulnerabilityScanError(
                f"Grype scanning failed with return code {result.returncode}. "
                f"Error: {result.stderr}",
                create_error_context(sbom_path=str(sbom_path), operation="grype_scan"),
            )

        if not result.stdout.strip():
            console.print("No grype output received", style="yellow")
            return {"matches": [], "source": {"target": str(sbom_path)}}

        try:
            scan_results = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise VulnerabilityScanError(
                f"Failed to parse grype JSON output: {e}",
                create_error_context(sbom_path=str(sbom_path), operation="grype_parse"),
            ) from e

        console.print(
            f"Grype found {len(scan_results.get('matches', []))} vulnerabilities", style="green"
        )
        return scan_results

    except subprocess.TimeoutExpired as e:
        raise VulnerabilityScanError(
            "Grype scanning timed out after 300 seconds",
            create_error_context(sbom_path=str(sbom_path), operation="grype_timeout"),
        ) from e
    except Exception as e:
        if isinstance(e, VulnerabilityScanError):
            raise
        raise VulnerabilityScanError(
            f"Unexpected error during grype scanning: {str(e)}",
            create_error_context(sbom_path=str(sbom_path), operation="grype_error"),
        ) from e


def convert_grype_to_enriched_sbom(
    sbom_data: dict[str, Any], grype_results: dict[str, Any]
) -> dict[str, Any]:
    """Convert grype scan results to enriched SBOM format.

    This function takes grype results and merges them back into the original SBOM
    in the same format that the previous OSV-based enrichment used.

    Args:
        sbom_data: Original SBOM data
        grype_results: Results from grype scan

    Returns:
        Enhanced SBOM with vulnerability data embedded in components
    """
    if not sbom_data or "components" not in sbom_data:
        console.print("Error: Invalid SBOM data provided for enrichment.", style="red")
        return sbom_data

    # Create a copy of the SBOM data to avoid modifying the original
    enriched_sbom = sbom_data.copy()

    # Create a mapping from PURLs to component indices for efficient lookup
    component_map = {}
    for i, comp in enumerate(enriched_sbom.get("components", [])):
        if isinstance(comp, dict) and comp.get("purl"):
            component_map[comp["purl"]] = i

    console.print(
        f"Processing {len(grype_results.get('matches', []))} vulnerability matches...", style="blue"
    )

    # Track statistics
    vulnerable_components = set()
    total_vulnerabilities = 0
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NEGLIGIBLE": 0,
        "UNKNOWN": 0,
    }

    # Process vulnerability matches in parallel with Python 3.13 free-threading
    matches = grype_results.get("matches", [])

    # Initialize component vulnerabilities lists
    for i in range(len(enriched_sbom.get("components", []))):
        if "vulnerabilities" not in enriched_sbom["components"][i]:
            enriched_sbom["components"][i]["vulnerabilities"] = []

    # Define worker function for processing individual matches
    def process_vulnerability_match(match):
        """Process a single vulnerability match and return enriched data."""
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})
        related_vulns = match.get("relatedVulnerabilities", [])

        # Find the component this vulnerability affects
        artifact_purl = artifact.get("purl", "")
        if not artifact_purl or artifact_purl not in component_map:
            return None, None, None

        component_idx = component_map[artifact_purl]

        # Use the primary CVE if available, otherwise use the grype vulnerability ID
        primary_cve = None
        for related in related_vulns:
            if related.get("id", "").startswith("CVE-"):
                primary_cve = related.get("id")
                break

        vuln_id = primary_cve or vulnerability.get("id", "Unknown")

        # Extract CVSS information using version-aware handler
        cvss_score = None
        cvss_version = None
        cvss_severity = "UNKNOWN"
        cvss_vector = None
        all_cvss_metrics = {}

        # Collect all CVSS data from both related vulnerabilities and main vulnerability
        all_grype_cvss = []

        # Try related vulnerabilities first (more detailed, prefer Primary type)
        for related in related_vulns:
            cvss_list = related.get("cvss", [])
            if cvss_list:
                # Prefer Primary source entries
                primary_entries = [c for c in cvss_list if c.get("type") == "Primary"]
                if primary_entries:
                    all_grype_cvss.extend(primary_entries)
                else:
                    all_grype_cvss.extend(cvss_list)

        # If no related CVSS, try the main vulnerability
        if not all_grype_cvss:
            cvss_list = vulnerability.get("cvss", [])
            if cvss_list:
                all_grype_cvss.extend(cvss_list)

        # Use version-aware CVSS selection if we have any CVSS data
        if all_grype_cvss:
            # Parse Grype CVSS format into version-keyed dictionary
            parsed_cvss = CVSSVersionHandler.parse_grype_cvss(all_grype_cvss)

            # Select best CVSS version based on our priority hierarchy
            best_cvss = CVSSVersionHandler.select_best_cvss(parsed_cvss)

            cvss_score = best_cvss["cvss_score"]
            cvss_version = best_cvss["cvss_version"]
            cvss_vector = best_cvss["cvss_vector"]
            cvss_severity = best_cvss["cvss_severity"] or "UNKNOWN"
            all_cvss_metrics = best_cvss["all_cvss_metrics"]

        # Fallback to Grype's severity if no CVSS severity determined
        if cvss_severity == "UNKNOWN":
            grype_severity = vulnerability.get("severity", "").upper()
            if grype_severity in severity_counts:
                cvss_severity = grype_severity

        # Get description (prefer related CVE descriptions)
        description = vulnerability.get("description", "")
        for related in related_vulns:
            related_desc = related.get("description", "")
            if related_desc and len(related_desc) > len(description):
                description = related_desc
                break

        if not description:
            description = "No description available"

        # Collect references
        references = []
        for related in related_vulns:
            references.extend(related.get("urls", []))

        # Remove duplicates while preserving order
        seen_refs = set()
        unique_references = []
        for ref in references:
            if ref not in seen_refs:
                unique_references.append(ref)
                seen_refs.add(ref)

        # Extract CWE information from description and references
        import re

        cwe_ids = set()
        cwe_pattern = r"CWE-\d+"

        # Check description and references for CWE mentions
        for text in [description] + unique_references:
            if text:
                cwe_matches = re.findall(cwe_pattern, str(text))
                cwe_ids.update(cwe_matches)

        # Create vulnerability entry with version-aware CVSS fields
        vuln_entry = {
            "source_id": vulnerability.get("id", "Unknown"),
            "cve_id": vuln_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "all_cvss_metrics": all_cvss_metrics,
            "references": unique_references,
            "cwe_ids": list(cwe_ids) if cwe_ids else [],
            "published_date": None,  # Grype doesn't provide this directly
            "modified_date": None,  # Grype doesn't provide this directly
        }

        # Add fix information if available
        fix_info = vulnerability.get("fix", {})
        if fix_info:
            vuln_entry["fixed_versions"] = fix_info.get("versions", [])
            vuln_entry["fix_state"] = fix_info.get("state", "unknown")

        return component_idx, vuln_entry, cvss_severity

    # Process matches in parallel using free-threading
    import sys

    # Use 4 workers if GIL is disabled, otherwise fall back to sequential
    max_workers = 4 if not sys._is_gil_enabled() else 1

    # Collect results from parallel processing
    vuln_results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_match = {
            executor.submit(process_vulnerability_match, match): match for match in matches
        }

        # Process completed futures
        for future in as_completed(future_to_match):
            try:
                component_idx, vuln_entry, cvss_severity = future.result()
                if component_idx is not None and vuln_entry is not None:
                    vuln_results.append((component_idx, vuln_entry, cvss_severity))
            except Exception as e:
                console.print(f"Warning: Failed to process vulnerability: {e}", style="yellow")

    # Apply results to enriched SBOM (sequential to avoid race conditions)
    for component_idx, vuln_entry, cvss_severity in vuln_results:
        enriched_sbom["components"][component_idx]["vulnerabilities"].append(vuln_entry)
        vulnerable_components.add(component_idx)
        total_vulnerabilities += 1

        # Update severity counts
        if cvss_severity in severity_counts:
            severity_counts[cvss_severity] += 1

    # Print summary
    console.print("\n✓ Vulnerability enrichment complete:", style="green")
    console.print(
        f"  - Components with vulnerabilities: {len(vulnerable_components)}", style="cyan"
    )
    console.print(f"  - Total vulnerabilities found: {total_vulnerabilities}", style="cyan")
    console.print("  - Severity breakdown:", style="cyan")
    for severity, count in severity_counts.items():
        if count > 0:
            console.print(f"    - {severity}: {count}", style="cyan")

    return enriched_sbom


def process_single_sbom(input_path: Path, output_path: Path, cache_enabled: bool = True) -> bool:
    """Process a single SBOM file and create enriched version using grype.

    Args:
        input_path: Path to input SBOM file
        output_path: Path where enriched SBOM should be saved
        cache_enabled: Whether to use caching (default: True)

    Returns:
        True if processing succeeded, False otherwise
    """
    try:
        from ...shared.output import output_manager

        # Check cache first based on SBOM content (only if caching is enabled)
        if cache_enabled:
            cached_scan = output_manager.get_cached_scan_by_content(input_path, "grype")
            if cached_scan:
                console.print(f"Found cached scan results for {input_path.name}", style="blue")
                # Ensure output directory exists
                output_path.parent.mkdir(parents=True, exist_ok=True)
                # Copy cached result to output location
                shutil.copy2(cached_scan, output_path)
                console.print(f"Used cached enriched SBOM: {output_path}", style="green")
                return True

        # Load the original SBOM
        with open(input_path) as f:
            sbom_data = json.load(f)

        # Check if SBOM has components
        components = sbom_data.get("components", [])
        if not components:
            console.print(
                f"No components found in {input_path}. Copying original file.",
                style="yellow",
            )
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(input_path, output_path)
            return True

        cache_status = "No cached results found." if cache_enabled else "Caching disabled."
        console.print(
            f"{cache_status} Scanning {len(components)} components with grype...", style="blue"
        )

        # Scan with grype
        grype_results = scan_sbom_with_grype(input_path)

        # Convert grype results to enriched SBOM format
        enriched_sbom_data = convert_grype_to_enriched_sbom(sbom_data, grype_results)

        if enriched_sbom_data is None:
            console.print("Failed to enrich SBOM data", style="red")
            return False

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save enriched SBOM
        with open(output_path, "w") as f:
            json.dump(enriched_sbom_data, f, indent=2)

        console.print(f"✓ Enriched SBOM saved: {output_path}", style="green")

        # Cache the result if caching is enabled
        if cache_enabled:
            try:
                output_manager.cache_scan_result(input_path, output_path, "grype")
                console.print("✓ Cached scan result for future use", style="blue")
            except Exception as e:
                console.print(f"⚠️  Could not cache result: {e}", style="yellow")

        return True

    except Exception as e:
        console.print(f"✗ Error processing SBOM: {e}", style="red")
        return False


class VulnerabilityProcessor:
    """Processor for vulnerability scanning operations on SBOM data using grype."""

    def __init__(self, knowledge_graph_builder=None):
        """Initialize vulnerability processor.

        Args:
            knowledge_graph_builder: Optional KnowledgeGraphBuilder instance for KG integration
        """
        self.kg_builder = knowledge_graph_builder

    def process_sbom_with_kg(
        self,
        input_path: Path,
        output_dir: Path,
        output_filename_override: Path | None = None,
    ) -> Path | None:
        """Process a single SBOM file to add vulnerability data with KG integration.

        Args:
            input_path: Path to input SBOM file
            output_dir: Output directory for enriched SBOM
            output_filename_override: Optional custom output filename

        Returns:
            Path to enriched SBOM file if successful, None otherwise
        """
        # Create output path based on parameters
        if output_filename_override:
            output_path = output_filename_override
        else:
            output_path = output_dir / f"{input_path.stem}_enriched.json"

        # Call the module function to process the SBOM
        success = process_single_sbom(input_path, output_path)
        return output_path if success else None

    def enrich_sbom_with_vulnerabilities(self, input_path: Path, output_path: Path) -> bool:
        """Enrich SBOM with vulnerability data using grype.

        Args:
            input_path: Path to input SBOM
            output_path: Path for output enriched SBOM

        Returns:
            True if successful, False otherwise
        """
        return process_single_sbom(input_path, output_path)

    def process_with_kg_integration(
        self, input_paths: list[Path], output_dir: Path
    ) -> dict[str, Any]:
        """Process multiple SBOMs with knowledge graph integration.

        Args:
            input_paths: List of SBOM file paths to process
            output_dir: Output directory for enriched SBOMs

        Returns:
            Dictionary with processing results and KG statistics
        """
        results: dict[str, Any] = {"processed_sboms": [], "failed_sboms": [], "kg_stats": {}}

        if not self.kg_builder:
            raise ValueError("Knowledge graph builder not configured")

        for input_path in input_paths:
            try:
                output_filename = f"{input_path.stem}_enriched.json"
                output_path = output_dir / output_filename

                success = self.enrich_sbom_with_vulnerabilities(input_path, output_path)

                if success:
                    results["processed_sboms"].append(
                        {"input": str(input_path), "output": str(output_path)}
                    )
                else:
                    results["failed_sboms"].append(str(input_path))

            except Exception as e:
                console.print(f"Error processing {input_path}: {e}", style="red")
                results["failed_sboms"].append(str(input_path))

        # Add KG statistics if available
        if self.kg_builder:
            try:
                kg_data = self.kg_builder.get_graph_data()
                results["kg_stats"] = {
                    "total_nodes": len(kg_data.get("nodes", [])),
                    "total_edges": len(kg_data.get("edges", [])),
                }
            except Exception as e:
                console.print(f"Could not get KG stats: {e}", style="yellow")

        return results


if __name__ == "__main__":
    """Main entry point for direct execution."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Scan SBOM components for vulnerabilities using grype."
    )
    parser.add_argument(
        "sbom_file",
        type=str,
        help="Path to the input CycloneDX SBOM JSON file.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to save the enriched SBOM file.",
    )

    args = parser.parse_args()

    input_path = Path(args.sbom_file)

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / f"{input_path.stem}_enriched.json"

    console.print(f"Input SBOM: {input_path}", style="blue")
    console.print(f"Output Path: {output_path}", style="blue")

    success = process_single_sbom(input_path, output_path)

    if success:
        console.print("✓ SBOM enrichment completed successfully", style="green")
        sys.exit(0)
    else:
        console.print("✗ SBOM enrichment failed", style="red")
        sys.exit(1)
