"""
Simplified SBOM and vulnerability scanning tools.
"""

import json
import logging
import shutil
import subprocess
from datetime import UTC
from pathlib import Path
from typing import Any

from ..shared.exceptions import (
    SBOMGenerationError,
    VulnerabilityScanError,
    create_error_context,
)
from ..shared.models import RepositoryInfo


def get_available_sbom_generators() -> list[str]:
    """Get list of available SBOM generators."""
    generators = ["syft", "cdxgen"]
    return [gen for gen in generators if shutil.which(gen)]


def get_available_vulnerability_scanners() -> list[str]:
    """Get list of available vulnerability scanners."""
    scanners = ["grype"]
    return [gen for gen in scanners if shutil.which(gen)]


def get_best_sbom_generator(preference: str | None = None) -> str:
    """Get the best available SBOM generator."""
    available = get_available_sbom_generators()

    if not available:
        raise SBOMGenerationError(
            "No SBOM generators available. Please install syft or cdxgen.",
            create_error_context(operation="generator_selection"),
        )

    # Check preference first
    if preference and preference in available:
        return preference

    # Priority order: syft (primary) > cdxgen (fallback)
    priority = ["syft", "cdxgen"]
    for gen in priority:
        if gen in available:
            return gen

    return available[0]


def get_best_vulnerability_scanner(preference: str | None = None) -> str:
    """Get the best available vulnerability scanner."""
    available = get_available_vulnerability_scanners()

    if not available:
        raise VulnerabilityScanError(
            "No vulnerability scanners available. Please install grype.",
            create_error_context(operation="scanner_selection"),
        )

    # Check preference first
    if preference and preference in available:
        return preference

    # Only grype is supported now
    return "grype"


def generate_sbom(
    repo_info: RepositoryInfo, output_dir: Path, generator: str | None = None
) -> Path | None:
    """Generate SBOM using the specified or best available generator."""
    logger = logging.getLogger(__name__)

    # Get generator
    tool = get_best_sbom_generator(generator)
    logger.info(f"Using SBOM generator: {tool}")

    # Create output path
    output_filename = f"{repo_info.metadata.name}_sbom.json"
    sbom_path = output_dir / output_filename

    context = create_error_context(
        generator=tool, repo_name=repo_info.metadata.name, operation="generate_sbom"
    )

    try:
        if tool == "syft":
            return _generate_with_syft(repo_info, sbom_path, context)
        elif tool == "cdxgen":
            return _generate_with_cdxgen(repo_info, sbom_path, context)
        else:
            raise SBOMGenerationError(f"Unknown generator: {tool}", context)

    except Exception as e:
        if isinstance(e, SBOMGenerationError):
            raise
        raise SBOMGenerationError(f"SBOM generation failed: {str(e)}", context) from e


def scan_for_vulnerabilities(sbom_path: Path, scanner: str | None = None) -> dict[str, Any]:
    """Scan SBOM for vulnerabilities using grype."""
    logger = logging.getLogger(__name__)

    # Always use grype now
    tool = "grype"
    logger.info(f"Using vulnerability scanner: {tool}")

    context = create_error_context(scanner=tool, sbom_path=str(sbom_path), operation="scan_sbom")

    try:
        return _scan_with_grype(sbom_path, context)
    except Exception as e:
        if isinstance(e, VulnerabilityScanError):
            raise
        raise VulnerabilityScanError(f"Vulnerability scan failed: {str(e)}", context) from e


def _generate_with_syft(
    repo_info: RepositoryInfo, sbom_path: Path, context: dict[str, Any]
) -> Path:
    """Generate SBOM using Syft."""
    cmd = [
        "syft",
        str(repo_info.path),
        "-o",
        f"cyclonedx-json={sbom_path}",
        "--exclude",
        "**/.git/**",
        "--exclude",
        "**/node_modules/**",
        "--exclude",
        "**/__pycache__/**",
        "--exclude",
        "**/venv/**",
        "--exclude",
        "**/.venv/**",
    ]

    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)

    # Enrich with metadata
    _enrich_sbom_metadata(sbom_path, repo_info, "syft")
    return sbom_path


def _generate_with_cdxgen(
    repo_info: RepositoryInfo, sbom_path: Path, context: dict[str, Any]
) -> Path:
    """Generate SBOM using cdxgen."""
    cmd = [
        "cdxgen",
        "-t",
        "python",
        "-o",
        str(sbom_path),
        "--exclude-dir",
        ".venv",
        "--exclude-dir",
        "venv",
        "--exclude-dir",
        "node_modules",
        str(repo_info.path),
    ]

    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)

    # Enrich with metadata
    _enrich_sbom_metadata(sbom_path, repo_info, "cdxgen")
    return sbom_path


def _scan_with_grype(sbom_path: Path, context: dict[str, Any]) -> dict[str, Any]:
    """Scan with Grype."""
    cmd = ["grype", str(sbom_path), "-o", "json"]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
    return json.loads(result.stdout)


def _enrich_sbom_metadata(sbom_path: Path, repo_info: RepositoryInfo, generator: str) -> None:
    """Add repository metadata to SBOM."""
    from datetime import datetime

    try:
        with open(sbom_path, encoding="utf-8") as f:
            sbom_data = json.load(f)

        # Add metadata
        if "metadata" not in sbom_data:
            sbom_data["metadata"] = {}

        sbom_data["metadata"]["repository"] = {
            "url": repo_info.metadata.url,
            "owner": repo_info.metadata.owner,
            "name": repo_info.metadata.name,
            "commit": repo_info.metadata.commit_hash or "unknown",
            "latest_tag": repo_info.metadata.latest_tag or "no tag",
            "sbom_generated_at": datetime.now(UTC).isoformat(),
            "generator": generator,
        }

        with open(sbom_path, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

    except Exception:
        # Don't fail SBOM generation if metadata enrichment fails
        pass


# Docker-based generation has been archived - see src/sbom_toolkit/pipeline/archived/docker_tools.py
