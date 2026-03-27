"""
Cleanup command for SBOM toolkit CLI.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from ...shared.exceptions import SBOMToolkitError
from ...shared.output import OutputManager
from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


def _check_docker_available() -> bool:
    """Check if Docker is available and accessible."""
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _get_docker_images(filters: list[str] | None = None) -> list[dict[str, Any]]:
    """Get Docker images with optional filters."""
    cmd = ["docker", "images", "--format", "json"]
    if filters:
        for f in filters:
            cmd.extend(["-f", f])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return []

        images = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                try:
                    images.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return images
    except Exception:
        return []


def _get_sbom_related_images() -> list[dict[str, Any]]:
    """Get Docker images created by SBOM toolkit."""
    all_images = _get_docker_images()
    sbom_images = []

    sbom_patterns = ["sbom-scan-", "sbom-adaptive-", "sbom-"]

    for image in all_images:
        repo = image.get("Repository", "")
        if any(pattern in repo for pattern in sbom_patterns):
            sbom_images.append(image)

    return sbom_images


def _remove_docker_images(image_ids: list[str], force: bool = True) -> tuple[int, list[str]]:
    """Remove Docker images by ID."""
    if not image_ids:
        return 0, []

    cmd = ["docker", "rmi"]
    if force:
        cmd.append("-f")
    cmd.extend(image_ids)

    removed_count = 0
    errors = []

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            removed_count = len(image_ids)
        else:
            errors.append(f"Docker rmi failed: {result.stderr}")
    except Exception as e:
        errors.append(f"Failed to remove images: {str(e)}")

    return removed_count, errors


def _cleanup_docker_system(dry_run: bool = False) -> dict[str, Any]:
    """Clean up Docker system (dangling images, unused containers, etc.)."""
    stats = {
        "dangling_images": 0,
        "unused_containers": 0,
        "volumes": 0,
        "networks": 0,
        "build_cache": 0,
        "total_space_reclaimed": "0B",
    }

    if dry_run:
        # For dry run, just show what would be cleaned
        try:
            result = subprocess.run(
                ["docker", "system", "df", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data:
                    if item["Type"] == "Images":
                        stats["total_space_reclaimed"] = item["Reclaimable"]
        except Exception:
            pass
    else:
        # Actually clean up
        try:
            result = subprocess.run(
                ["docker", "system", "prune", "-a", "-f", "--volumes"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                # Parse the output to get statistics
                output = result.stdout
                if "Total reclaimed space:" in output:
                    stats["total_space_reclaimed"] = output.split("Total reclaimed space:")[
                        -1
                    ].strip()
        except Exception as e:
            stats["error"] = str(e)

    return stats


@click.command()
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be cleaned without actually doing it",
)
@click.option(
    "--max-age-days",
    type=int,
    default=30,
    help="Maximum age of files to keep (in days)",
)
@click.option(
    "--organize-only",
    is_flag=True,
    help="Only organize misplaced files, do not delete old files",
)
@click.option("--clear-cache", is_flag=True, help="Clear all cached scan results")
@click.option(
    "--docker-cleanup",
    is_flag=True,
    help="Clean up Docker images created by SBOM toolkit",
)
@click.option(
    "--docker-deep-clean",
    is_flag=True,
    help="Perform deep Docker cleanup (all dangling images, containers, volumes)",
)
@click.option("--output-dir", default="outputs", help="Output directory to clean up")
@click.pass_context
def cleanup(
    ctx,
    dry_run,
    max_age_days,
    organize_only,
    clear_cache,
    docker_cleanup,
    docker_deep_clean,
    output_dir,
):
    """Clean up and organize output files and Docker images."""
    logger = ctx.obj["logger"]

    try:
        output_manager = OutputManager(Path(output_dir))

        click.echo("🧹 Analyzing cleanup targets...")

        # First, organize any misplaced files
        organized_count = _organize_misplaced_files(output_manager, dry_run)

        if organized_count > 0:
            click.echo(f"✓ Organized {organized_count} misplaced files")

        if clear_cache:
            # Clear cache files
            cache_dir = output_manager.dirs["cache"]
            cache_count = len(list(cache_dir.glob("*.json")))

            if dry_run:
                click.echo(f"📋 Would clear {cache_count} cached scan results")
            else:
                try:
                    output_manager.cache_manager.clean_cache("*.json")
                    click.echo(f"✓ Cleared {cache_count} cached scan results")
                except Exception as e:
                    click.echo(f"⚠️ Warning: Failed to clear cache: {e}")

        # Docker cleanup
        if docker_cleanup or docker_deep_clean:
            if not _check_docker_available():
                click.echo("⚠️ Warning: Docker not available, skipping Docker cleanup")
            else:
                _perform_docker_cleanup(docker_deep_clean, dry_run)

        if not organize_only:
            # Clean up old files
            cleanup_stats = output_manager.clean_old_files(
                max_age_days=max_age_days, dry_run=dry_run
            )

            if dry_run:
                click.echo("\n📋 Cleanup summary (DRY RUN):")
            else:
                click.echo("\n✓ Cleanup completed:")

            total_cleaned = sum(cleanup_stats.values())
            if total_cleaned > 0:
                for file_type, count in cleanup_stats.items():
                    if count > 0:
                        click.echo(f"   - {file_type}: {count} files")
            else:
                click.echo("   - No old files found to clean")

        # Show current status
        status = output_manager.get_status()
        click.echo("\n📊 Current output directory status:")
        total_files = 0
        total_size_mb = 0.0

        for category, info in status.items():
            if info["file_count"] > 0:
                click.echo(f"   - {category}: {info['file_count']} files")
                total_files += info["file_count"]
                total_size_mb += info["total_size_mb"]

        click.echo(f"   - Total: {total_files} files, {total_size_mb:.1f} MB")

        logger.info(f"Cleanup completed for {output_dir}")

    except SBOMToolkitError as e:
        logger.error(f"Cleanup failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during cleanup: {e}")
        click.echo(f"✗ Unexpected error: {e}", err=True)
        sys.exit(1)


def _perform_docker_cleanup(deep_clean: bool, dry_run: bool):
    """Perform Docker cleanup operations."""
    click.echo("\n🐳 Docker cleanup:")

    if deep_clean:
        # Deep clean: remove all dangling images, unused containers, volumes, etc.
        click.echo("   Performing deep Docker cleanup...")

        if dry_run:
            # Show what would be cleaned
            dangling_images = _get_docker_images(["dangling=true"])
            click.echo(f"   📋 Would remove {len(dangling_images)} dangling images")

            stats = _cleanup_docker_system(dry_run=True)
            if stats.get("total_space_reclaimed", "0B") != "0B":
                click.echo(f"   📋 Would reclaim approximately {stats['total_space_reclaimed']}")
        else:
            stats = _cleanup_docker_system(dry_run=False)
            if "error" in stats:
                click.echo(f"   ⚠️ Warning: Docker cleanup failed: {stats['error']}")
            else:
                click.echo("   ✓ Docker system cleanup completed")
                if stats.get("total_space_reclaimed", "0B") != "0B":
                    click.echo(f"   ✓ Reclaimed space: {stats['total_space_reclaimed']}")
    else:
        # Regular clean: only SBOM-related images
        sbom_images = _get_sbom_related_images()
        dangling_images = _get_docker_images(["dangling=true"])

        if sbom_images:
            image_ids = [img["ID"] for img in sbom_images]

            if dry_run:
                click.echo(f"   📋 Would remove {len(sbom_images)} SBOM-related images:")
                for img in sbom_images[:5]:  # Show first 5
                    repo = img.get("Repository", "<none>")
                    tag = img.get("Tag", "<none>")
                    size = img.get("Size", "unknown")
                    click.echo(f"      - {repo}:{tag} ({size})")
                if len(sbom_images) > 5:
                    click.echo(f"      ... and {len(sbom_images) - 5} more")
            else:
                removed_count, errors = _remove_docker_images(image_ids)
                if removed_count > 0:
                    click.echo(f"   ✓ Removed {removed_count} SBOM-related images")
                if errors:
                    for error in errors:
                        click.echo(f"   ⚠️ Warning: {error}")

        if dangling_images:
            image_ids = [img["ID"] for img in dangling_images]

            if dry_run:
                total_size = sum(
                    float(
                        img.get("Size", "0B").replace("GB", "").replace("MB", "").replace("B", "")
                    )
                    for img in dangling_images
                    if "GB" in img.get("Size", "") or "MB" in img.get("Size", "")
                )
                click.echo(
                    f"   📋 Would remove {len(dangling_images)} dangling images (~{total_size:.1f}GB)"
                )
            else:
                removed_count, errors = _remove_docker_images(image_ids)
                if removed_count > 0:
                    click.echo(f"   ✓ Removed {removed_count} dangling images")
                if errors:
                    for error in errors:
                        click.echo(f"   ⚠️ Warning: {error}")

        if not sbom_images and not dangling_images:
            click.echo("   ✓ No Docker images to clean up")


def _organize_misplaced_files(output_manager: OutputManager, dry_run: bool) -> int:
    """Organize files that are in the wrong locations.

    Args:
        output_manager: Output manager instance
        dry_run: Whether to only show what would be done

    Returns:
        Number of files organized
    """
    organized_count = 0
    base_dir = output_manager.base_dir

    # Look for SBOM files in the root that should be in sboms/
    for file_path in base_dir.glob("*_sbom.json"):
        if file_path.is_file():
            target_path = output_manager.dirs["sboms"] / file_path.name

            if dry_run:
                click.echo(f"   Would move: {file_path.name} → sboms/")
            else:
                shutil.move(str(file_path), str(target_path))
                click.echo(f"   Moved: {file_path.name} → sboms/")

            organized_count += 1

    # Look for scan files in the root that should be in scans/
    for file_path in base_dir.glob("*_scan_*.json"):
        if file_path.is_file():
            target_path = output_manager.dirs["scans"] / file_path.name

            if dry_run:
                click.echo(f"   Would move: {file_path.name} → scans/")
            else:
                shutil.move(str(file_path), str(target_path))
                click.echo(f"   Moved: {file_path.name} → scans/")

            organized_count += 1

    # Look for visualization files in the root that should be in visualizations/
    for file_path in base_dir.glob("*.html"):
        if file_path.is_file() and any(
            layout in file_path.name
            for layout in [
                "force-directed",
                "hierarchical",
                "circular",
                "visualization",
            ]
        ):
            target_path = output_manager.dirs["visualizations"] / file_path.name

            if dry_run:
                click.echo(f"   Would move: {file_path.name} → visualizations/")
            else:
                shutil.move(str(file_path), str(target_path))
                click.echo(f"   Moved: {file_path.name} → visualizations/")

            organized_count += 1

    return organized_count


@click.command()
@click.option("--output-dir", default="outputs", help="Output directory to analyze")
@click.pass_context
def status(ctx, output_dir):
    """Show detailed status of output directory."""
    logger = ctx.obj["logger"]

    try:
        output_manager = OutputManager(Path(output_dir))
        status_info = output_manager.get_status()

        click.echo("📊 Output Directory Status")
        click.echo("=" * 40)

        click.echo(f"Base directory: {output_manager.base_dir}")

        total_files = 0
        total_size_mb = 0.0

        click.echo("\nFile counts by category:")
        for category, info in status_info.items():
            if info["file_count"] > 0:
                click.echo(
                    f"   {category:<15}: {info['file_count']:>4} files ({info['total_size_mb']:.1f} MB)"
                )
                total_files += info["file_count"]
                total_size_mb += info["total_size_mb"]

        click.echo(f"\nTotal: {total_files} files, {total_size_mb:.1f} MB")

        logger.info(f"Status displayed for {output_dir}")

    except Exception as e:
        logger.error(f"Status check failed: {e}")
        click.echo(f"✗ Error: {e}", err=True)
        sys.exit(1)
