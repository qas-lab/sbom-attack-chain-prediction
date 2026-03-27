"""
Health check command for SBOM toolkit CLI.
Tests actual functionality of all components, not just availability.
"""

import json
import shutil
import tempfile
import time
from pathlib import Path

from ..utils import get_click

click, CLICK_AVAILABLE = get_click()


class HealthCheckResult:
    """Result of a health check test."""

    def __init__(
        self,
        component: str,
        test: str,
        passed: bool,
        message: str,
        details: str | None = None,
        duration: float | None = None,
    ):
        self.component = component
        self.test = test
        self.passed = passed
        self.message = message
        self.details = details
        self.duration = duration


class HealthChecker:
    """Comprehensive health checker for SBOM toolkit components."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: list[HealthCheckResult] = []
        self.temp_dir: Path | None = None

    def setup_test_environment(self) -> bool:
        """Set up a minimal test environment."""
        try:
            # Create temporary directory
            self.temp_dir = Path(tempfile.mkdtemp(prefix="sbom_health_check_"))

            # Create a minimal Python project for testing
            test_repo_path = self.temp_dir / "test_project"
            test_repo_path.mkdir()

            # Create minimal Python files
            (test_repo_path / "requirements.txt").write_text("requests==2.28.0\n")
            (test_repo_path / "main.py").write_text(
                "import requests\n\ndef hello():\n    return 'Hello, World!'\n"
            )

            return True
        except Exception as e:
            self.results.append(
                HealthCheckResult(
                    "Environment",
                    "setup",
                    False,
                    f"Failed to create test environment: {str(e)}",
                )
            )
            return False

    def cleanup_test_environment(self) -> None:
        """Clean up test environment."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sbom_generators(self) -> None:
        """Test SBOM generator functionality."""
        click.echo("Testing SBOM generators...")

        try:
            from ...pipeline import (
                generate_sbom,
                get_available_sbom_generators,
            )
            from ...shared.models import RepositoryInfo, RepositoryMetadata

            available_generators = get_available_sbom_generators()

            if not self.temp_dir:
                self.results.append(
                    HealthCheckResult(
                        "SBOM Generator",
                        "setup",
                        False,
                        "Test environment not available",
                    )
                )
                return

            # Create a simple test project structure
            test_repo_path = self.temp_dir / "test_project"
            test_repo_path.mkdir(exist_ok=True)

            # Create a simple Python project
            (test_repo_path / "setup.py").write_text(
                "from setuptools import setup; setup(name='test')"
            )
            (test_repo_path / "requirements.txt").write_text("requests==2.28.0\n")

            repo_info = RepositoryInfo(
                path=test_repo_path,
                metadata=RepositoryMetadata(
                    name="test-project",
                    owner="test",
                    url="https://github.com/test/test-project",
                ),
            )

            output_dir = self.temp_dir / "sbom_output"
            output_dir.mkdir(exist_ok=True)

            # Test each available generator
            for generator_name in ["syft", "cdxgen"]:
                start_time = time.time()

                if generator_name not in available_generators:
                    self.results.append(
                        HealthCheckResult(
                            "SBOM Generator",
                            generator_name,
                            False,
                            "Generator not available",
                            duration=time.time() - start_time,
                        )
                    )
                    continue

                try:
                    # Test actual SBOM generation
                    sbom_path = generate_sbom(repo_info, output_dir, generator=generator_name)
                    duration = time.time() - start_time

                    if sbom_path and sbom_path.exists():
                        # Basic validation
                        with open(sbom_path) as f:
                            sbom_data = json.load(f)

                        has_components = bool(
                            sbom_data.get("components") or sbom_data.get("artifacts")
                        )

                        if has_components:
                            self.results.append(
                                HealthCheckResult(
                                    "SBOM Generator",
                                    generator_name,
                                    True,
                                    "Generated valid SBOM with components",
                                    f"SBOM path: {sbom_path}",
                                    duration,
                                )
                            )
                        else:
                            self.results.append(
                                HealthCheckResult(
                                    "SBOM Generator",
                                    generator_name,
                                    False,
                                    "Generated SBOM but no components found",
                                    f"SBOM path: {sbom_path}",
                                    duration,
                                )
                            )
                    else:
                        self.results.append(
                            HealthCheckResult(
                                "SBOM Generator",
                                generator_name,
                                False,
                                "Failed to generate SBOM file",
                                duration=duration,
                            )
                        )

                except Exception as e:
                    duration = time.time() - start_time
                    self.results.append(
                        HealthCheckResult(
                            "SBOM Generator",
                            generator_name,
                            False,
                            f"Generation failed: {str(e)}",
                            duration=duration,
                        )
                    )

            # Docker-based generation has been archived

        except Exception as e:
            self.results.append(
                HealthCheckResult(
                    "SBOM Generator",
                    "import",
                    False,
                    f"Failed to import generator functions: {str(e)}",
                )
            )

    def test_vulnerability_scanners(self) -> None:
        """Test vulnerability scanner functionality."""
        click.echo("Testing vulnerability scanners...")

        try:
            from ...pipeline import (
                get_available_vulnerability_scanners,
                scan_for_vulnerabilities,
            )

            available_scanners = get_available_vulnerability_scanners()

            if not self.temp_dir:
                self.results.append(
                    HealthCheckResult(
                        "Vulnerability Scanner",
                        "setup",
                        False,
                        "Test environment not available",
                    )
                )
                return

            # Create a minimal test SBOM with proper CycloneDX format
            test_sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789012",
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00.000Z",
                    "tools": [
                        {
                            "vendor": "sbom-toolkit",
                            "name": "health-check",
                            "version": "1.0.0",
                        }
                    ],
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "pkg:pypi/requests@2.28.0",
                        "name": "requests",
                        "version": "2.28.0",
                        "purl": "pkg:pypi/requests@2.28.0",
                    }
                ],
            }

            sbom_path = self.temp_dir / "bom.json"
            with open(sbom_path, "w") as f:
                json.dump(test_sbom, f)

            # Test each available scanner
            for scanner_name in ["grype"]:
                start_time = time.time()

                if scanner_name not in available_scanners:
                    self.results.append(
                        HealthCheckResult(
                            "Vulnerability Scanner",
                            scanner_name,
                            False,
                            "Scanner not available",
                            duration=time.time() - start_time,
                        )
                    )
                    continue

                try:
                    # Test SBOM scanning
                    scan_results = scan_for_vulnerabilities(sbom_path, scanner=scanner_name)
                    duration = time.time() - start_time

                    # Validate scan results
                    if isinstance(scan_results, dict):
                        vuln_count = (
                            len(scan_results.get("vulnerabilities", []))
                            if "vulnerabilities" in scan_results
                            else 0
                        )
                        # For some scanners, vulnerabilities might be in different locations
                        if vuln_count == 0:
                            # Check alternative structures
                            if "matches" in scan_results:
                                vuln_count = len(scan_results["matches"])
                            elif "Results" in scan_results:
                                vuln_count = sum(
                                    len(r.get("Vulnerabilities", []))
                                    for r in scan_results["Results"]
                                )

                        self.results.append(
                            HealthCheckResult(
                                "Vulnerability Scanner",
                                scanner_name,
                                True,
                                f"Scan completed, found {vuln_count} vulnerabilities",
                                f"Results structure: {list(scan_results.keys())}",
                                duration,
                            )
                        )
                    else:
                        self.results.append(
                            HealthCheckResult(
                                "Vulnerability Scanner",
                                scanner_name,
                                False,
                                "Scanner returned invalid results format",
                                duration=duration,
                            )
                        )

                except Exception as e:
                    duration = time.time() - start_time
                    self.results.append(
                        HealthCheckResult(
                            "Vulnerability Scanner",
                            scanner_name,
                            False,
                            f"Scanning failed: {str(e)}",
                            duration=duration,
                        )
                    )

        except Exception as e:
            self.results.append(
                HealthCheckResult(
                    "Vulnerability Scanner",
                    "import",
                    False,
                    f"Failed to import scanner functions: {str(e)}",
                )
            )

    def test_optional_dependencies(self) -> None:
        """Test optional dependencies."""
        click.echo("Testing optional dependencies...")

        deps = [
            ("pyvis", "Interactive network visualizations"),
            ("networkx", "Graph analysis and processing"),
            ("rich", "Enhanced console output"),
            ("pydantic", "Data validation"),
        ]

        for dep, description in deps:
            start_time = time.time()
            try:
                __import__(dep)
                duration = time.time() - start_time
                self.results.append(
                    HealthCheckResult(
                        "Optional Dependency",
                        dep,
                        True,
                        f"Available - {description}",
                        duration=duration,
                    )
                )
            except ImportError:
                duration = time.time() - start_time
                self.results.append(
                    HealthCheckResult(
                        "Optional Dependency",
                        dep,
                        False,
                        f"Missing - {description}",
                        f"Install with: pip install {dep}",
                        duration,
                    )
                )

    def run_all_tests(self) -> list[HealthCheckResult]:
        """Run all health check tests."""
        click.echo("Starting comprehensive health check...\n")

        if not self.setup_test_environment():
            return self.results

        try:
            self.test_sbom_generators()
            self.test_vulnerability_scanners()
            self.test_optional_dependencies()
        finally:
            self.cleanup_test_environment()

        return self.results


def display_results(results: list[HealthCheckResult], verbose: bool) -> None:
    """Display health check results in human-readable format."""
    # Group results by component
    by_component: dict[str, list[HealthCheckResult]] = {}
    for result in results:
        if result.component not in by_component:
            by_component[result.component] = []
        by_component[result.component].append(result)

    # Summary stats
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.passed)
    failed_tests = total_tests - passed_tests

    click.echo("\n=== Health Check Results ===")
    click.echo(f"Total tests: {total_tests}")
    click.echo(f"Passed: {passed_tests}")
    click.echo(f"Failed: {failed_tests}")
    if total_tests > 0:
        click.echo(f"Success rate: {(passed_tests / total_tests * 100):.1f}%\n")

    # Detailed results by component
    for component, component_results in by_component.items():
        component_passed = sum(1 for r in component_results if r.passed)
        component_total = len(component_results)

        click.echo(f"=== {component} ({component_passed}/{component_total} passed) ===")

        for result in component_results:
            status = "✓" if result.passed else "✗"
            duration_str = f" ({result.duration:.2f}s)" if result.duration else ""

            click.echo(f"  {status} {result.test}: {result.message}{duration_str}")

            if verbose and result.details:
                click.echo(f"    Details: {result.details}")
            elif not result.passed and result.details:
                click.echo(f"    Error: {result.details}")

        click.echo("\n")


@click.command(name="check")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed test output")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
@click.option(
    "--component",
    "-c",
    help="Test only specific component type (generator, scanner, dependency)",
)
def check(verbose: bool, json_output: bool, component: str | None):
    """Run comprehensive health checks on all SBOM toolkit components.

    This command goes beyond the basic 'tools' availability check and actually
    tests the functionality of each component with real execution.
    """
    checker = HealthChecker(verbose=verbose)

    if component:
        # Test only specific component type
        component = component.lower()
        if component == "generator":
            if checker.setup_test_environment():
                checker.test_sbom_generators()
                checker.cleanup_test_environment()
        elif component == "scanner":
            if checker.setup_test_environment():
                checker.test_vulnerability_scanners()
                checker.cleanup_test_environment()
        elif component == "dependency":
            checker.test_optional_dependencies()
        else:
            click.echo(f"Unknown component type: {component}")
            click.echo("Available types: generator, scanner, dependency")
            return

        results = checker.results
    else:
        # Run all tests
        results = checker.run_all_tests()

    # Output results
    if json_output:
        json_results = []
        for result in results:
            json_results.append(
                {
                    "component": result.component,
                    "test": result.test,
                    "passed": result.passed,
                    "message": result.message,
                    "details": result.details,
                    "duration": result.duration,
                }
            )
        click.echo(json.dumps(json_results, indent=2))
    else:
        # Human-readable output
        display_results(results, verbose)
