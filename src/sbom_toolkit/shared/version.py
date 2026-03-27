"""
Python version detection utilities.

This module provides sophisticated Python version detection for repositories
using multiple approaches: explicit metadata, code analysis, and heuristics.
"""

import re

# Use built-in tomllib on Python 3.11+, fallback to tomli for older versions
import tomllib  # type: ignore[import-untyped]
from pathlib import Path


def detect_python_version(repo_path: Path) -> str:
    """Detect Python version requirements from repository files using multiple approaches."""

    # First, check explicit project metadata (most authoritative)
    explicit_version = _get_explicit_python_version(repo_path)
    if explicit_version:
        return explicit_version

    # If no explicit version, analyze the actual code using vermin
    code_analysis_version = _analyze_code_requirements(repo_path)
    if code_analysis_version:
        return code_analysis_version

    # Fallback to project heuristics
    if _is_modern_project(repo_path):
        return "3.11"  # Modern default
    else:
        return "3.8"  # Legacy default


def _get_explicit_python_version(repo_path: Path) -> str | None:
    """Extract explicitly declared Python version from project metadata."""

    # Check pyproject.toml first (preferred modern approach)
    if (repo_path / "pyproject.toml").exists():
        try:
            with open(repo_path / "pyproject.toml", "rb") as f:
                pyproject = tomllib.load(f)
                if "project" in pyproject and "requires-python" in pyproject["project"]:
                    version = pyproject["project"]["requires-python"]
                    return _extract_minimum_version(version)
        except Exception as e:
            print(f"Warning: Could not parse pyproject.toml: {e}")

    # Check setup.py for python_requires
    if (repo_path / "setup.py").exists():
        try:
            with open(repo_path / "setup.py", encoding="utf-8") as f:
                content = f.read()
                match = re.search(r'python_requires\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if match:
                    version = match.group(1)
                    return _extract_minimum_version(version)
        except Exception as e:
            print(f"Warning: Could not parse setup.py: {e}")

    return None


def _extract_minimum_version(version_spec: str) -> str | None:
    """Extract minimum version number from a version specifier string."""
    # Handle common patterns: ">=3.8", "~=3.9", "==3.10.*", etc.
    version_match = re.search(r"(\d+\.\d+)", version_spec)
    if version_match:
        return version_match.group(1)
    return None


def _analyze_code_requirements(repo_path: Path) -> str | None:
    """Use vermin to analyze actual Python code and determine minimum version requirements."""
    try:
        # Try to import vermin for code analysis
        import vermin  # type: ignore

        # Configure vermin to analyze the repository
        config = vermin.Config()
        config.set_quiet(True)  # Reduce output noise

        # Run vermin analysis on the repository
        visitor = vermin.visit(str(repo_path), config)

        # Handle different vermin API versions
        minimum_versions = None
        if hasattr(visitor, "minimum_versions") and callable(
            getattr(visitor, "minimum_versions", None)
        ):
            # Newer vermin API with visitor object
            minimum_versions = visitor.minimum_versions()  # type: ignore
        elif isinstance(visitor, list | tuple) and len(visitor) >= 2:
            # Older vermin API that returns tuple/list directly
            minimum_versions = visitor
        else:
            # Unknown vermin version, skip analysis
            print("Warning: Unsupported vermin version, skipping code analysis")
            return None

        # Extract Python 3 minimum version
        if minimum_versions and len(minimum_versions) >= 2:
            py3_version = minimum_versions[1]  # Second element is Python 3 version
            if py3_version and py3_version != float("inf"):
                # Convert from vermin's internal format to version string
                try:
                    # Handle different possible types for version
                    if isinstance(py3_version, int | float):
                        version_float = float(py3_version)
                        major = int(version_float)
                        minor = int((version_float - major) * 10)
                        return f"{major}.{minor}"
                except (ValueError, TypeError):
                    # Could not convert version format
                    pass

    except ImportError:
        print("Note: vermin not available for code analysis. Install with: pip install vermin")
    except Exception as e:
        print(f"Warning: Code analysis failed: {e}")

    return None


def _is_modern_project(repo_path: Path) -> bool:
    """Determine if this is a modern project based on various indicators."""
    modern_indicators = 0

    # Check for modern project files
    if (repo_path / "pyproject.toml").exists():
        modern_indicators += 2

    if (repo_path / "Dockerfile").exists():
        modern_indicators += 1

    # Check for modern Python patterns in Python files
    try:
        python_files = list(repo_path.glob("*.py"))
        if not python_files:
            # Look deeper if no top-level Python files
            python_files = list(repo_path.rglob("*.py"))[:5]  # Sample a few files

        for py_file in python_files[:3]:  # Check first few files
            if py_file.is_file():
                try:
                    with open(py_file, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        # Modern patterns
                        if "from __future__ import annotations" in content:
                            modern_indicators += 1
                        if any(
                            pattern in content for pattern in ["TypedDict", "Protocol", "Final"]
                        ):
                            modern_indicators += 1
                        if "async def" in content and "await" in content:
                            modern_indicators += 1
                        if 'f"' in content or "f'" in content:  # f-strings (3.6+)
                            modern_indicators += 1
                except Exception:
                    continue
    except Exception:
        pass

    # Check git info for recent activity
    try:
        if (repo_path / ".git").exists():
            import subprocess

            result = subprocess.run(
                ["git", "log", "-1", "--format=%ci"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                from datetime import datetime, timedelta

                try:
                    commit_date = datetime.fromisoformat(
                        result.stdout.strip().replace(" ", "T", 1).replace(" ", "")
                    )
                    if commit_date > datetime.now() - timedelta(days=730):  # 2 years
                        modern_indicators += 2
                except Exception:
                    pass
    except Exception:
        pass

    return modern_indicators >= 3
