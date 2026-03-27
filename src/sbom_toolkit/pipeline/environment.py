"""
Simplified environment management for Python environments.
"""

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..shared.version import detect_python_version


def get_available_backends() -> dict:
    """Get status of all available environment backends."""
    return {
        "uv": shutil.which("uv") is not None,
        "venv": True,  # Always available
    }


def setup_environment(
    repo_path: Path,
    preferred_backend: str | None = None,
    env_name: str | None = None,
) -> tuple[str, str]:
    """Set up Python environment for the repository.

    Args:
        repo_path: Path to the repository
        preferred_backend: Preferred backend ('conda', 'uv', 'venv', or None for auto)
        env_name: Optional environment name

    Returns:
        Tuple of (python_path, pip_path)
    """
    logger = logging.getLogger(__name__)

    if env_name is None:
        env_name = f"sbom_{repo_path.name}"

    # Select backend
    available = get_available_backends()

    if preferred_backend and available.get(preferred_backend):
        backend = preferred_backend
    elif available["uv"]:
        backend = "uv"  # Primary choice
    else:
        backend = "venv"  # Fallback choice

    logger.debug(f"Using environment backend: {backend}")

    # Setup environment based on backend
    if backend == "uv":
        return _setup_uv_env(repo_path, env_name)
    else:
        return _setup_venv_env(repo_path, env_name)


def install_dependencies(repo_path: Path, python_path: str, backend: str | None = None) -> bool:
    """Install dependencies for the repository.

    Args:
        repo_path: Path to the repository
        python_path: Path to Python executable
        backend: Backend that was used for environment setup

    Returns:
        True if installation was successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    logger.debug("Installing dependencies...")

    # Check for different dependency files in priority order
    requirements_file = repo_path / "requirements.txt"
    pyproject_file = repo_path / "pyproject.toml"
    pipfile = repo_path / "Pipfile"
    uv_lock_file = repo_path / "uv.lock"

    # Debug logging to help diagnose file detection issues
    logger.info(f"Checking for dependency files in: {repo_path}")
    if repo_path.exists():
        try:
            files_in_repo = [f.name for f in repo_path.iterdir() if f.is_file()]
            logger.info(f"Files found: {files_in_repo}")
        except Exception as e:
            logger.warning(f"Could not list repository contents: {e}")

    logger.debug(f"Checking for requirements.txt at: {requirements_file}")
    logger.debug(f"requirements.txt exists: {requirements_file.exists()}")
    logger.debug(f"Checking for pyproject.toml at: {pyproject_file}")
    logger.debug(f"pyproject.toml exists: {pyproject_file.exists()}")

    # Detect backend from python_path if not provided
    if backend is None:
        if ".venv_" in str(python_path):
            backend = "uv"
        else:
            backend = "venv"

    try:
        # Use uv's native capabilities when available
        if backend == "uv" and shutil.which("uv"):
            # Try uv's native project management first
            if uv_lock_file.exists():
                logger.debug("Found uv.lock, using uv sync...")
                return _install_with_uv_sync(repo_path, python_path)
            elif pyproject_file.exists():
                logger.debug("Found pyproject.toml, using uv for project installation...")
                return _install_with_uv_project(repo_path, python_path, pyproject_file)
            elif requirements_file.exists():
                logger.debug("Found requirements.txt, using uv pip install...")
                return _install_with_uv_pip(repo_path, python_path, requirements_file)
            else:
                logger.warning(
                    "No dependency files found (requirements.txt, pyproject.toml, uv.lock)"
                )
                logger.info(
                    "Skipping dependency installation - this may be an application without explicit dependencies"
                )
                return True  # Return success to allow SBOM generation to continue
        else:
            # Fallback to traditional pip-based installation
            if requirements_file.exists():
                logger.debug("Found requirements.txt, installing dependencies...")
                return _install_from_requirements(repo_path, python_path, requirements_file)
            elif pyproject_file.exists():
                logger.debug("Found pyproject.toml, installing package...")
                return _install_from_pyproject(repo_path, python_path)
            elif pipfile.exists():
                logger.debug("Found Pipfile, installing with pipenv...")
                return _install_from_pipfile(repo_path, python_path)
            else:
                logger.warning(
                    "No dependency files found (requirements.txt, pyproject.toml, Pipfile)"
                )
                logger.info(
                    "Skipping dependency installation - this may be an application without explicit dependencies"
                )
                return True  # Return success to allow SBOM generation to continue
    except Exception as e:
        logger.error(f"Dependency installation failed: {e}")
        return False


def cleanup_environment(env_name: str, backend: str | None = None) -> None:
    """Clean up environment.

    Args:
        env_name: Name of the environment to remove
        backend: Backend that was used (for cleanup optimization)
    """
    logger = logging.getLogger(__name__)

    # For uv/venv, we'd need the actual path - just log for now
    logger.debug(f"Environment cleanup requested for: {env_name}")


def _setup_uv_env(repo_path: Path, env_name: str) -> tuple[str, str]:
    """Set up uv environment with optimized configuration."""
    logger = logging.getLogger(__name__)
    python_version = detect_python_version(repo_path)
    venv_path = repo_path / f".venv_{env_name}"

    # Remove existing environment
    if venv_path.exists():
        shutil.rmtree(venv_path)

    # Create new environment with uv optimizations
    env = {
        # Enable parallel downloads and installations
        "UV_CONCURRENT_INSTALLS": "4",  # Use 4 threads for installs
        "UV_CONCURRENT_BUILDS": "2",  # Limit concurrent builds to avoid memory issues
    }

    subprocess.run(
        ["uv", "venv", str(venv_path), "--python", python_version],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_path,
        env={**os.environ, **env},
    )

    # Get paths
    if sys.platform == "win32":
        python_path = str(venv_path / "Scripts" / "python.exe")
    else:
        python_path = str(venv_path / "bin" / "python")

    logger.debug(f"✓ uv environment created with parallel installation support: {venv_path}")
    return python_path, "uv"  # Return "uv" as indicator to use uv commands


def _setup_venv_env(repo_path: Path, env_name: str) -> tuple[str, str]:
    """Set up standard venv environment."""
    venv_path = repo_path / f".venv_{env_name}"

    # Remove existing environment
    if venv_path.exists():
        shutil.rmtree(venv_path)

    # Create new environment
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_path)],
        check=True,
        capture_output=True,
        text=True,
        cwd=repo_path,
    )

    # Get paths
    if sys.platform == "win32":
        python_path = str(venv_path / "Scripts" / "python.exe")
        pip_path = str(venv_path / "Scripts" / "pip.exe")
    else:
        python_path = str(venv_path / "bin" / "python")
        pip_path = str(venv_path / "bin" / "pip")

    return python_path, pip_path


# uv-native installation functions
def _install_with_uv_sync(repo_path: Path, python_path: str) -> bool:
    """Install dependencies using uv sync (fastest method for uv projects)."""
    logger = logging.getLogger(__name__)

    try:
        logger.debug("Installing dependencies with uv sync...")

        # Extract virtual environment path from python_path
        venv_path = Path(python_path).parent.parent

        # Set up environment for parallel operations and virtual environment isolation
        env = {
            "UV_CONCURRENT_INSTALLS": "4",
            "UV_CONCURRENT_BUILDS": "2",
            "VIRTUAL_ENV": str(venv_path),  # Tell uv which virtual environment to use
        }

        subprocess.run(
            ["uv", "sync", "--locked", "--python", python_path],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
        )
        logger.debug("✓ uv sync installation successful")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"uv sync failed: {e.stderr.strip() if e.stderr else str(e)}")
        return False


def _install_with_uv_project(repo_path: Path, python_path: str, pyproject_file: Path) -> bool:
    """Install project using uv's project management."""
    logger = logging.getLogger(__name__)

    try:
        logger.debug("Installing project with uv...")

        # Extract virtual environment path from python_path
        venv_path = Path(python_path).parent.parent

        # Set up environment for parallel operations and virtual environment isolation
        env = {
            "UV_CONCURRENT_INSTALLS": "4",
            "UV_CONCURRENT_BUILDS": "2",
            "VIRTUAL_ENV": str(venv_path),  # Tell uv which virtual environment to use
        }

        # Try to create lock file and sync
        try:
            subprocess.run(
                ["uv", "lock", "--python", python_path],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, **env},
                timeout=120,  # Reasonable timeout for lock generation
            )

            subprocess.run(
                ["uv", "sync", "--python", python_path],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, **env},
            )
            logger.debug("✓ uv project installation successful")
            return True
        except subprocess.CalledProcessError:
            # Fallback to pip install if lock/sync fails
            logger.debug("uv sync failed, trying uv pip install .")
            subprocess.run(
                ["uv", "pip", "install", ".", "--python", python_path],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, **env},
            )
            logger.debug("✓ uv pip install . successful")
            return True

    except subprocess.CalledProcessError as e:
        logger.warning(
            f"uv project installation failed: {e.stderr.strip() if e.stderr else str(e)}"
        )
        return False


def _install_with_uv_pip(repo_path: Path, python_path: str, requirements_file: Path) -> bool:
    """Install dependencies using uv pip (much faster than regular pip)."""
    logger = logging.getLogger(__name__)

    logger.debug(f"Installing dependencies from {requirements_file} using uv pip...")

    # Extract virtual environment path from python_path
    venv_path = Path(python_path).parent.parent

    # Set up environment for parallel operations and virtual environment isolation
    env = {
        "UV_CONCURRENT_INSTALLS": "4",
        "UV_CONCURRENT_BUILDS": "2",
        "VIRTUAL_ENV": str(venv_path),  # Tell uv which virtual environment to use
    }

    try:
        subprocess.run(
            ["uv", "pip", "install", "-r", str(requirements_file), "--python", python_path],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
        )
        logger.debug("✓ uv pip bulk installation successful")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"uv pip bulk install failed: {e.stderr.strip() if e.stderr else str(e)}")

        # For uv, we don't need to fall back to individual installs as often
        # uv is much more robust than pip, but let's try once more with verbose output
        try:
            logger.debug("Retrying uv pip install with verbose output...")
            subprocess.run(
                [
                    "uv",
                    "pip",
                    "install",
                    "-r",
                    str(requirements_file),
                    "--python",
                    python_path,
                    "-v",
                ],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, **env},
            )
            logger.debug("✓ uv pip verbose installation successful")
            return True
        except subprocess.CalledProcessError as e2:
            logger.error(
                f"uv pip installation failed even with verbose: {e2.stderr.strip() if e2.stderr else str(e2)}"
            )
            return False


def _install_with_uv_editable(repo_path: Path, python_path: str) -> bool:
    """Install package in editable mode using uv."""
    logger = logging.getLogger(__name__)

    try:
        logger.debug("Installing package in editable mode with uv...")

        # Extract virtual environment path from python_path
        venv_path = Path(python_path).parent.parent

        # Set up environment for parallel operations and virtual environment isolation
        env = {
            "UV_CONCURRENT_INSTALLS": "4",
            "UV_CONCURRENT_BUILDS": "2",
            "VIRTUAL_ENV": str(venv_path),  # Tell uv which virtual environment to use
        }

        subprocess.run(
            ["uv", "pip", "install", "-e", ".", "--python", python_path],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, **env},
        )
        logger.debug("✓ uv editable installation successful")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"uv editable install failed: {e.stderr.strip() if e.stderr else str(e)}")
        return False


# Traditional pip-based installation functions (fallbacks)
def _install_from_requirements(repo_path: Path, python_path: str, requirements_file: Path) -> bool:
    """Install dependencies from requirements.txt."""
    logger = logging.getLogger(__name__)

    try:
        logger.debug(f"Installing dependencies from {requirements_file} using {python_path}")
        subprocess.run(
            [python_path, "-m", "pip", "install", "-r", str(requirements_file)],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        logger.debug("✓ Bulk dependency installation successful")
        return True
    except subprocess.CalledProcessError as e:
        logger.warning(f"Bulk pip install failed: {e.stderr.strip() if e.stderr else str(e)}")
        logger.debug("Attempting individual package installation...")

        # Try individual package installation on failure
        try:
            with open(requirements_file) as f:
                requirements = [
                    line.strip() for line in f if line.strip() and not line.startswith("#")
                ]

            success = True
            failed_packages = []

            for req in requirements:
                try:
                    logger.debug(f"Installing: {req}")
                    subprocess.run(
                        [python_path, "-m", "pip", "install", req],
                        cwd=repo_path,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    logger.debug(f"✓ Successfully installed: {req}")
                except subprocess.CalledProcessError as e:
                    logger.warning(
                        f"Failed to install {req}: {e.stderr.strip() if e.stderr else str(e)}"
                    )
                    failed_packages.append(req)
                    success = False

            if failed_packages:
                logger.warning(f"Failed to install packages: {', '.join(failed_packages)}")

            return success
        except Exception as e:
            logger.error(f"Individual package installation failed: {e}")
            return False


def _install_from_pyproject(repo_path: Path, python_path: str) -> bool:
    """Install package from pyproject.toml."""
    try:
        subprocess.run(
            [python_path, "-m", "pip", "install", "."],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _install_from_pipfile(repo_path: Path, python_path: str) -> bool:
    """Install dependencies using pipenv."""
    try:
        # Install pipenv first
        subprocess.run(
            [python_path, "-m", "pip", "install", "pipenv"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        # Run pipenv install
        subprocess.run(
            ["pipenv", "install"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _install_editable(repo_path: Path, python_path: str) -> bool:
    """Install package in editable mode."""
    try:
        subprocess.run(
            [python_path, "-m", "pip", "install", "-e", "."],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False
