"""
SBOM operations module.

Contains SBOM generation and filtering functionality.
"""

from .filtering import SBOMFilterProcessor
from .generation import SBOMProcessor

__all__ = [
    "SBOMProcessor",
    "SBOMFilterProcessor",
]
