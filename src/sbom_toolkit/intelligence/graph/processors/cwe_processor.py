from typing import Any

from ..schema import KGNodeType
from .base_processor import BaseProcessor


class CWEProcessor(BaseProcessor):
    """Processor for CWE data."""

    def process(self, data: Any, *args: Any, **kwargs: Any) -> dict[str, int]:
        """Builds graph components from a list of parsed CWE data.

        Args:
            data: List of parsed CWE data

        Returns:
            Statistics about processed data
        """
        cwe_data_list = data
        cwe_count = 0

        for cwe_data in cwe_data_list:
            cwe_id = cwe_data.get("id")
            if not cwe_id:
                continue
            self.add_node(KGNodeType.CWE, cwe_id, cwe_data)
            cwe_count += 1

        return {"cwe_count": cwe_count}
