from typing import Any

from ..schema import KGNodeType, KGRelationshipType
from .base_processor import BaseProcessor


class CAPECProcessor(BaseProcessor):
    """Processor for CAPEC data."""

    def process(self, data: Any, *args: Any, **kwargs: Any) -> dict[str, int]:
        """Builds graph components from a list of parsed CAPEC data.

        Args:
            data: List of parsed CAPEC data

        Returns:
            Statistics about processed data
        """
        capec_data_list = data
        capec_count = 0
        relationship_count = 0

        for capec_data in capec_data_list:
            capec_id = capec_data.get("id")
            if not capec_id:
                continue
            self.add_node(KGNodeType.CAPEC, capec_id, capec_data)
            capec_count += 1

            for related_cwe in capec_data.get("related_cwes", []):
                self.add_edge(
                    KGNodeType.CAPEC,
                    capec_id,
                    KGNodeType.CWE,
                    related_cwe,
                    KGRelationshipType.EXPLOITS_CWE,
                )
                relationship_count += 1

        return {"capec_count": capec_count, "relationship_count": relationship_count}
