from typing import Any

from ..schema import KGNodeType, KGRelationshipType
from .base_processor import BaseProcessor
from .sbom_processor import SBOMProcessor


class SelectiveDataBuilder(BaseProcessor):
    """Builder for selective CWE/CAPEC data based on SBOM vulnerabilities."""

    def __init__(self, builder, sbom_processor: SBOMProcessor):
        super().__init__(builder)
        self.sbom_processor = sbom_processor

    def process(self, data: Any, *args: Any, **kwargs: Any) -> dict[str, int]:
        """Selectively build CWE and CAPEC data based on CVEs found in the SBOM.

        This method:
        1. Extracts all CVE IDs from the SBOM vulnerability data
        2. Fetches detailed CVE information to get associated CWEs
        3. Only adds those specific CWEs to the knowledge graph
        4. Only adds CAPECs that are related to those CWEs

        Args:
            data: The enriched SBOM data containing vulnerability information
            *args: Optional positional args (supports legacy `fallback_to_all`)
            **kwargs: Optional keyword args (supports `fallback_to_all`)

        Returns:
            Dictionary with counts of added nodes: {'cwe_count': int, 'capec_count': int}
        """
        from ..resolver import CVECWEResolver

        sbom_data = data
        fallback_any = args[0] if args else kwargs.get("fallback_to_all", False)
        fallback_to_all = bool(fallback_any)

        # Step 1: Extract all CVE IDs from SBOM vulnerability data
        cve_ids = self.sbom_processor.extract_cve_ids_from_sbom(sbom_data)
        if not cve_ids:
            print("No CVE IDs found in SBOM vulnerability data")
            if fallback_to_all:
                return self._build_all_cwe_capec_fallback()
            return {"cwe_count": 0, "capec_count": 0}

        print(
            f"Found {len(cve_ids)} unique CVE IDs in SBOM: {list(cve_ids)[:5]}{'...' if len(cve_ids) > 5 else ''}"
        )

        try:
            # Step 2a: Get CWE IDs directly from vulnerability data (fast, no API calls)
            direct_cwe_ids = self.sbom_processor.extract_cwes_from_sbom_vulnerabilities(sbom_data)

            # Step 2b: Resolve CVE IDs to CWE IDs via NVD API (slower but more comprehensive)
            resolver = CVECWEResolver()
            cve_to_cwes = resolver.resolve_cves_to_cwes(list(cve_ids))

            # Collect all unique CWE IDs from both sources
            relevant_cwe_ids = set(direct_cwe_ids)
            for _cve_id, cwe_list in cve_to_cwes.items():
                relevant_cwe_ids.update(cwe_list)

            if direct_cwe_ids:
                print(
                    f"Found {len(direct_cwe_ids)} CWE IDs directly in vulnerability data: {list(direct_cwe_ids)[:3]}{'...' if len(direct_cwe_ids) > 3 else ''}"
                )

            nvd_cwe_count = sum(len(cwes) for cwes in cve_to_cwes.values())
            if nvd_cwe_count > 0:
                print(f"Found {nvd_cwe_count} additional CWE IDs from NVD API")

            if not relevant_cwe_ids:
                print("No CWE mappings found from either source")
                if fallback_to_all:
                    print("Falling back to loading basic CWE/CAPEC data...")
                    return self._build_all_cwe_capec_fallback()
                return {"cwe_count": 0, "capec_count": 0}

            print(
                f"Total unique CWE IDs: {len(relevant_cwe_ids)}: {list(relevant_cwe_ids)[:5]}{'...' if len(relevant_cwe_ids) > 5 else ''}"
            )

            # Step 3: Fetch and add only the relevant CWEs
            from ....intelligence.data_processing.cwe_parser import CWEParser

            cwe_parser = CWEParser()
            # Try to use parallel parsing if available
            try:
                all_cwe_data = cwe_parser.get_cwe_data_parallel()
            except AttributeError:
                # Fall back to sequential if parallel method not available
                all_cwe_data = cwe_parser.get_cwe_data()

            relevant_cwe_data = [cwe for cwe in all_cwe_data if cwe.get("id") in relevant_cwe_ids]

            # Add the relevant CWEs to the knowledge graph
            for cwe_data in relevant_cwe_data:
                self.add_node(KGNodeType.CWE, cwe_data["id"], cwe_data)

            # Step 4: Add CVE-CWE relationships
            for cve_id, cwe_list in cve_to_cwes.items():
                for cwe_id in cwe_list:
                    if cwe_id in relevant_cwe_ids:  # Only add edges for CWEs we actually added
                        self.add_edge(
                            KGNodeType.CVE,
                            cve_id,
                            KGNodeType.CWE,
                            cwe_id,
                            KGRelationshipType.HAS_CWE,
                        )

            # Step 5: Fetch and add only relevant CAPECs (those that target our CWEs)
            from ....intelligence.data_processing.capec_parser import CAPECParser

            capec_parser = CAPECParser()
            all_capec_data = capec_parser.get_capec_data()

            relevant_capec_data = [
                capec
                for capec in all_capec_data
                if any(cwe_id in relevant_cwe_ids for cwe_id in capec.get("related_cwes", []))
            ]

            # Add the relevant CAPECs to the knowledge graph
            for capec_data in relevant_capec_data:
                capec_id = capec_data.get("id")
                if capec_id:
                    self.add_node(KGNodeType.CAPEC, capec_id, capec_data)

                    # Add CAPEC-CWE relationships only for our relevant CWEs
                    for related_cwe in capec_data.get("related_cwes", []):
                        if related_cwe in relevant_cwe_ids:
                            self.add_edge(
                                KGNodeType.CAPEC,
                                capec_id,
                                KGNodeType.CWE,
                                related_cwe,
                                KGRelationshipType.EXPLOITS_CWE,
                            )

            return {
                "cwe_count": len(relevant_cwe_data),
                "capec_count": len(relevant_capec_data),
            }

        except Exception as e:
            print(f"Error in selective CWE/CAPEC building: {e}")
            if fallback_to_all:
                print("Falling back to loading basic CWE/CAPEC data...")
                return self._build_all_cwe_capec_fallback()
            raise

    def _build_all_cwe_capec_fallback(self) -> dict[str, int]:
        """Fallback method to build all CWE and CAPEC data (original behavior).

        Returns:
            Dictionary with counts of added nodes
        """
        try:
            from ....intelligence.data_processing.capec_parser import CAPECParser
            from ....intelligence.data_processing.cwe_parser import CWEParser

            # Add all CWE data
            cwe_parser = CWEParser()
            cwe_data = cwe_parser.get_cwe_data()
            cwe_count = 0
            if cwe_data:
                for cwe_item in cwe_data:
                    cwe_id = cwe_item.get("id")
                    if cwe_id:
                        self.add_node(KGNodeType.CWE, cwe_id, cwe_item)
                        cwe_count += 1

            # Add all CAPEC data
            capec_parser = CAPECParser()
            capec_data = capec_parser.get_capec_data()
            capec_count = 0
            if capec_data:
                for capec_item in capec_data:
                    capec_id = capec_item.get("id")
                    if capec_id:
                        self.add_node(KGNodeType.CAPEC, capec_id, capec_item)
                        capec_count += 1

                        for related_cwe in capec_item.get("related_cwes", []):
                            self.add_edge(
                                KGNodeType.CAPEC,
                                capec_id,
                                KGNodeType.CWE,
                                related_cwe,
                                KGRelationshipType.EXPLOITS_CWE,
                            )

            return {"cwe_count": cwe_count, "capec_count": capec_count}
        except Exception as e:
            print(f"Error in fallback CWE/CAPEC building: {e}")
            return {"cwe_count": 0, "capec_count": 0}
