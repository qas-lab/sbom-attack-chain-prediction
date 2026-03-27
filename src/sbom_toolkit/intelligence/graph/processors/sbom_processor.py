import logging
from typing import Any
from urllib.parse import urlparse

from ....shared.component_utils import ComponentProcessor
from ..schema import KGNodeType, KGRelationshipType
from .base_processor import BaseProcessor


class SBOMProcessor(BaseProcessor):
    """Processor for SBOM data."""

    def __init__(self, builder):
        """Initialize SBOM processor with component processing capabilities."""
        super().__init__(builder)
        self.component_processor = ComponentProcessor()
        self.logger = logging.getLogger(__name__)

    def process(self, data: Any, *args: Any, **kwargs: Any) -> str:
        """Builds graph components from SBOM data.

        Args:
            data: SBOM data in CycloneDX format
            *args: Optional positional args (supports legacy `sbom_id`)
            **kwargs: Optional keyword args (supports `sbom_id`)

        Returns:
            The SBOM ID that was used
        """
        sbom_data = data
        sbom_id_any = args[0] if args else kwargs.get("sbom_id")
        sbom_id = sbom_id_any if isinstance(sbom_id_any, str) or sbom_id_any is None else None

        # Generate SBOM ID if not provided
        if not sbom_id:
            import hashlib
            import json

            sbom_content = json.dumps(sbom_data, sort_keys=True)
            sbom_id = f"sbom_{hashlib.md5(sbom_content.encode()).hexdigest()[:8]}"

        # Add SBOM node
        sbom_properties = {
            "bomFormat": sbom_data.get("bomFormat", "CycloneDX"),
            "specVersion": sbom_data.get("specVersion", "1.4"),
            "serialNumber": sbom_data.get("serialNumber"),
            "version": sbom_data.get("version", 1),
            "metadata": sbom_data.get("metadata", {}),
            "created_at": sbom_data.get("metadata", {}).get("timestamp"),
        }
        self.add_node(KGNodeType.SBOM, sbom_id, sbom_properties)

        # Add repository information if available
        self._process_repository_info(sbom_data, sbom_id)

        # Process components with enhanced filtering and normalization
        components = sbom_data.get("components", [])

        # Apply component processing improvements
        # Use parallel processing if available and beneficial
        try:
            processed_components, stats = self.component_processor.process_components_parallel(
                components,
                filter_files=True,  # Filter out file components like requirements.txt
                standardize_types=True,  # Standardize component types (library -> framework)
                batch_size=50,  # Process in batches of 50
            )
        except AttributeError:
            # Fall back to sequential if parallel method not available
            processed_components, stats = self.component_processor.process_components(
                components,
                filter_files=True,
                standardize_types=True,
            )

        self.logger.debug(
            f"SBOM component processing: {stats['original_count']} → {stats['final_count']} "
            f"(filtered: {stats['filtered_count']}, type changes: {stats.get('type_changes', 0)})"
        )

        for component in processed_components:
            self._process_sbom_component(component, sbom_id)

        # Process dependencies
        dependencies = sbom_data.get("dependencies", [])
        self._process_sbom_dependencies(dependencies)

        return sbom_id

    def _process_repository_info(self, sbom_data: dict[str, Any], sbom_id: str):
        """Process repository metadata and add to graph."""
        metadata = sbom_data.get("metadata", {})
        repository = metadata.get("repository", {})

        if not repository:
            return

        repo_url = repository.get("url", "")
        repo_name = repository.get("name", "")
        repo_owner = repository.get("owner", "")

        if repo_url:
            repo_id = self._extract_repo_id_from_url(repo_url)
            if repo_id:
                repo_properties = {
                    "url": repo_url,
                    "name": repo_name,
                    "owner": repo_owner,
                    "commit": repository.get("commit", ""),
                    "latest_tag": repository.get("latest_tag", ""),
                }

                self.add_node(KGNodeType.REPOSITORY, repo_id, repo_properties)
                self.add_edge(
                    KGNodeType.SBOM,
                    sbom_id,
                    KGNodeType.REPOSITORY,
                    repo_id,
                    KGRelationshipType.SCANNED_FROM_REPOSITORY,
                )

    def _process_sbom_component(self, component: dict[str, Any], sbom_id: str):
        """Process a single SBOM component and add it to the graph."""
        component_name = component.get("name", "")
        component_version = component.get("version", "")
        purl = component.get("purl", "")

        if not component_name:
            return

        # Use normalized component name for consistency
        normalized_name = self.component_processor.normalizer.normalize_name(component_name)

        # Extract ecosystem and component info from PURL
        ecosystem = "unknown"
        component_base_id = normalized_name  # Use normalized name for ID

        if purl:
            ecosystem, extracted_id = self._parse_purl_for_component_info(purl)
            # Use the normalized version of the extracted ID
            component_base_id = self.component_processor.normalizer.normalize_name(extracted_id)

        # Add ecosystem node
        self.add_node(KGNodeType.ECOSYSTEM, ecosystem, {"name": ecosystem})

        # Add component node (without version) - using standardized type
        component_properties = {
            "name": component_name,  # Keep original name for display
            "normalized_name": normalized_name,  # Add normalized name for matching
            "ecosystem": ecosystem,
            "component_type": component.get("type", "library"),  # This is already standardized
            "description": component.get("description", ""),
            "purl_base": purl.split("@")[0] if "@" in purl else purl,
        }
        self.add_node(KGNodeType.COMPONENT, component_base_id, component_properties)
        self.add_edge(
            KGNodeType.COMPONENT,
            component_base_id,
            KGNodeType.ECOSYSTEM,
            ecosystem,
            KGRelationshipType.BELONGS_TO_ECOSYSTEM,
        )

        # Add version node if version exists
        if component_version:
            self._process_component_version(
                component, component_base_id, component_version, sbom_id
            )
        else:
            # Connect SBOM to component (no version)
            self.add_edge(
                KGNodeType.SBOM,
                sbom_id,
                KGNodeType.COMPONENT,
                component_base_id,
                KGRelationshipType.CONTAINS_COMPONENT,
            )

        # Process licenses
        self._process_component_licenses(component, component_base_id, component_version)

    def _process_component_version(
        self,
        component: dict[str, Any],
        component_base_id: str,
        component_version: str,
        sbom_id: str,
    ):
        """Process a component version and its vulnerabilities."""
        version_id = f"{component_base_id}@{component_version}"
        purl = component.get("purl", "")

        version_properties = {
            "version": component_version,
            "component_id": component_base_id,
            "purl": purl,
            "bom_ref": component.get("bom-ref", ""),
        }

        # Calculate vulnerability statistics
        vulnerabilities = component.get("vulnerabilities", [])
        if vulnerabilities:
            # Filter out None values and get numeric scores
            cvss_scores = [
                v.get("cvss_score", 0) for v in vulnerabilities if v.get("cvss_score") is not None
            ]
            max_cvss = max(cvss_scores) if cvss_scores else 0

            version_properties.update(
                {
                    "is_vulnerable": True,
                    "vulnerability_count": len(vulnerabilities),
                    "max_cvss_score": max_cvss,
                }
            )
        else:
            version_properties.update(
                {
                    "is_vulnerable": False,
                    "vulnerability_count": 0,
                    "max_cvss_score": 0,
                }
            )

        self.add_node(KGNodeType.VERSION, version_id, version_properties)
        self.add_edge(
            KGNodeType.COMPONENT,
            component_base_id,
            KGNodeType.VERSION,
            version_id,
            KGRelationshipType.HAS_VERSION,
        )

        # Connect SBOM to version
        self.add_edge(
            KGNodeType.SBOM,
            sbom_id,
            KGNodeType.VERSION,
            version_id,
            KGRelationshipType.CONTAINS_COMPONENT,
        )

        # Process vulnerabilities
        for vuln in vulnerabilities:
            self._process_component_vulnerability(version_id, vuln)

    def _process_component_vulnerability(self, version_id: str, vulnerability: dict[str, Any]):
        """Process a component vulnerability and connect it to the version."""
        # Handle both OSV-scanner format (id) and Grype format (cve_id)
        vuln_id = vulnerability.get("cve_id") or vulnerability.get("id", "")
        if not vuln_id:
            return

        # Add vulnerability node
        # Handle date fields with proper null checking
        # Provide reasonable defaults for missing date fields
        published_date = vulnerability.get("published_date") or "1970-01-01T00:00:00Z"
        modified_date = vulnerability.get("modified_date") or "1970-01-01T00:00:00Z"

        # Handle CVSS score properly - preserve None for missing scores
        cvss_score = vulnerability.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        vuln_properties = {
            "id": vuln_id,
            "severity": vulnerability.get("cvss_severity", ""),
            "cvss_score": cvss_score,  # Use None instead of 0 for missing scores
            "cvss_version": vulnerability.get("cvss_version"),
            "cvss_vector": vulnerability.get("cvss_vector", ""),
            "cvss_severity": vulnerability.get("cvss_severity", ""),
            "all_cvss_metrics": vulnerability.get("all_cvss_metrics", {}),
            "description": vulnerability.get("description", ""),
            "published": published_date,
            "lastModified": modified_date,
        }

        self.add_node(KGNodeType.CVE, vuln_id, vuln_properties)
        self.add_edge(
            KGNodeType.VERSION,
            version_id,
            KGNodeType.CVE,
            vuln_id,
            KGRelationshipType.HAS_VULNERABILITY,
        )

    def _process_component_licenses(
        self, component: dict[str, Any], component_base_id: str, component_version: str | None
    ):
        """Process component license information."""
        licenses = component.get("licenses", [])
        if not licenses:
            return

        for license_info in licenses:
            license_id = None
            license_name = None

            if isinstance(license_info, dict):
                license_data = license_info.get("license", {})
                if isinstance(license_data, dict):
                    license_id = license_data.get("id", "")
                    license_name = license_data.get("name", "")
                elif isinstance(license_data, str):
                    license_id = license_data
                    license_name = license_data
            elif isinstance(license_info, str):
                license_id = license_info
                license_name = license_info

            if license_id:
                license_properties = {
                    "id": license_id,
                    "name": license_name or license_id,
                }

                self.add_node(KGNodeType.LICENSE, license_id, license_properties)

                # Connect to component or version
                if component_version:
                    version_id = f"{component_base_id}@{component_version}"
                    self.add_edge(
                        KGNodeType.VERSION,
                        version_id,
                        KGNodeType.LICENSE,
                        license_id,
                        KGRelationshipType.HAS_LICENSE,
                    )
                else:
                    self.add_edge(
                        KGNodeType.COMPONENT,
                        component_base_id,
                        KGNodeType.LICENSE,
                        license_id,
                        KGRelationshipType.HAS_LICENSE,
                    )

    def _process_sbom_dependencies(self, dependencies: list[dict[str, Any]]):
        """Process dependency relationships from SBOM."""
        for dep in dependencies:
            source_ref = dep.get("ref", "")
            depends_on = dep.get("dependsOn", [])

            if not source_ref or not depends_on:
                continue

            # Find the source component/version using enhanced lookup
            source_id = self._find_node_id_by_bom_ref(source_ref)
            if not source_id:
                continue

            for target_ref in depends_on:
                target_id = self._find_node_id_by_bom_ref(target_ref)
                if target_id:
                    # Determine if it's a direct dependency (simple heuristic)
                    is_direct = len(depends_on) <= 10  # Assume direct deps have fewer connections

                    dependency_properties = {
                        "is_direct": is_direct,
                        "source_bom_ref": source_ref,
                        "target_bom_ref": target_ref,
                    }

                    self.add_edge(
                        KGNodeType.VERSION,
                        source_id,
                        KGNodeType.VERSION,
                        target_id,
                        KGRelationshipType.DEPENDS_ON,
                        dependency_properties,
                    )

    def _find_node_id_by_bom_ref(self, bom_ref: str) -> str | None:
        """Find a node ID by its bom-ref value using enhanced normalization."""
        # Search through VERSION nodes for matching bom_ref
        for version_id, version_data in self.builder.nodes[KGNodeType.VERSION].items():
            if version_data.get("bom_ref") == bom_ref:
                return version_id

        # Fallback: try to extract from bom_ref directly if it looks like a PURL
        if bom_ref.startswith("pkg:"):
            ecosystem, component_id = self._parse_purl_for_component_info(bom_ref)
            # Normalize the component ID for consistent matching
            normalized_component_id = self.component_processor.normalizer.normalize_name(
                component_id
            )

            # Try to find version
            if "@" in bom_ref:
                version = bom_ref.split("@")[-1]
                version_id = f"{normalized_component_id}@{version}"
                if version_id in self.builder.nodes[KGNodeType.VERSION]:
                    return version_id

        return None

    def extract_cve_ids_from_sbom(self, sbom_data: dict[str, Any]) -> set[str]:
        """Extract all unique CVE IDs from SBOM vulnerability data.

        Args:
            sbom_data: The enriched SBOM data

        Returns:
            Set of unique CVE IDs found in the SBOM
        """
        cve_ids = set()

        # Check component-level vulnerabilities
        for component in sbom_data.get("components", []):
            for vuln in component.get("vulnerabilities", []):
                cve_id = vuln.get("cve_id")
                if cve_id and cve_id.startswith("CVE-"):
                    cve_ids.add(cve_id)

        # Check top-level vulnerabilities (if any)
        for vuln in sbom_data.get("vulnerabilities", []):
            cve_id = vuln.get("cve_id") or vuln.get("id")
            if cve_id and cve_id.startswith("CVE-"):
                cve_ids.add(cve_id)

        return cve_ids

    def extract_cwes_from_sbom_vulnerabilities(self, sbom_data: dict[str, Any]) -> set[str]:
        """Extract all unique CWE IDs from SBOM vulnerability data.

        Args:
            sbom_data: The enriched SBOM data containing vulnerability information

        Returns:
            Set of unique CWE IDs found in the SBOM vulnerability data
        """
        cwe_ids = set()

        # Check component-level vulnerabilities
        for component in sbom_data.get("components", []):
            for vuln in component.get("vulnerabilities", []):
                vuln_cwe_ids = vuln.get("cwe_ids", [])
                if isinstance(vuln_cwe_ids, list):
                    for cwe_id in vuln_cwe_ids:
                        if cwe_id and cwe_id.startswith("CWE-"):
                            cwe_ids.add(cwe_id)

        # Check top-level vulnerabilities (if any)
        for vuln in sbom_data.get("vulnerabilities", []):
            vuln_cwe_ids = vuln.get("cwe_ids", [])
            if isinstance(vuln_cwe_ids, list):
                for cwe_id in vuln_cwe_ids:
                    if cwe_id and cwe_id.startswith("CWE-"):
                        cwe_ids.add(cwe_id)

        return cwe_ids

    def _extract_repo_id_from_url(self, url: str) -> str | None:
        """Extract repository ID from URL."""
        try:
            parsed = urlparse(url)
            path = parsed.path.strip("/")
            if "/" in path:
                owner, name = path.split("/", 1)
                return f"{owner}/{name.replace('.git', '')}"
        except Exception:
            pass
        return None

    def _parse_purl_for_component_info(self, purl: str) -> tuple[str, str]:
        """Parse PURL to extract ecosystem and component information."""
        try:
            # Basic PURL parsing: pkg:type/namespace/name@version
            if purl.startswith("pkg:"):
                parts = purl[4:].split("/")  # Remove 'pkg:' prefix
                if parts:
                    ecosystem = parts[0].split("@")[0]  # Remove version from type

                    # Extract component name (last part before version)
                    if len(parts) >= 3:  # pkg:type/namespace/name
                        component_name = parts[-1].split("@")[0]
                    elif len(parts) == 2:  # pkg:type/name
                        component_name = parts[1].split("@")[0]
                    else:
                        component_name = "unknown"

                    return ecosystem, component_name
        except Exception:
            pass

        return "unknown", "unknown"
