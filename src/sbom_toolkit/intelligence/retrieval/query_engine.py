from typing import Any

from .knowledge_graph_manager import KnowledgeGraphManager


class QueryEngine:
    """
    Handles queries, searches, and data retrieval operations against the knowledge graph.
    Provides methods for filtering, searching, and aggregating data.
    """

    def __init__(self, kg_manager: KnowledgeGraphManager):
        """Initialize with a knowledge graph manager."""
        self.kg_manager = kg_manager

    def query_vulnerabilities(
        self, focus: str = "all", include_attack_patterns: bool = True
    ) -> dict[str, Any]:
        """Main vulnerability query function that provides comprehensive security data."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        # Get all vulnerable components
        vulnerable_components = []
        all_cves = []
        all_cwes = []
        all_capecs = []

        # Process vulnerable versions
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            if node.get("vulnerability_count", 0) > 0:
                component_name = node.get(
                    "component_id", node_id.split("@")[0] if "@" in node_id else node_id
                )
                version = node.get("version", "unknown")
                max_cvss = node.get("max_cvss_score", 0.0)
                vuln_count = node.get("vulnerability_count", 0)

                # Get CVEs for this version
                cves = []
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_VULNERABILITY":
                        cve_id = edge.get("target_id", "")
                        if cve_id.startswith("CVE-"):
                            cve_node = self.kg_manager.get_node(cve_id) or {}
                            cves.append(
                                {
                                    "cve_id": cve_id,
                                    "cvss_score": cve_node.get("cvss_score", 0.0),
                                    "severity": cve_node.get("cvss_severity", "unknown"),
                                    "description": cve_node.get("description", ""),
                                }
                            )
                            all_cves.append(cve_id)

                # Get CWEs for this version
                cwes = []
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_CWE":
                        cwe_id = edge.get("target_id", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_node = self.kg_manager.get_node(cwe_id) or {}
                            cwes.append(
                                {
                                    "cwe_id": cwe_id,
                                    "name": cwe_node.get("name", ""),
                                    "description": cwe_node.get("description", ""),
                                }
                            )
                            all_cwes.append(cwe_id)

                # Filter based on focus
                if focus == "critical" and max_cvss < 7.0:
                    continue

                vulnerable_components.append(
                    {
                        "component": component_name,
                        "version": version,
                        "version_id": node_id,
                        "vulnerability_count": vuln_count,
                        "max_cvss_score": max_cvss,
                        "cves": cves,
                        "cwes": cwes,
                        "purl": node.get("purl", ""),
                    }
                )

        # Get CAPEC attack patterns if requested
        if include_attack_patterns:
            for node_id, node in self.kg_manager.get_nodes_by_type("CAPEC").items():
                all_capecs.append(
                    {
                        "capec_id": node_id,
                        "name": node.get("name", ""),
                        "description": node.get("description", ""),
                    }
                )

        # Sort components by severity
        vulnerable_components.sort(key=lambda x: x["max_cvss_score"], reverse=True)

        # Create comprehensive result
        result = {
            "vulnerable_components": vulnerable_components,
            "summary": {
                "total_vulnerable_components": len(vulnerable_components),
                "total_cves": len(set(all_cves)),
                "total_cwes": len(set(all_cwes)),
                "total_capecs": len(all_capecs),
                "highest_cvss": max(
                    [c["max_cvss_score"] for c in vulnerable_components], default=0.0
                ),
                "focus": focus,
            },
            "all_cve_ids": list(set(all_cves)),
            "all_cwe_ids": list(set(all_cwes)),
            "attack_patterns": all_capecs if include_attack_patterns else [],
        }

        return result

    def get_vulnerable_components(
        self,
        min_severity_score: float = 0.0,
        limit: int = 10,
        include_paths: bool = True,
    ) -> dict[str, Any]:
        """Get vulnerable components with filtering."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        vulnerable_components = []
        all_cve_ids = set()
        all_cwe_ids = set()

        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            vuln_count = node.get("vulnerability_count", 0)
            max_cvss = node.get("max_cvss_score", 0)
            if vuln_count > 0 and max_cvss >= min_severity_score:
                component_name = node.get(
                    "component_id", node_id.split("@")[0] if "@" in node_id else node_id
                )

                # Gather all CVE IDs for this version node (version HAS_VULNERABILITY -> CVE)
                cve_ids = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "HAS_VULNERABILITY"
                    and edge.get("target_id", "").startswith("CVE-")
                ]

                # Gather all CWE IDs for this version node (version HAS_CWE -> CWE)
                cwe_ids = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "HAS_CWE"
                    and edge.get("target_id", "").startswith("CWE-")
                ]

                # Get dependency information for impact analysis
                dependency_count = len(
                    [
                        edge
                        for edge in self.kg_manager.get_edges_by_source(node_id)
                        if edge.get("type") == "DEPENDS_ON"
                    ]
                )
                dependent_count = len(
                    [
                        edge
                        for edge in self.kg_manager.get_edges_by_target(node_id)
                        if edge.get("type") == "DEPENDS_ON"
                    ]
                )

                # Add to global sets for comprehensive citations
                all_cve_ids.update(cve_ids)
                all_cwe_ids.update(cwe_ids)

                vulnerable_components.append(
                    {
                        "component": component_name,
                        "version": node.get("version", "unknown"),
                        "vulnerabilities": vuln_count,
                        "max_cvss_score": max_cvss,
                        "version_id": node_id,
                        "cve_ids": cve_ids,
                        "cwe_ids": cwe_ids,
                        "dependency_count": dependency_count,
                        "dependent_count": dependent_count,
                        "blast_radius_indicator": dependent_count,
                        "purl": node.get("purl", ""),
                    }
                )

        vulnerable_components.sort(
            key=lambda x: (x["max_cvss_score"], x["vulnerabilities"]), reverse=True
        )

        return {
            "components": vulnerable_components[:limit],  # Use expected key name
            "vulnerable_components": vulnerable_components[:limit],  # Keep both for compatibility
            "total_found": len(vulnerable_components),
            "filtered_by_severity": min_severity_score > 0,
            "include_paths": include_paths,
            "summary_statistics": {
                "total_vulnerable_components": len(vulnerable_components),
                "total_cves": len(all_cve_ids),
                "total_cwes": len(all_cwe_ids),
                "highest_cvss": max(
                    (c["max_cvss_score"] for c in vulnerable_components), default=0.0
                ),
                "critical_count": len(
                    [c for c in vulnerable_components if c["max_cvss_score"] >= 9.0]
                ),
                "high_count": len(
                    [c for c in vulnerable_components if 7.0 <= c["max_cvss_score"] < 9.0]
                ),
                "medium_count": len(
                    [c for c in vulnerable_components if 4.0 <= c["max_cvss_score"] < 7.0]
                ),
                "low_count": len([c for c in vulnerable_components if c["max_cvss_score"] < 4.0]),
            },
            "citations": {
                "all_cve_ids": sorted(all_cve_ids),
                "all_cwe_ids": sorted(all_cwe_ids),
                "cve_details": {
                    cve_id: {
                        "description": (self.kg_manager.get_node(cve_id) or {}).get(
                            "description", ""
                        ),
                        "cvss_score": (self.kg_manager.get_node(cve_id) or {}).get("cvss_score"),
                        "cvss_severity": (self.kg_manager.get_node(cve_id) or {}).get(
                            "cvss_severity"
                        ),
                        "summary": (self.kg_manager.get_node(cve_id) or {}).get("summary", ""),
                        "published": (self.kg_manager.get_node(cve_id) or {}).get("published", ""),
                    }
                    for cve_id in all_cve_ids
                },
                "cwe_details": {
                    cwe_id: {
                        "name": (self.kg_manager.get_node(cwe_id) or {}).get("name", ""),
                        "description": (
                            (self.kg_manager.get_node(cwe_id) or {}).get("description", "")[:200]
                            + "..."
                            if len((self.kg_manager.get_node(cwe_id) or {}).get("description", ""))
                            > 200
                            else (self.kg_manager.get_node(cwe_id) or {}).get("description", "")
                        ),
                    }
                    for cwe_id in all_cwe_ids
                },
                "evidence_source": "knowledge_graph_analysis",
                "analysis_scope": (
                    f"filtered_by_severity_{min_severity_score}"
                    if min_severity_score > 0
                    else "all_vulnerabilities"
                ),
            },
        }

    def get_sbom_overview(self) -> dict[str, Any]:
        """Get a high-level overview of the SBOM."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        overview: dict[str, Any] = {
            "total_components": len(self.kg_manager.get_nodes_by_type("Component")),
            "total_versions": len(self.kg_manager.get_nodes_by_type("Version")),
            "total_cves": len(self.kg_manager.get_nodes_by_type("CVE")),
            "total_cwes": len(self.kg_manager.get_nodes_by_type("CWE")),
            "total_capecs": len(self.kg_manager.get_nodes_by_type("CAPEC")),
            "vulnerable_components": 0,
            "total_vulnerabilities": 0,
            "highest_cvss": 0.0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_vulnerable_components": [],
            "ecosystems": [],
        }

        component_vulns = {}
        all_cve_ids = set()
        all_cwe_ids = set()
        all_capec_ids = set()
        critical_cves = []
        high_cves = []

        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            vuln_count = node.get("vulnerability_count", 0)
            max_cvss = node.get("max_cvss_score", 0)
            if vuln_count > 0:
                overview["vulnerable_components"] += 1
                overview["total_vulnerabilities"] += vuln_count
                overview["highest_cvss"] = max(overview["highest_cvss"], max_cvss)

                # Categorize vulnerabilities by severity
                if max_cvss >= 9.0:
                    overview["severity_distribution"]["CRITICAL"] += vuln_count
                elif max_cvss >= 7.0:
                    overview["severity_distribution"]["HIGH"] += vuln_count
                elif max_cvss >= 4.0:
                    overview["severity_distribution"]["MEDIUM"] += vuln_count
                else:
                    overview["severity_distribution"]["LOW"] += vuln_count

                component_name = node.get(
                    "component_id", node_id.split("@")[0] if "@" in node_id else node_id
                )
                if component_name not in component_vulns:
                    component_vulns[component_name] = {
                        "vulns": 0,
                        "max_cvss": 0,
                        "cve_ids": set(),
                    }
                component_vulns[component_name]["vulns"] += vuln_count
                component_vulns[component_name]["max_cvss"] = max(
                    component_vulns[component_name]["max_cvss"], max_cvss
                )

                # Add CVEs for this version and collect by severity (version HAS_VULNERABILITY -> CVE)
                cve_ids = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "HAS_VULNERABILITY"
                    and edge.get("target_id", "").startswith("CVE-")
                ]
                component_vulns[component_name]["cve_ids"].update(cve_ids)
                all_cve_ids.update(cve_ids)

                # Collect CVEs by severity for detailed citation
                for cve_id in cve_ids:
                    if cve_id is not None:
                        cve_node = self.kg_manager.get_node(cve_id) or {}
                        cvss_score = cve_node.get(
                            "cvss_score", max_cvss
                        )  # fallback to component max
                        if cvss_score is not None:
                            if cvss_score >= 9.0:
                                critical_cves.append(cve_id)
                            elif cvss_score >= 7.0:
                                high_cves.append(cve_id)

                # Add CWE IDs for this version
                cwe_ids = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "HAS_CWE"
                    and edge.get("target_id", "").startswith("CWE-")
                ]
                all_cwe_ids.update(cwe_ids)

        # Collect all CAPEC IDs from the knowledge graph
        for capec_id in self.kg_manager.get_nodes_by_type("CAPEC"):
            all_capec_ids.add(capec_id)

        top_vulns = sorted(
            component_vulns.items(),
            key=lambda x: (x[1]["vulns"], x[1]["max_cvss"]),
            reverse=True,
        )[:5]
        top_vulnerable_components: list[dict[str, Any]] = [
            {
                "component": comp,
                "vulnerabilities": data["vulns"],
                "max_cvss_score": data["max_cvss"],
                "cve_ids": sorted(data["cve_ids"]),
            }
            for comp, data in top_vulns
        ]
        overview["top_vulnerable_components"] = top_vulnerable_components

        for node_id, node in self.kg_manager.get_nodes_by_type("Ecosystem").items():
            overview["ecosystems"].append(
                {"name": node.get("name", node_id), "ecosystem_id": node_id}
            )

        # Add detailed CVE information for proper citations
        cve_details = {}
        for cve_id in all_cve_ids:
            cve_node = self.kg_manager.get_node(cve_id) or {}
            cve_details[cve_id] = {
                "description": cve_node.get("description", ""),
                "cvss_score": cve_node.get("cvss_score"),
                "cvss_severity": cve_node.get("cvss_severity"),
                "summary": cve_node.get("summary", ""),
                "published": cve_node.get("published", ""),
            }

        # Add detailed CWE information for proper citations
        cwe_details = {}
        for cwe_id in all_cwe_ids:
            cwe_node = self.kg_manager.get_node(cwe_id) or {}
            cwe_details[cwe_id] = {
                "name": cwe_node.get("name", ""),
                "description": (
                    cwe_node.get("description", "")[:200] + "..."
                    if len(cwe_node.get("description", "")) > 200
                    else cwe_node.get("description", "")
                ),
            }

        # Add detailed CAPEC information for proper citations
        capec_details = {}
        for capec_id in all_capec_ids:
            capec_node = self.kg_manager.get_node(capec_id) or {}
            capec_details[capec_id] = {
                "name": capec_node.get("name", ""),
                "description": (
                    capec_node.get("description", "")[:150] + "..."
                    if len(capec_node.get("description", "")) > 150
                    else capec_node.get("description", "")
                ),
            }

        # Add comprehensive citations and analysis metadata
        overview["citations"] = {
            "all_cve_ids": sorted(all_cve_ids),
            "all_cwe_ids": sorted(all_cwe_ids),
            "all_capec_ids": sorted(all_capec_ids),
            "critical_cves": sorted(critical_cves),
            "high_severity_cves": sorted(high_cves),
            "cve_details": cve_details,
            "cwe_details": cwe_details,
            "capec_details": capec_details,
            "evidence_source": "comprehensive_knowledge_graph_analysis",
            "node_type_counts": {
                "components": len(self.kg_manager.get_nodes_by_type("Component")),
                "versions": len(self.kg_manager.get_nodes_by_type("Version")),
                "cves": len(self.kg_manager.get_nodes_by_type("CVE")),
                "cwes": len(self.kg_manager.get_nodes_by_type("CWE")),
                "capecs": len(self.kg_manager.get_nodes_by_type("CAPEC")),
            },
        }

        # Add risk analysis summary
        overview["risk_analysis"] = {
            "risk_level": (
                "CRITICAL"
                if overview["highest_cvss"] >= 9.0
                else (
                    "HIGH"
                    if overview["highest_cvss"] >= 7.0
                    else "MEDIUM"
                    if overview["highest_cvss"] >= 4.0
                    else "LOW"
                )
            ),
            "vulnerability_density": overview["total_vulnerabilities"]
            / max(overview["total_components"], 1),
            "critical_component_ratio": len(
                [c for c in top_vulnerable_components if c["max_cvss_score"] >= 9.0]
            )
            / max(len(top_vulnerable_components), 1),
        }

        return overview

    def search_components_by_criteria(
        self,
        ecosystem: str | None = None,
        has_vulnerabilities: bool | None = None,
        min_dependents: int | None = None,
        risk_level: str | None = None,
    ) -> dict[str, Any]:
        """Search components by various criteria."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        matching_components = []
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            if ecosystem:
                component_purl = node.get("purl", "")
                if ecosystem.lower() not in component_purl.lower():
                    continue
            if has_vulnerabilities is not None:
                vuln_count = node.get("vulnerability_count", 0)
                if has_vulnerabilities and vuln_count == 0:
                    continue
                if not has_vulnerabilities and vuln_count > 0:
                    continue
            if min_dependents is not None:
                dependents_count = len(
                    [
                        edge
                        for edge in self.kg_manager.get_edges_by_target(node_id)
                        if edge.get("type") == "DEPENDS_ON"
                    ]
                )
                if dependents_count < min_dependents:
                    continue
            if risk_level:
                max_cvss = node.get("max_cvss_score", 0)
                if risk_level == "low" and max_cvss >= 4.0:
                    continue
                elif risk_level == "medium" and (max_cvss < 4.0 or max_cvss >= 7.0):
                    continue
                elif risk_level == "high" and (max_cvss < 7.0 or max_cvss >= 9.0):
                    continue
                elif risk_level == "critical" and max_cvss < 9.0:
                    continue
            component_name = node.get(
                "component_id", node_id.split("@")[0] if "@" in node_id else node_id
            )
            cve_ids = [
                edge.get("source_id")
                for edge in self.kg_manager.get_edges_by_target(node_id)
                if edge.get("type") == "HAS_VULNERABILITY"
                and edge.get("source_id", "").startswith("CVE-")
            ]
            cwe_ids = [
                edge.get("target_id")
                for edge in self.kg_manager.get_edges_by_source(node_id)
                if edge.get("type") == "HAS_CWE" and edge.get("target_id", "").startswith("CWE-")
            ]
            matching_components.append(
                {
                    "component": component_name,
                    "version": node.get("version", ""),
                    "vulnerabilities": node.get("vulnerability_count", 0),
                    "max_cvss_score": node.get("max_cvss_score", 0),
                    "purl": node.get("purl", ""),
                    "version_id": node_id,
                    "cve_ids": cve_ids,
                    "cwe_ids": cwe_ids,
                }
            )
        return {
            "matching_components": matching_components[:20],
            "total_found": len(matching_components),
            "search_criteria": {
                "ecosystem": ecosystem,
                "has_vulnerabilities": has_vulnerabilities,
                "min_dependents": min_dependents,
                "risk_level": risk_level,
            },
        }

    def list_available_parameters(
        self, limit: int = 20, include_versions: bool = True
    ) -> dict[str, Any]:
        """List all available component names and CVE IDs that can be used as parameters in other functions."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        available_params = []
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            component_name = node.get(
                "component_id", node_id.split("@")[0] if "@" in node_id else ""
            )
            cve_ids = [
                edge.get("target_id")
                for edge in self.kg_manager.get_edges_by_source(node_id)
                if edge.get("type") == "HAS_VULNERABILITY"
                and edge.get("target_id", "").startswith("CVE-")
            ]
            available_params.append(
                {
                    "component_name": component_name,
                    "cve_ids": cve_ids,
                    "version": node.get("version", "unknown"),
                }
            )
        return {
            "available_parameters": available_params[:limit],
            "total_found": len(available_params),
            "search_criteria": {
                "limit": limit,
                "include_versions": include_versions,
            },
        }

    def find_vulnerability_clusters(
        self, clustering_method: str = "cwe_based", min_cluster_size: int = 2
    ) -> dict[str, Any]:
        """Detect components that share similar vulnerability patterns."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        components_data = {}

        # Collect component vulnerability data
        for version_id, version_node in self.kg_manager.get_nodes_by_type("Version").items():
            if version_node.get("vulnerability_count", 0) == 0:
                continue

            component_name = version_node.get(
                "component_id", version_id.split("@")[0] if "@" in version_id else version_id
            )
            max_cvss = version_node.get("max_cvss_score", 0.0) or 0.0

            if component_name not in components_data:
                components_data[component_name] = {
                    "versions": [],
                    "all_cves": set(),
                    "all_cwes": set(),
                    "max_cvss": 0.0,
                    "total_vulnerabilities": 0,
                }

            # Get CVEs and CWEs for this version
            cves = set()
            cwes = set()

            for edge in self.kg_manager.get_edges_by_source(version_id):
                if edge.get("type") == "HAS_VULNERABILITY":
                    cve_id = edge.get("target_id", "")
                    if cve_id.startswith("CVE-"):
                        cves.add(cve_id)
                elif edge.get("type") == "HAS_CWE":
                    cwe_id = edge.get("target_id", "")
                    if cwe_id.startswith("CWE-"):
                        cwes.add(cwe_id)

            components_data[component_name]["versions"].append(
                {
                    "version": version_node.get("version", "unknown"),
                    "version_id": version_id,
                    "cvss": max_cvss,
                    "cves": cves,
                    "cwes": cwes,
                    "vulnerability_count": version_node.get("vulnerability_count", 0),
                }
            )
            components_data[component_name]["all_cves"].update(cves)
            components_data[component_name]["all_cwes"].update(cwes)
            components_data[component_name]["max_cvss"] = max(
                components_data[component_name]["max_cvss"], max_cvss
            )
            components_data[component_name]["total_vulnerabilities"] += version_node.get(
                "vulnerability_count", 0
            )

        # Generate clusters based on method
        clusters = []
        component_names = list(components_data.keys())

        if clustering_method == "cwe_based":
            clusters = self._cluster_by_cwe_similarity(
                components_data, component_names, min_cluster_size
            )
        elif clustering_method == "severity_based":
            clusters = self._cluster_by_severity_ranges(
                components_data, component_names, min_cluster_size
            )
        elif clustering_method == "pattern_based":
            clusters = self._cluster_by_vulnerability_patterns(
                components_data, component_names, min_cluster_size
            )

        return {
            "vulnerability_clusters": clusters,
            "clustering_method": clustering_method,
            "min_cluster_size": min_cluster_size,
            "summary": {
                "total_clusters": len(clusters),
                "total_components_analyzed": len(components_data),
                "average_cluster_size": sum(len(c["components"]) for c in clusters) / len(clusters)
                if clusters
                else 0,
                "largest_cluster_size": max(len(c["components"]) for c in clusters)
                if clusters
                else 0,
            },
        }

    def _cluster_by_cwe_similarity(
        self, components_data: dict, component_names: list, min_cluster_size: int
    ) -> list[dict]:
        """Cluster components by CWE similarity."""
        clusters = []
        processed_components = set()

        for i, comp1 in enumerate(component_names):
            if comp1 in processed_components:
                continue

            cluster_components = [comp1]
            comp1_cwes = components_data[comp1]["all_cwes"]

            for _j, comp2 in enumerate(component_names[i + 1 :], i + 1):
                if comp2 in processed_components:
                    continue

                comp2_cwes = components_data[comp2]["all_cwes"]

                # Calculate CWE similarity (Jaccard index)
                intersection = len(comp1_cwes & comp2_cwes)
                union = len(comp1_cwes | comp2_cwes)
                similarity = intersection / union if union > 0 else 0

                # Group components with > 30% CWE similarity
                if similarity > 0.3:
                    cluster_components.append(comp2)
                    processed_components.add(comp2)

            if len(cluster_components) >= min_cluster_size:
                # Calculate cluster metadata
                all_cluster_cwes = set()
                all_cluster_cves = set()
                max_cluster_cvss = 0.0
                total_vulnerabilities = 0

                for comp in cluster_components:
                    all_cluster_cwes.update(components_data[comp]["all_cwes"])
                    all_cluster_cves.update(components_data[comp]["all_cves"])
                    max_cluster_cvss = max(max_cluster_cvss, components_data[comp]["max_cvss"])
                    total_vulnerabilities += components_data[comp]["total_vulnerabilities"]

                clusters.append(
                    {
                        "cluster_id": f"cwe_cluster_{len(clusters) + 1}",
                        "components": cluster_components,
                        "shared_cwes": list(
                            comp1_cwes
                            & set().union(
                                *[components_data[c]["all_cwes"] for c in cluster_components[1:]]
                            )
                        )
                        if len(cluster_components) > 1
                        else list(comp1_cwes),
                        "all_cwes": list(all_cluster_cwes),
                        "all_cves": list(all_cluster_cves),
                        "cluster_size": len(cluster_components),
                        "max_cvss_score": max_cluster_cvss,
                        "total_vulnerabilities": total_vulnerabilities,
                        "risk_level": "high"
                        if max_cluster_cvss >= 7.0
                        else "medium"
                        if max_cluster_cvss >= 4.0
                        else "low",
                    }
                )
                processed_components.update(cluster_components)

        return clusters

    def _cluster_by_severity_ranges(
        self, components_data: dict, component_names: list, min_cluster_size: int
    ) -> list[dict]:
        """Cluster components by CVSS severity ranges."""
        severity_groups = {
            "critical": [],  # 9.0-10.0
            "high": [],  # 7.0-8.9
            "medium": [],  # 4.0-6.9
            "low": [],  # 0.0-3.9
        }

        for comp_name in component_names:
            max_cvss = components_data[comp_name]["max_cvss"]
            if max_cvss >= 9.0:
                severity_groups["critical"].append(comp_name)
            elif max_cvss >= 7.0:
                severity_groups["high"].append(comp_name)
            elif max_cvss >= 4.0:
                severity_groups["medium"].append(comp_name)
            else:
                severity_groups["low"].append(comp_name)

        clusters = []
        for severity, components in severity_groups.items():
            if len(components) >= min_cluster_size:
                all_cwes = set()
                all_cves = set()
                total_vulnerabilities = 0
                max_cvss = 0.0

                for comp in components:
                    all_cwes.update(components_data[comp]["all_cwes"])
                    all_cves.update(components_data[comp]["all_cves"])
                    total_vulnerabilities += components_data[comp]["total_vulnerabilities"]
                    max_cvss = max(max_cvss, components_data[comp]["max_cvss"])

                clusters.append(
                    {
                        "cluster_id": f"severity_{severity}_cluster",
                        "components": components,
                        "severity_range": severity,
                        "all_cwes": list(all_cwes),
                        "all_cves": list(all_cves),
                        "cluster_size": len(components),
                        "max_cvss_score": max_cvss,
                        "total_vulnerabilities": total_vulnerabilities,
                        "risk_level": severity,
                    }
                )

        return clusters

    def _cluster_by_vulnerability_patterns(
        self, components_data: dict, component_names: list, min_cluster_size: int
    ) -> list[dict]:
        """Cluster components by vulnerability patterns (combination of CVE and CWE patterns)."""
        clusters = []
        processed_components = set()

        for i, comp1 in enumerate(component_names):
            if comp1 in processed_components:
                continue

            cluster_components = [comp1]
            comp1_cves = components_data[comp1]["all_cves"]
            comp1_cwes = components_data[comp1]["all_cwes"]

            for _j, comp2 in enumerate(component_names[i + 1 :], i + 1):
                if comp2 in processed_components:
                    continue

                comp2_cves = components_data[comp2]["all_cves"]
                comp2_cwes = components_data[comp2]["all_cwes"]

                # Calculate pattern similarity (weighted combination of CVE and CWE similarity)
                cve_intersection = len(comp1_cves & comp2_cves)
                cve_union = len(comp1_cves | comp2_cves)
                cve_similarity = cve_intersection / cve_union if cve_union > 0 else 0

                cwe_intersection = len(comp1_cwes & comp2_cwes)
                cwe_union = len(comp1_cwes | comp2_cwes)
                cwe_similarity = cwe_intersection / cwe_union if cwe_union > 0 else 0

                # Weighted pattern similarity (CWE patterns are more important for patterns)
                pattern_similarity = (0.7 * cwe_similarity) + (0.3 * cve_similarity)

                if pattern_similarity > 0.25:  # 25% pattern similarity threshold
                    cluster_components.append(comp2)
                    processed_components.add(comp2)

            if len(cluster_components) >= min_cluster_size:
                all_cluster_cwes = set()
                all_cluster_cves = set()
                max_cluster_cvss = 0.0
                total_vulnerabilities = 0

                for comp in cluster_components:
                    all_cluster_cwes.update(components_data[comp]["all_cwes"])
                    all_cluster_cves.update(components_data[comp]["all_cves"])
                    max_cluster_cvss = max(max_cluster_cvss, components_data[comp]["max_cvss"])
                    total_vulnerabilities += components_data[comp]["total_vulnerabilities"]

                # Identify common patterns
                shared_cves = comp1_cves.copy()
                shared_cwes = comp1_cwes.copy()
                for comp in cluster_components[1:]:
                    shared_cves &= components_data[comp]["all_cves"]
                    shared_cwes &= components_data[comp]["all_cwes"]

                clusters.append(
                    {
                        "cluster_id": f"pattern_cluster_{len(clusters) + 1}",
                        "components": cluster_components,
                        "shared_patterns": {
                            "common_cves": list(shared_cves),
                            "common_cwes": list(shared_cwes),
                        },
                        "all_cwes": list(all_cluster_cwes),
                        "all_cves": list(all_cluster_cves),
                        "cluster_size": len(cluster_components),
                        "max_cvss_score": max_cluster_cvss,
                        "total_vulnerabilities": total_vulnerabilities,
                        "risk_level": "high"
                        if max_cluster_cvss >= 7.0
                        else "medium"
                        if max_cluster_cvss >= 4.0
                        else "low",
                    }
                )
                processed_components.update(cluster_components)

        return clusters
