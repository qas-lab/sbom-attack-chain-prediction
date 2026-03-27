from typing import Any

from .knowledge_graph_manager import KnowledgeGraphManager


class ComponentAnalyzer:
    """
    Handles component-specific analysis including vulnerability details, dependency analysis,
    and component intelligence gathering.
    """

    def __init__(self, kg_manager: KnowledgeGraphManager):
        """Initialize with a knowledge graph manager."""
        self.kg_manager = kg_manager

    def analyze_component(self, component_name: str) -> dict[str, Any]:
        """Analyze a specific component in detail."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        component_info: dict[str, Any] = {
            "component_name": component_name,
            "versions": [],
            "total_vulnerabilities": 0,
            "cves": [],
            "cwes": [],
            "dependencies": [],
            "dependents": [],
        }

        # Find all versions of this component
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            node_component = node.get(
                "component_id", node_id.split("@")[0] if "@" in node_id else node_id
            )
            if node_component.lower() == component_name.lower():
                version_info: dict[str, Any] = {
                    "version": node.get("version", "unknown"),
                    "version_id": node_id,
                    "vulnerability_count": node.get("vulnerability_count", 0),
                    "max_cvss_score": node.get("max_cvss_score", 0.0),
                    "is_vulnerable": node.get("is_vulnerable", False),
                    "cves": [],
                }

                # Get CVEs for this version
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_VULNERABILITY":
                        cve_id = edge.get("target_id", "")
                        if cve_id.startswith("CVE-"):
                            cve_node = self.kg_manager.get_node(cve_id) or {}
                            cve_info = {
                                "cve_id": cve_id,
                                "cvss_score": cve_node.get("cvss_score", 0.0),
                                "severity": cve_node.get("cvss_severity", "unknown"),
                                "description": cve_node.get("description", ""),
                            }
                            version_info["cves"].append(cve_info)
                            component_info["cves"].append(cve_info)

                # Get CWEs for this version
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_CWE":
                        cwe_id = edge.get("target_id", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_node = self.kg_manager.get_node(cwe_id) or {}
                            cwe_info = {
                                "cwe_id": cwe_id,
                                "name": cwe_node.get("name", ""),
                                "description": cwe_node.get("description", ""),
                            }
                            component_info["cwes"].append(cwe_info)

                component_info["versions"].append(version_info)
                component_info["total_vulnerabilities"] += version_info["vulnerability_count"]

        # Remove duplicates
        component_info["cves"] = list(
            {cve["cve_id"]: cve for cve in component_info["cves"]}.values()
        )
        component_info["cwes"] = list(
            {cwe["cwe_id"]: cwe for cwe in component_info["cwes"]}.values()
        )

        # Sort by severity
        component_info["cves"].sort(key=lambda x: x["cvss_score"], reverse=True)
        component_info["versions"].sort(key=lambda x: x["max_cvss_score"], reverse=True)

        return component_info

    def get_cve_analysis(self, cve_id: str) -> dict[str, Any]:
        """Get comprehensive analysis of a specific CVE."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        cve_node = self.kg_manager.get_node(cve_id)
        if not cve_node:
            return {"error": f"CVE {cve_id} not found in knowledge graph"}

        analysis: dict[str, Any] = {
            "cve_id": cve_id,
            "cvss_score": cve_node.get("cvss_score", 0.0),
            "severity": cve_node.get("cvss_severity", "unknown"),
            "description": cve_node.get("description", ""),
            "affected_components": [],
            "related_cwes": [],
            "attack_patterns": [],
        }

        # Find affected components
        for edge in self.kg_manager.get_edges_by_target(cve_id):
            if edge.get("type") == "HAS_VULNERABILITY":
                version_id = edge.get("source_id", "")
                version_node = self.kg_manager.get_node(version_id)
                if version_node:
                    component_name = version_node.get(
                        "component_id",
                        version_id.split("@")[0] if "@" in version_id else version_id,
                    )
                    analysis["affected_components"].append(
                        {
                            "component": component_name,
                            "version": version_node.get("version", "unknown"),
                            "version_id": version_id,
                        }
                    )

        # Find related CWEs
        for edge in self.kg_manager.get_edges_by_source(cve_id):
            if edge.get("type") == "HAS_CWE":
                cwe_id = edge.get("target_id", "")
                cwe_node = self.kg_manager.get_node(cwe_id)
                if cwe_node:
                    analysis["related_cwes"].append(
                        {
                            "cwe_id": cwe_id,
                            "name": cwe_node.get("name", ""),
                            "description": cwe_node.get("description", ""),
                        }
                    )

        # Find related attack patterns
        for cwe_info in analysis["related_cwes"]:
            cwe_id = cwe_info["cwe_id"]
            for edge in self.kg_manager.get_edges_by_source(cwe_id):
                if edge.get("type") == "CAPEC_EXPLOITS_CWE":
                    capec_id = edge.get("source_id", "")
                    capec_node = self.kg_manager.get_node(capec_id)
                    if capec_node:
                        analysis["attack_patterns"].append(
                            {
                                "capec_id": capec_id,
                                "name": capec_node.get("name", ""),
                                "description": capec_node.get("description", ""),
                            }
                        )

        return analysis

    def get_component_details(
        self, component_name: str, include_dependents: bool = True
    ) -> dict[str, Any]:
        """Get detailed information about a specific component."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        component_summary: dict[str, Any] = {
            "component_name": component_name,
            "total_versions": 0,
            "vulnerable_versions": 0,
            "total_vulnerabilities": 0,
            "max_cvss_score": 0.0,
            "versions": [],
        }

        all_cve_ids = set()
        all_cwe_ids = set()
        all_capec_ids = set()
        all_dependents = set()
        all_dependencies = set()
        version_risk_analysis: dict[str, dict[str, Any]] = {}

        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            component_id = node.get("component_id", node_id.split("@")[0] if "@" in node_id else "")
            if (
                component_name.lower() in component_id.lower()
                or component_name.lower() in node_id.lower()
            ):
                vuln_count = node.get("vulnerability_count", 0)
                max_cvss = node.get("max_cvss_score", 0)

                # CVEs for this version (version HAS_VULNERABILITY -> CVE)
                cve_ids = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "HAS_VULNERABILITY"
                    and edge.get("target_id", "").startswith("CVE-")
                ]
                all_cve_ids.update(cve_ids)

                # CWEs for this version
                cwe_ids = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "HAS_CWE"
                    and edge.get("target_id", "").startswith("CWE-")
                ]
                all_cwe_ids.update(cwe_ids)

                # Find CAPEC patterns for the CWEs
                version_capecs = set()
                for cwe_id in cwe_ids:
                    if cwe_id is not None:
                        capec_patterns = [
                            edge.get("target_id")
                            for edge in self.kg_manager.get_edges_by_source(cwe_id)
                            if edge.get("type") == "EXPLOITS_CWE"
                            and edge.get("target_id", "").startswith("CAPEC-")
                        ]
                        version_capecs.update(capec_patterns)
                all_capec_ids.update(version_capecs)

                # Dependencies for this version
                dependencies = [
                    edge.get("target_id")
                    for edge in self.kg_manager.get_edges_by_source(node_id)
                    if edge.get("type") == "DEPENDS_ON"
                ]
                all_dependencies.update(dependencies)

                # Dependents for this version (blast radius)
                dependents = [
                    edge.get("source_id")
                    for edge in self.kg_manager.get_edges_by_target(node_id)
                    if edge.get("type") == "DEPENDS_ON"
                ]
                all_dependents.update(dependents)

                # Calculate risk metrics for this version
                risk_score = vuln_count * max_cvss if max_cvss > 0 else 0
                blast_radius = len(dependents)
                dependency_depth = len(dependencies)

                version_risk_analysis[node_id] = {
                    "risk_score": risk_score,
                    "blast_radius": blast_radius,
                    "dependency_depth": dependency_depth,
                    "criticality": (
                        "CRITICAL"
                        if max_cvss >= 9.0
                        else "HIGH"
                        if max_cvss >= 7.0
                        else "MEDIUM"
                        if max_cvss >= 4.0
                        else "LOW"
                    ),
                }

                version_info: dict[str, Any] = {
                    "version": node.get("version", "unknown"),
                    "version_id": node_id,
                    "vulnerabilities": vuln_count,
                    "max_cvss_score": max_cvss,
                    "is_vulnerable": node.get("is_vulnerable", False),
                    "purl": node.get("purl", ""),
                    "cve_ids": cve_ids,
                    "cwe_ids": cwe_ids,
                    "capec_ids": sorted(version_capecs),
                    "dependencies": dependencies,
                    "dependents": dependents,
                    "blast_radius": blast_radius,
                    "dependency_depth": dependency_depth,
                    "risk_score": risk_score,
                    "criticality": version_risk_analysis[node_id]["criticality"],
                }

                component_summary["versions"].append(version_info)
                component_summary["total_versions"] += 1
                component_summary["total_vulnerabilities"] += vuln_count
                component_summary["max_cvss_score"] = max(
                    component_summary["max_cvss_score"], max_cvss
                )

                if vuln_count > 0:
                    component_summary["vulnerable_versions"] += 1

        # Calculate aggregate risk analysis
        if component_summary["versions"]:
            total_blast_radius = sum(v["blast_radius"] for v in component_summary["versions"])
            max_blast_radius = max(v["blast_radius"] for v in component_summary["versions"])
            avg_dependency_depth = sum(
                v["dependency_depth"] for v in component_summary["versions"]
            ) / len(component_summary["versions"])
            critical_versions = [
                v for v in component_summary["versions"] if v["criticality"] in ["CRITICAL", "HIGH"]
            ]
        else:
            total_blast_radius = max_blast_radius = avg_dependency_depth = 0
            critical_versions = []

        # Add comprehensive summary data
        component_summary.update(
            {
                "all_cve_ids": sorted(all_cve_ids),
                "all_cwe_ids": sorted(all_cwe_ids),
                "all_capec_ids": sorted(all_capec_ids),
                "all_dependencies": sorted(all_dependencies),
                "dependency_count": len(all_dependencies),
                "supply_chain_position": {
                    "total_blast_radius": total_blast_radius,
                    "max_blast_radius": max_blast_radius,
                    "avg_dependency_depth": avg_dependency_depth,
                    "supply_chain_risk": (
                        "HIGH"
                        if max_blast_radius > 5 or avg_dependency_depth > 10
                        else "MEDIUM"
                        if max_blast_radius > 1 or avg_dependency_depth > 5
                        else "LOW"
                    ),
                },
                "attack_surface_analysis": {
                    "unique_attack_patterns": len(all_capec_ids),
                    "weakness_categories": len(all_cwe_ids),
                    "attack_sophistication": (
                        "HIGH"
                        if len(all_capec_ids) > 5
                        else "MEDIUM"
                        if len(all_capec_ids) > 2
                        else "LOW"
                    ),
                    "exploitability": (
                        "HIGH"
                        if component_summary["max_cvss_score"] >= 7.0 and len(all_capec_ids) > 0
                        else "MEDIUM"
                        if component_summary["max_cvss_score"] >= 4.0
                        else "LOW"
                    ),
                },
                "version_distribution": {
                    "critical_versions": len(
                        [v for v in component_summary["versions"] if v["criticality"] == "CRITICAL"]
                    ),
                    "high_risk_versions": len(
                        [v for v in component_summary["versions"] if v["criticality"] == "HIGH"]
                    ),
                    "total_risk_versions": len(critical_versions),
                    "vulnerability_density": component_summary["total_vulnerabilities"]
                    / max(component_summary["total_versions"], 1),
                },
            }
        )

        if include_dependents:
            component_summary["all_dependents"] = sorted(all_dependents)
            component_summary["dependent_count"] = len(all_dependents)

        # Add detailed information for citations
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

        # Add comprehensive citations
        component_summary["citations"] = {
            "component_name": component_name,
            "all_cve_ids": sorted(all_cve_ids),
            "all_cwe_ids": sorted(all_cwe_ids),
            "all_capec_ids": sorted(all_capec_ids),
            "cve_details": cve_details,
            "cwe_details": cwe_details,
            "capec_details": capec_details,
            "evidence_source": "component_knowledge_graph_analysis",
            "analysis_scope": f"all_versions_of_{component_name}",
            "version_ids_analyzed": [v["version_id"] for v in component_summary["versions"]],
        }

        return component_summary

    def get_cve_details(self, cve_id: str) -> dict[str, Any]:
        """Get detailed information about a specific CVE."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        if not self.kg_manager.get_node(cve_id):
            return {"error": f"CVE {cve_id} not found in knowledge graph"}

        cve_node = self.kg_manager.get_node(cve_id)

        # Find affected components
        affected_components = []
        related_cves = set()
        component_blast_radius = {}

        for edge in self.kg_manager.get_edges_by_target(cve_id):
            if edge.get("type") == "HAS_VULNERABILITY":
                source_id = edge.get("source_id", "")
                source_node = self.kg_manager.get_node(source_id)
                if source_node:
                    component_name = source_node.get("component_id", source_id)

                    # Calculate blast radius for this component
                    dependent_count = len(
                        [
                            e
                            for e in self.kg_manager.get_edges_by_target(source_id)
                            if e.get("type") == "DEPENDS_ON"
                        ]
                    )
                    dependency_count = len(
                        [
                            e
                            for e in self.kg_manager.get_edges_by_source(source_id)
                            if e.get("type") == "DEPENDS_ON"
                        ]
                    )

                    # Find other CVEs affecting this component for context
                    other_cves = [
                        e.get("target_id")
                        for e in self.kg_manager.get_edges_by_source(source_id)
                        if e.get("type") == "HAS_VULNERABILITY"
                        and e.get("target_id") != cve_id
                        and e.get("target_id", "").startswith("CVE-")
                    ]
                    related_cves.update(other_cves)

                    affected_components.append(
                        {
                            "component_id": source_id,
                            "component_name": component_name,
                            "version": source_node.get("version", ""),
                            "cvss_score": edge.get("cvss_score"),
                            "cvss_severity": edge.get("cvss_severity"),
                            "purl": source_node.get("purl", ""),
                            "blast_radius": dependent_count,
                            "dependency_depth": dependency_count,
                            "other_cves": sorted([cve for cve in other_cves if cve is not None]),
                            "total_vulnerabilities": source_node.get("vulnerability_count", 1),
                        }
                    )

                    component_blast_radius[component_name] = dependent_count

        # Find related CWEs and their CAPEC attack patterns
        related_cwes = []
        related_capecs = set()

        for edge in self.kg_manager.get_edges_by_source(cve_id):
            if edge.get("type") == "HAS_CWE":
                cwe_id = edge.get("target_id", "")
                cwe_node = self.kg_manager.get_node(cwe_id)
                if cwe_node:
                    # Find CAPEC patterns for this CWE
                    capec_patterns = []
                    for cwe_edge in self.kg_manager.get_edges_by_source(cwe_id):
                        if cwe_edge.get("type") == "EXPLOITS_CWE":
                            capec_id = cwe_edge.get("target_id", "")
                            capec_node = self.kg_manager.get_node(capec_id)
                            if capec_node:
                                related_capecs.add(capec_id)
                                capec_patterns.append(
                                    {
                                        "capec_id": capec_id,
                                        "name": capec_node.get("name", ""),
                                        "description": (
                                            capec_node.get("description", "")[:100] + "..."
                                            if len(capec_node.get("description", "")) > 100
                                            else capec_node.get("description", "")
                                        ),
                                    }
                                )

                    related_cwes.append(
                        {
                            "cwe_id": cwe_id,
                            "name": cwe_node.get("name", ""),
                            "description": (
                                cwe_node.get("description", "")[:200] + "..."
                                if len(cwe_node.get("description", "")) > 200
                                else cwe_node.get("description", "")
                            ),
                            "attack_patterns": capec_patterns,
                        }
                    )

        # Calculate impact analysis
        total_blast_radius = sum(component_blast_radius.values())
        max_blast_radius = max(component_blast_radius.values()) if component_blast_radius else 0
        high_impact_components = [comp for comp in affected_components if comp["blast_radius"] > 0]

        # Calculate max CVSS score, filtering out None values
        available_cvss_scores = []

        # Collect CVSS scores from affected components, excluding None
        for comp in affected_components:
            cvss_score = comp.get("cvss_score")
            if cvss_score is not None and isinstance(cvss_score, int | float):
                available_cvss_scores.append(float(cvss_score))

        # Add CVE node's CVSS score if available
        if cve_node:
            cve_cvss = cve_node.get("cvss_score")
            if cve_cvss is not None and isinstance(cve_cvss, int | float):
                available_cvss_scores.append(float(cve_cvss))

        # Calculate max CVSS or indicate unavailable
        max_cvss_score = max(available_cvss_scores) if available_cvss_scores else None
        cvss_availability = {
            "total_components": len(affected_components),
            "components_with_cvss": len(
                [comp for comp in affected_components if comp.get("cvss_score") is not None]
            ),
            "components_without_cvss": len(
                [comp for comp in affected_components if comp.get("cvss_score") is None]
            ),
            "cve_has_cvss": cve_node.get("cvss_score") is not None if cve_node else False,
        }

        return {
            "cve_id": cve_id,
            "summary": cve_node.get("summary", "") if cve_node else "",
            "description": cve_node.get("description", "") if cve_node else "",
            "cvss_score": cve_node.get("cvss_score") if cve_node else None,
            "cvss_severity": cve_node.get("cvss_severity") if cve_node else None,
            "published": cve_node.get("published") if cve_node else None,
            "affected_components": affected_components,
            "related_cwes": related_cwes,
            "total_affected_components": len(affected_components),
            "impact_analysis": {
                "total_blast_radius": total_blast_radius,
                "max_component_blast_radius": max_blast_radius,
                "high_impact_components": len(high_impact_components),
                "supply_chain_risk": (
                    "HIGH" if max_blast_radius > 5 else "MEDIUM" if max_blast_radius > 1 else "LOW"
                ),
            },
            "attack_intelligence": {
                "exploitable_weakness_count": len(related_cwes),
                "attack_pattern_count": len(related_capecs),
                "attack_sophistication": (
                    "HIGH"
                    if len(related_capecs) > 2
                    else "MEDIUM"
                    if len(related_capecs) > 0
                    else "LOW"
                ),
            },
            "citations": {
                "cve_id": cve_id,
                "related_cves": sorted(related_cves),
                "cwe_ids": [cwe["cwe_id"] for cwe in related_cwes],
                "capec_ids": sorted(related_capecs),
                "evidence_source": "cve_knowledge_graph_analysis",
                "affected_component_ids": [comp["component_id"] for comp in affected_components],
            },
            "risk_context": {
                "component_diversity": len(
                    {comp["component_name"] for comp in affected_components}
                ),
                "version_spread": len(
                    {f"{comp['component_name']}@{comp['version']}" for comp in affected_components}
                ),
                "max_cvss_in_analysis": max_cvss_score,
                "cvss_availability": cvss_availability,
            },
        }

    def analyze_supply_chain_impact(
        self, component_name: str, depth_limit: int = 3, impact_threshold: float = 5.0
    ) -> dict[str, Any]:
        """Analyze how component vulnerabilities propagate through the supply chain."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        # Find all versions of the target component
        target_versions = []
        for version_id, version_node in self.kg_manager.get_nodes_by_type("Version").items():
            node_component = version_node.get(
                "component_id", version_id.split("@")[0] if "@" in version_id else version_id
            )
            if node_component.lower() == component_name.lower():
                target_versions.append(
                    {
                        "version_id": version_id,
                        "version": version_node.get("version", "unknown"),
                        "vulnerability_count": version_node.get("vulnerability_count", 0),
                        "max_cvss_score": version_node.get("max_cvss_score", 0.0) or 0.0,
                    }
                )

        if not target_versions:
            return {"error": f"Component '{component_name}' not found in knowledge graph"}

        # Analyze supply chain propagation
        supply_chain_analysis: dict[str, Any] = {
            "target_component": component_name,
            "direct_dependents": [],
            "cascade_analysis": [],
            "vulnerability_propagation": [],
            "impact_summary": {
                "total_affected_components": 0,
                "max_cascade_depth": 0,
                "critical_propagation_paths": [],
                "supply_chain_risk_score": 0.0,
            },
        }

        all_affected_components = set()
        propagation_paths = []

        # For each vulnerable version, trace the propagation
        for target_version in target_versions:
            if target_version["vulnerability_count"] == 0:
                continue

            version_id = target_version["version_id"]
            max_cvss = target_version["max_cvss_score"]

            if max_cvss < impact_threshold:
                continue

            # Get CVEs for this version
            version_cves = []
            for edge in self.kg_manager.get_edges_by_source(version_id):
                if edge.get("type") == "HAS_VULNERABILITY":
                    cve_id = edge.get("target_id", "")
                    if cve_id.startswith("CVE-"):
                        version_cves.append(cve_id)

            # Trace dependency propagation
            cascade_path = self._trace_dependency_cascade(version_id, depth_limit, impact_threshold)

            if cascade_path["affected_components"]:
                propagation_paths.append(
                    {
                        "source_version": target_version,
                        "source_cves": version_cves,
                        "cascade_depth": cascade_path["max_depth"],
                        "affected_components": cascade_path["affected_components"],
                        "propagation_score": self._calculate_propagation_score(
                            cascade_path, max_cvss
                        ),
                    }
                )

                all_affected_components.update(
                    comp["component_name"] for comp in cascade_path["affected_components"]
                )

        # Find direct dependents (immediate impact)
        direct_dependents = set()
        for target_version in target_versions:
            version_id = target_version["version_id"]
            for edge in self.kg_manager.get_edges_by_target(version_id):
                if edge.get("type") == "DEPENDS_ON":
                    dependent_id = edge.get("source_id", "")
                    dependent_node = self.kg_manager.get_node(dependent_id)
                    if dependent_node:
                        dependent_component = dependent_node.get("component_id", dependent_id)
                        direct_dependents.add(dependent_component)
                        supply_chain_analysis["direct_dependents"].append(
                            {
                                "component_name": dependent_component,
                                "version": dependent_node.get("version", "unknown"),
                                "depends_on_version": target_version["version"],
                                "dependency_risk": target_version["max_cvss_score"],
                            }
                        )

        # Calculate comprehensive impact metrics
        if propagation_paths:
            max_depth = max(path["cascade_depth"] for path in propagation_paths)
            max_propagation_score = max(path["propagation_score"] for path in propagation_paths)

            # Find critical propagation paths (high impact, deep propagation)
            critical_paths = [
                path
                for path in propagation_paths
                if path["propagation_score"] >= 7.0 and path["cascade_depth"] >= 2
            ]

            supply_chain_analysis["cascade_analysis"] = propagation_paths
            supply_chain_analysis["impact_summary"].update(
                {
                    "total_affected_components": len(all_affected_components),
                    "max_cascade_depth": max_depth,
                    "critical_propagation_paths": critical_paths,
                    "supply_chain_risk_score": self._calculate_supply_chain_risk_score(
                        len(all_affected_components), max_depth, max_propagation_score
                    ),
                    "direct_dependents_count": len(direct_dependents),
                    "cascading_impact_ratio": len(all_affected_components)
                    / max(len(direct_dependents), 1),
                }
            )

        # Analyze vulnerability propagation patterns
        vulnerability_patterns = self._analyze_vulnerability_propagation_patterns(propagation_paths)
        supply_chain_analysis["vulnerability_propagation"] = vulnerability_patterns

        # Add comprehensive citations
        all_cves = set()
        all_cwes = set()
        for path in propagation_paths:
            all_cves.update(path["source_cves"])
            # Get CWEs for the source CVEs
            for cve_id in path["source_cves"]:
                for edge in self.kg_manager.get_edges_by_source(cve_id):
                    if edge.get("type") == "HAS_CWE":
                        cwe_id = edge.get("target_id", "")
                        if cwe_id.startswith("CWE-"):
                            all_cwes.add(cwe_id)

        supply_chain_analysis["citations"] = {
            "target_component": component_name,
            "analyzed_versions": [v["version"] for v in target_versions],
            "propagated_cves": sorted(all_cves),
            "related_cwes": sorted(all_cwes),
            "affected_components": sorted(all_affected_components),
            "evidence_source": "supply_chain_propagation_analysis",
            "analysis_depth": depth_limit,
            "impact_threshold": impact_threshold,
        }

        return supply_chain_analysis

    def _trace_dependency_cascade(
        self, version_id: str, depth_limit: int, impact_threshold: float
    ) -> dict[str, Any]:
        """Trace how vulnerabilities cascade through dependencies."""
        visited = set()
        cascade_data: dict[str, Any] = {"affected_components": [], "max_depth": 0}

        def _traverse_dependents(current_id: str, current_depth: int, impact_score: float):
            if current_depth >= depth_limit or current_id in visited:
                return

            visited.add(current_id)
            cascade_data["max_depth"] = max(cascade_data["max_depth"], current_depth)

            # Find components that depend on this one
            for edge in self.kg_manager.get_edges_by_target(current_id):
                if edge.get("type") == "DEPENDS_ON":
                    dependent_id = edge.get("source_id", "")
                    dependent_node = self.kg_manager.get_node(dependent_id)

                    if dependent_node:
                        dependent_component = dependent_node.get("component_id", dependent_id)
                        dependent_cvss = dependent_node.get("max_cvss_score", 0.0) or 0.0

                        # Calculate cascading impact score
                        cascade_impact = impact_score * (0.8**current_depth)  # Diminishing returns

                        if cascade_impact >= impact_threshold:
                            cascade_data["affected_components"].append(
                                {
                                    "component_name": dependent_component,
                                    "version": dependent_node.get("version", "unknown"),
                                    "cascade_depth": current_depth + 1,
                                    "cascade_impact_score": cascade_impact,
                                    "own_vulnerability_score": dependent_cvss,
                                    "dependency_path_length": current_depth + 1,
                                }
                            )

                            # Continue cascading
                            _traverse_dependents(dependent_id, current_depth + 1, cascade_impact)

        # Start cascading from the target component
        target_node = self.kg_manager.get_node(version_id)
        initial_impact = target_node.get("max_cvss_score", 0.0) if target_node else 0.0

        _traverse_dependents(version_id, 0, initial_impact)

        return cascade_data

    def _calculate_propagation_score(self, cascade_path: dict, source_cvss: float) -> float:
        """Calculate propagation impact score."""
        if not cascade_path["affected_components"]:
            return 0.0

        # Factors: source severity, cascade depth, number of affected components
        depth_factor = min(cascade_path["max_depth"] / 3.0, 1.0)  # Normalize to 0-1
        breadth_factor = min(
            len(cascade_path["affected_components"]) / 10.0, 1.0
        )  # Normalize to 0-1

        # Calculate average impact across cascade
        avg_cascade_impact = sum(
            comp["cascade_impact_score"] for comp in cascade_path["affected_components"]
        ) / len(cascade_path["affected_components"])

        propagation_score = (
            (source_cvss * 0.4)
            + (avg_cascade_impact * 0.3)
            + (depth_factor * 2.0)
            + (breadth_factor * 1.0)
        )

        return round(min(propagation_score, 10.0), 2)

    def _calculate_supply_chain_risk_score(
        self, affected_count: int, max_depth: int, max_propagation: float
    ) -> float:
        """Calculate overall supply chain risk score."""
        # Weighted combination of factors
        breadth_score = min(affected_count / 20.0, 1.0) * 3.0  # Normalize breadth impact
        depth_score = min(max_depth / 5.0, 1.0) * 2.0  # Normalize depth impact
        severity_score = max_propagation * 0.5  # Direct severity contribution

        total_score = breadth_score + depth_score + severity_score
        return round(min(total_score, 10.0), 2)

    def _analyze_vulnerability_propagation_patterns(
        self, propagation_paths: list
    ) -> dict[str, Any]:
        """Analyze patterns in vulnerability propagation."""
        if not propagation_paths:
            return {"patterns": [], "summary": "No propagation paths found"}

        patterns = {
            "high_impact_cascades": [],
            "deep_propagation_chains": [],
            "broad_impact_components": [],
            "vulnerability_amplification": [],
        }

        for path in propagation_paths:
            # High impact cascades (high source CVSS + significant cascade)
            if path["source_version"]["max_cvss_score"] >= 7.0 and path["cascade_depth"] >= 2:
                patterns["high_impact_cascades"].append(
                    {
                        "source": path["source_version"]["version"],
                        "cvss": path["source_version"]["max_cvss_score"],
                        "cascade_depth": path["cascade_depth"],
                        "affected_count": len(path["affected_components"]),
                    }
                )

            # Deep propagation (depth >= 3)
            if path["cascade_depth"] >= 3:
                patterns["deep_propagation_chains"].append(
                    {
                        "source": path["source_version"]["version"],
                        "max_depth": path["cascade_depth"],
                        "propagation_score": path["propagation_score"],
                    }
                )

            # Broad impact (affects many components)
            if len(path["affected_components"]) >= 5:
                patterns["broad_impact_components"].append(
                    {
                        "source": path["source_version"]["version"],
                        "affected_count": len(path["affected_components"]),
                        "impact_breadth": len(
                            {comp["component_name"] for comp in path["affected_components"]}
                        ),
                    }
                )

            # Vulnerability amplification (cascade creates higher risk than source)
            amplified_components = [
                comp
                for comp in path["affected_components"]
                if comp["cascade_impact_score"] > path["source_version"]["max_cvss_score"] * 0.7
            ]
            if amplified_components:
                patterns["vulnerability_amplification"].append(
                    {
                        "source": path["source_version"]["version"],
                        "amplified_components": len(amplified_components),
                        "amplification_factor": max(
                            comp["cascade_impact_score"]
                            / max(path["source_version"]["max_cvss_score"], 1.0)
                            for comp in amplified_components
                        ),
                    }
                )

        return {
            "patterns": patterns,
            "summary": {
                "high_impact_cascade_count": len(patterns["high_impact_cascades"]),
                "deep_propagation_count": len(patterns["deep_propagation_chains"]),
                "broad_impact_count": len(patterns["broad_impact_components"]),
                "amplification_cases": len(patterns["vulnerability_amplification"]),
            },
        }

    def get_cvss_breakdown(self, cve_id: str) -> dict[str, Any]:
        """Get detailed CVSS version breakdown for a specific CVE."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        cve_node = self.kg_manager.get_node(cve_id)
        if not cve_node:
            return {"error": f"CVE {cve_id} not found in knowledge graph"}

        # Get basic CVE information
        cvss_breakdown = {
            "cve_id": cve_id,
            "description": cve_node.get("description", ""),
            "selected_cvss": {
                "score": cve_node.get("cvss_score"),
                "version": cve_node.get("cvss_version"),
                "vector": cve_node.get("cvss_vector"),
                "severity": cve_node.get("cvss_severity"),
            },
            "all_cvss_versions": {},
            "version_comparison": [],
            "scoring_evolution": {},
        }

        # Get all CVSS metrics if available
        all_cvss_metrics = cve_node.get("all_cvss_metrics", {})

        if all_cvss_metrics:
            cvss_breakdown["all_cvss_versions"] = all_cvss_metrics

            # Create version comparison
            version_scores = []
            for version, metrics in all_cvss_metrics.items():
                if isinstance(metrics, dict):
                    score = self._extract_score_from_metrics(metrics)
                    vector = self._extract_vector_from_metrics(metrics)
                    severity = self._extract_severity_from_metrics(metrics, score)

                    if score is not None:
                        version_scores.append(
                            {
                                "version": version,
                                "score": score,
                                "vector": vector,
                                "severity": severity,
                                "is_selected": version == cve_node.get("cvss_version"),
                            }
                        )

            # Sort by version priority (4.0 > 3.1 > 3.0 > 2.0)
            version_priority = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}
            version_scores.sort(key=lambda x: version_priority.get(x["version"], 0), reverse=True)
            cvss_breakdown["version_comparison"] = version_scores

            # Analyze scoring evolution
            if len(version_scores) > 1:
                cvss_breakdown["scoring_evolution"] = self._analyze_cvss_evolution(version_scores)

        # Find affected components
        affected_components = []
        for edge in self.kg_manager.get_edges_by_target(cve_id):
            if edge.get("type") == "HAS_VULNERABILITY":
                version_id = edge.get("source_id", "")
                version_node = self.kg_manager.get_node(version_id)
                if version_node:
                    affected_components.append(
                        {
                            "component_name": version_node.get("component_id", version_id),
                            "version": version_node.get("version", "unknown"),
                            "component_cvss": version_node.get("max_cvss_score"),
                        }
                    )

        cvss_breakdown["affected_components"] = affected_components
        cvss_breakdown["total_affected_components"] = len(affected_components)

        return cvss_breakdown

    def _extract_score_from_metrics(self, metrics: dict) -> float | None:
        """Extract CVSS score from metrics dictionary."""
        score_fields = ["baseScore", "base_score", "score", "cvssScore", "cvss_score"]

        for field in score_fields:
            if field in metrics:
                try:
                    score = float(metrics[field])
                    if 0.0 <= score <= 10.0:
                        return score
                except (ValueError, TypeError):
                    continue

        # Check nested structures
        if "metrics" in metrics:
            return self._extract_score_from_metrics(metrics["metrics"])
        if "cvssData" in metrics:
            return self._extract_score_from_metrics(metrics["cvssData"])

        return None

    def _extract_vector_from_metrics(self, metrics: dict) -> str | None:
        """Extract CVSS vector from metrics dictionary."""
        vector_fields = ["vectorString", "vector_string", "vector", "cvssVector", "cvss_vector"]

        for field in vector_fields:
            if field in metrics and isinstance(metrics[field], str):
                return metrics[field]

        # Check nested structures
        if "metrics" in metrics:
            return self._extract_vector_from_metrics(metrics["metrics"])
        if "cvssData" in metrics:
            return self._extract_vector_from_metrics(metrics["cvssData"])

        return None

    def _extract_severity_from_metrics(
        self, metrics: dict, score: float | None = None
    ) -> str | None:
        """Extract CVSS severity from metrics dictionary."""
        severity_fields = [
            "baseSeverity",
            "base_severity",
            "severity",
            "cvssSeverity",
            "cvss_severity",
        ]

        for field in severity_fields:
            if field in metrics and isinstance(metrics[field], str):
                return metrics[field].upper()

        # Check nested structures
        if "metrics" in metrics:
            severity = self._extract_severity_from_metrics(metrics["metrics"], score)
            if severity:
                return severity
        if "cvssData" in metrics:
            severity = self._extract_severity_from_metrics(metrics["cvssData"], score)
            if severity:
                return severity

        # If no severity found but we have a score, calculate it
        if score is not None:
            return self._score_to_severity(score)

        return None

    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score == 0.0:
            return "NONE"
        elif 0.1 <= score <= 3.9:
            return "LOW"
        elif 4.0 <= score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= score <= 8.9:
            return "HIGH"
        elif 9.0 <= score <= 10.0:
            return "CRITICAL"
        else:
            return "UNKNOWN"

    def _analyze_cvss_evolution(self, version_scores: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze how CVSS scores evolved across versions."""
        if len(version_scores) < 2:
            return {}

        # Sort by version chronologically (2.0 -> 3.0 -> 3.1 -> 4.0)
        version_order = {"2.0": 1, "3.0": 2, "3.1": 3, "4.0": 4}
        chronological_scores = sorted(
            version_scores, key=lambda x: version_order.get(x["version"], 0)
        )

        evolution: dict[str, Any] = {
            "score_changes": [],
            "severity_changes": [],
            "trend": "stable",
            "max_increase": 0.0,
            "max_decrease": 0.0,
        }

        for i in range(1, len(chronological_scores)):
            prev_score = chronological_scores[i - 1]["score"]
            curr_score = chronological_scores[i]["score"]
            prev_severity = chronological_scores[i - 1]["severity"]
            curr_severity = chronological_scores[i]["severity"]

            score_change = curr_score - prev_score
            evolution["score_changes"].append(
                {
                    "from_version": chronological_scores[i - 1]["version"],
                    "to_version": chronological_scores[i]["version"],
                    "score_change": round(score_change, 1),
                    "from_score": prev_score,
                    "to_score": curr_score,
                }
            )

            if prev_severity != curr_severity:
                evolution["severity_changes"].append(
                    {
                        "from_version": chronological_scores[i - 1]["version"],
                        "to_version": chronological_scores[i]["version"],
                        "from_severity": prev_severity,
                        "to_severity": curr_severity,
                    }
                )

            # Track max changes
            if score_change > evolution["max_increase"]:
                evolution["max_increase"] = score_change
            if score_change < evolution["max_decrease"]:
                evolution["max_decrease"] = abs(score_change)

        # Determine overall trend
        total_change = chronological_scores[-1]["score"] - chronological_scores[0]["score"]
        if total_change > 0.5:
            evolution["trend"] = "increasing"
        elif total_change < -0.5:
            evolution["trend"] = "decreasing"
        else:
            evolution["trend"] = "stable"

        return evolution
