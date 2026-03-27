from typing import Any

from .knowledge_graph_manager import KnowledgeGraphManager


class SecurityAnalyzer:
    """
    Handles comprehensive security analysis of components, vulnerabilities, and attack patterns.
    Provides methods for analyzing SBOM security posture, attack surfaces, and vulnerability patterns.
    """

    def __init__(self, kg_manager: KnowledgeGraphManager):
        """Initialize with a knowledge graph manager."""
        self.kg_manager = kg_manager

    def analyze_security_comprehensive(self, focus: str = "comprehensive") -> dict[str, Any]:
        """Comprehensive security analysis that returns everything in one call."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        # Get all vulnerable components with full details
        vulnerable_components = []
        all_cves_detailed = []
        all_cwes_detailed = []
        all_capecs_detailed = []

        # Process all vulnerable versions and gather comprehensive data
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            if node.get("vulnerability_count", 0) > 0:
                component_name = node.get(
                    "component_id", node_id.split("@")[0] if "@" in node_id else node_id
                )
                version = node.get("version", "unknown")
                max_cvss = node.get("max_cvss_score", 0.0)
                vuln_count = node.get("vulnerability_count", 0)

                # Handle None values for CVSS scores
                if max_cvss is None:
                    max_cvss = 0.0

                # Filter based on focus for components
                if focus == "critical" and max_cvss < 7.0:
                    continue

                # Get detailed CVE information for this version
                cves_for_component = []
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_VULNERABILITY":
                        cve_id = edge.get("target_id", "")
                        if cve_id.startswith("CVE-"):
                            cve_node = self.kg_manager.get_node(cve_id) or {}
                            cvss_score = cve_node.get("cvss_score", 0.0)
                            if cvss_score is None:
                                cvss_score = 0.0
                            cve_detail = {
                                "cve_id": cve_id,
                                "cvss_score": cvss_score,
                                "severity": cve_node.get("cvss_severity", "unknown"),
                                "description": cve_node.get("description", ""),
                                "component": component_name,
                                "version": version,
                            }
                            cves_for_component.append(cve_detail)

                            # Add to global CVE list (avoid duplicates)
                            if not any(c["cve_id"] == cve_id for c in all_cves_detailed):
                                # Get CWEs and CAPECs for this CVE
                                related_cwes = []
                                related_capecs = []

                                # Find CWEs for this CVE
                                for cve_edge in self.kg_manager.get_edges_by_source(cve_id):
                                    if cve_edge.get("type") == "HAS_CWE":
                                        cwe_id = cve_edge.get("target_id", "")
                                        if cwe_id.startswith("CWE-"):
                                            cwe_node = self.kg_manager.get_node(cwe_id) or {}
                                            related_cwes.append(
                                                {
                                                    "cwe_id": cwe_id,
                                                    "name": cwe_node.get("name", ""),
                                                    "description": cwe_node.get("description", ""),
                                                }
                                            )

                                            # Find CAPECs that exploit this CWE
                                            for capec_edge in self.kg_manager.get_edges_by_target(
                                                cwe_id
                                            ):
                                                if capec_edge.get("type") == "CAPEC_EXPLOITS_CWE":
                                                    capec_id = capec_edge.get("source_id", "")
                                                    if capec_id.startswith("CAPEC-"):
                                                        capec_node = (
                                                            self.kg_manager.get_node(capec_id) or {}
                                                        )
                                                        related_capecs.append(
                                                            {
                                                                "capec_id": capec_id,
                                                                "name": capec_node.get("name", ""),
                                                                "description": capec_node.get(
                                                                    "description", ""
                                                                ),
                                                            }
                                                        )

                                cve_detail_full = cve_detail.copy()
                                cve_detail_full["related_cwes"] = related_cwes
                                cve_detail_full["related_capecs"] = related_capecs
                                all_cves_detailed.append(cve_detail_full)

                # Get CWEs for this version
                cwes_for_component = []
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_CWE":
                        cwe_id = edge.get("target_id", "")
                        if cwe_id.startswith("CWE-"):
                            cwe_node = self.kg_manager.get_node(cwe_id) or {}
                            cwe_detail = {
                                "cwe_id": cwe_id,
                                "name": cwe_node.get("name", ""),
                                "description": cwe_node.get("description", ""),
                            }
                            cwes_for_component.append(cwe_detail)

                            # Add to global CWE list (avoid duplicates)
                            if not any(c["cwe_id"] == cwe_id for c in all_cwes_detailed):
                                all_cwes_detailed.append(cwe_detail)

                vulnerable_components.append(
                    {
                        "component": component_name,
                        "version": version,
                        "version_id": node_id,
                        "vulnerability_count": vuln_count,
                        "max_cvss_score": max_cvss,
                        "cves": cves_for_component,
                        "cwes": cwes_for_component,
                        "purl": node.get("purl", ""),
                    }
                )

        # Get all CAPEC attack patterns
        for node_id, node in self.kg_manager.get_nodes_by_type("CAPEC").items():
            if focus != "components":  # Include CAPECs unless focus is purely on components
                capec_detail = {
                    "capec_id": node_id,
                    "name": node.get("name", ""),
                    "description": node.get("description", ""),
                }
                all_capecs_detailed.append(capec_detail)

        # Sort components by severity
        vulnerable_components.sort(key=lambda x: x["max_cvss_score"], reverse=True)

        # Sort CVEs by severity
        all_cves_detailed.sort(key=lambda x: x["cvss_score"], reverse=True)

        # Calculate highest CVSS score safely
        highest_cvss = 0.0
        if vulnerable_components:
            cvss_scores = [
                c["max_cvss_score"]
                for c in vulnerable_components
                if c["max_cvss_score"] is not None
            ]
            if cvss_scores:
                highest_cvss = max(cvss_scores)

        # Create comprehensive analysis
        analysis = {
            "summary": {
                "total_vulnerable_components": len(vulnerable_components),
                "total_cves": len(all_cves_detailed),
                "total_cwes": len(all_cwes_detailed),
                "total_capecs": len(all_capecs_detailed),
                "highest_cvss": highest_cvss,
                "focus": focus,
            },
            "vulnerable_components": vulnerable_components,
            "all_cves": all_cves_detailed,
            "all_cwes": all_cwes_detailed,
            "all_capecs": all_capecs_detailed if focus in ["comprehensive", "patterns"] else [],
            "security_patterns": {
                "common_cwes": [
                    cwe
                    for cwe in all_cwes_detailed
                    if any(
                        cwe["cwe_id"] in [c["cwe_id"] for c in comp["cwes"]]
                        for comp in vulnerable_components
                    )
                ],
                "attack_chains": [
                    {
                        "cve": cve["cve_id"],
                        "cwes": [cwe["cwe_id"] for cwe in cve.get("related_cwes", [])],
                        "capecs": [capec["capec_id"] for capec in cve.get("related_capecs", [])],
                    }
                    for cve in all_cves_detailed
                    if cve.get("related_cwes") or cve.get("related_capecs")
                ],
            },
            "citation_data": {
                "cve_ids": [cve["cve_id"] for cve in all_cves_detailed],
                "cwe_ids": [cwe["cwe_id"] for cwe in all_cwes_detailed],
                "capec_ids": [capec["capec_id"] for capec in all_capecs_detailed],
                "component_versions": [
                    f"{c['component']} v{c['version']}" for c in vulnerable_components
                ],
            },
        }

        return analysis

    def analyze_attack_surface(
        self, include_transitive: bool = True, severity_threshold: float = 4.0
    ) -> dict[str, Any]:
        """Analyze the attack surface by finding all externally-facing components and their vulnerability exposure."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        exposed_components = []
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            if node.get("is_vulnerable", False):
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
                    if edge.get("type") == "HAS_CWE"
                    and edge.get("target_id", "").startswith("CWE-")
                ]
                exposed_components.append(
                    {
                        "component": component_name,
                        "version": node.get("version", "unknown"),
                        "vulnerabilities": node.get("vulnerability_count", 0),
                        "max_cvss_score": node.get("max_cvss_score", 0),
                        "cve_ids": cve_ids,
                        "cwe_ids": cwe_ids,
                        "version_id": node_id,
                    }
                )
        filtered_components = [
            comp for comp in exposed_components if comp["max_cvss_score"] >= severity_threshold
        ]
        return {
            "exposed_components": filtered_components,
            "total_exposed_components": len(filtered_components),
            "include_transitive": include_transitive,
            "severity_threshold": severity_threshold,
        }

    def analyze_security_patterns(
        self, include_attack_scenarios: bool = True, threat_actor_focus: str = "any"
    ) -> dict[str, Any]:
        """Analyze security patterns by correlating CWE weaknesses with CAPEC attack patterns and component relationships."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        security_patterns = []
        all_cves = set()
        all_cwes = set()
        all_capecs = set()
        cwe_capec_mappings = {}
        attack_scenarios_by_severity = {"critical": [], "high": [], "medium": []}

        for cwe_id, cwe_node in self.kg_manager.get_nodes_by_type("CWE").items():
            all_cwes.add(cwe_id)

            # Find CAPEC patterns that exploit this CWE
            related_capecs = [
                edge.get("target_id")
                for edge in self.kg_manager.get_edges_by_source(cwe_id)
                if edge.get("type") == "EXPLOITS_CWE"
            ]

            if related_capecs:
                cwe_name = cwe_node.get("name", cwe_id)
                cwe_description = (
                    cwe_node.get("description", "")[:150] + "..."
                    if len(cwe_node.get("description", "")) > 150
                    else cwe_node.get("description", "")
                )

                # Track CWE-CAPEC mappings for comprehensive overview
                cwe_capec_mappings[cwe_id] = {
                    "cwe_name": cwe_name,
                    "capec_ids": related_capecs,
                    "affected_cves": [],
                }

                for capec_id in related_capecs:
                    all_capecs.add(capec_id)
                    capec_node = self.kg_manager.get_node(capec_id)  # type: ignore
                    if capec_node:
                        capec_name = capec_node.get("name", capec_id)
                        capec_description = (
                            capec_node.get("description", "")[:150] + "..."
                            if len(capec_node.get("description", "")) > 150
                            else capec_node.get("description", "")
                        )

                        # Find components vulnerable to this CWE and collect CVEs
                        attack_scenarios = []
                        component_relationships = []
                        scenario_cves = set()
                        max_scenario_cvss = 0.0

                        # Look for components with this CWE vulnerability
                        for version_id, version_node in self.kg_manager.get_nodes_by_type(
                            "Version"
                        ).items():
                            # Check if this version has the CWE
                            has_cwe = any(
                                edge.get("target_id") == cwe_id and edge.get("type") == "HAS_CWE"
                                for edge in self.kg_manager.get_edges_by_source(version_id)
                            )

                            if has_cwe:
                                # Get CVEs for this component
                                component_cves = [
                                    edge.get("source_id")
                                    for edge in self.kg_manager.get_edges_by_target(version_id)
                                    if edge.get("type") == "HAS_VULNERABILITY"
                                    and edge.get("source_id", "").startswith("CVE-")
                                ]

                                scenario_cves.update(component_cves)
                                all_cves.update(component_cves)
                                cwe_capec_mappings[cwe_id]["affected_cves"].extend(component_cves)

                                max_cvss = version_node.get("max_cvss_score", 0)
                                max_scenario_cvss = max(max_scenario_cvss, max_cvss)

                                # Build attack scenario
                                attack_scenario = {
                                    "target_component": version_node.get(
                                        "component_id", version_id
                                    ),
                                    "target_version": version_node.get("version", "unknown"),
                                    "vulnerability_count": version_node.get(
                                        "vulnerability_count", 0
                                    ),
                                    "max_cvss_score": max_cvss,
                                    "cve_ids": component_cves,
                                    "blast_radius": len(
                                        self.kg_manager.get_edges_by_target(version_id)
                                    ),
                                }
                                attack_scenarios.append(attack_scenario)
                                component_relationships.append(attack_scenario)

                        # Categorize scenario by severity for prioritization
                        if max_scenario_cvss >= 9.0:
                            attack_scenarios_by_severity["critical"].append(
                                {
                                    "cwe_id": cwe_id,
                                    "capec_id": capec_id,
                                    "max_cvss": max_scenario_cvss,
                                    "cve_count": len(scenario_cves),
                                }
                            )
                        elif max_scenario_cvss >= 7.0:
                            attack_scenarios_by_severity["high"].append(
                                {
                                    "cwe_id": cwe_id,
                                    "capec_id": capec_id,
                                    "max_cvss": max_scenario_cvss,
                                    "cve_count": len(scenario_cves),
                                }
                            )
                        else:
                            attack_scenarios_by_severity["medium"].append(
                                {
                                    "cwe_id": cwe_id,
                                    "capec_id": capec_id,
                                    "max_cvss": max_scenario_cvss,
                                    "cve_count": len(scenario_cves),
                                }
                            )

                        threat_actor_capability = {
                            "threat_actor": threat_actor_focus,
                            "capability": capec_name,
                            "sophistication_required": (
                                "high" if max_scenario_cvss >= 7.0 else "medium"
                            ),
                            "attack_feasibility": "high" if len(attack_scenarios) > 0 else "low",
                        }

                        security_patterns.append(
                            {
                                "cwe_id": cwe_id,
                                "cwe_name": cwe_name,
                                "cwe_description": cwe_description,
                                "capec_id": capec_id,
                                "capec_name": capec_name,
                                "capec_description": capec_description,
                                "attack_scenarios": (
                                    attack_scenarios if include_attack_scenarios else []
                                ),
                                "component_relationships": component_relationships,
                                "threat_actor_capability": threat_actor_capability,
                                "scenario_cves": sorted(scenario_cves),
                                "max_scenario_cvss": max_scenario_cvss,
                                "exploitable_components": len(component_relationships),
                            }
                        )

        # Remove duplicates from CWE-CAPEC mappings CVE lists
        for cwe_data in cwe_capec_mappings.values():
            cwe_data["affected_cves"] = sorted(set(cwe_data["affected_cves"]))

        return {
            "security_patterns": security_patterns,
            "total_patterns_analyzed": len(security_patterns),
            "include_attack_scenarios": include_attack_scenarios,
            "threat_actor_focus": threat_actor_focus,
            "patterns_by_severity": attack_scenarios_by_severity,
            "cwe_capec_mapping_summary": cwe_capec_mappings,
            "citations": {
                "all_cve_ids": sorted(all_cves),
                "all_cwe_ids": sorted(all_cwes),
                "all_capec_ids": sorted(all_capecs),
                "critical_patterns": len(attack_scenarios_by_severity["critical"]),
                "high_severity_patterns": len(attack_scenarios_by_severity["high"]),
                "evidence_source": "cwe_capec_correlation_analysis",
                "threat_intelligence_scope": f"threat_actor_{threat_actor_focus}",
            },
            "analysis_summary": {
                "total_cwes_with_attack_patterns": len(
                    [cwe for cwe, data in cwe_capec_mappings.items() if data["capec_ids"]]
                ),
                "total_exploitable_components": sum(
                    pattern["exploitable_components"] for pattern in security_patterns
                ),
                "highest_risk_cwe_capec": (
                    max(security_patterns, key=lambda x: x["max_scenario_cvss"])["cwe_id"]
                    if security_patterns
                    else None
                ),
                "attack_pattern_coverage": len(all_capecs)
                / max(len(self.kg_manager.get_nodes_by_type("CAPEC")), 1),
            },
        }

    def find_vulnerability_clusters(
        self, max_hops: int = 4, min_cluster_size: int = 2
    ) -> dict[str, Any]:
        """Find clusters of vulnerabilities that could enable complex attack chains through component relationships."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        clusters = []
        vulnerable_components = []

        # First, find all vulnerable components and their CVEs
        for node_id, node in self.kg_manager.get_nodes_by_type("Version").items():
            if node.get("is_vulnerable", False):
                # Find CVEs for this component version
                component_cves = []
                for edge in self.kg_manager.get_edges_by_source(node_id):
                    if edge.get("type") == "HAS_VULNERABILITY":
                        cve_id = edge.get("target_id", "")
                        if cve_id.startswith("CVE-"):
                            cve_node = self.kg_manager.get_node(cve_id) or {}
                            component_cves.append(
                                {
                                    "cve_id": cve_id,
                                    "cvss_score": cve_node.get("cvss_score", "Unknown"),
                                    "severity": cve_node.get("cvss_severity", "Unknown"),
                                    "description": cve_node.get(
                                        "description",
                                        "[No description found in the provided data]",
                                    ),
                                }
                            )

                if component_cves:
                    vulnerable_components.append(
                        {
                            "component_id": node_id,
                            "component_name": node.get("name", node_id),
                            "version": node.get("version", "Unknown"),
                            "vulnerability_count": len(component_cves),
                            "max_cvss": node.get("max_cvss_score", 0),
                            "cves": component_cves,
                        }
                    )

        # Create clusters based on components that share similar vulnerabilities or are related
        for i, comp1 in enumerate(vulnerable_components):
            for _j, comp2 in enumerate(vulnerable_components[i + 1 :], i + 1):
                # Find common CVEs
                cves1 = {cve["cve_id"] for cve in comp1["cves"]}
                cves2 = {cve["cve_id"] for cve in comp2["cves"]}
                common_cves = cves1 & cves2

                # Also check for similar vulnerability types or patterns
                is_related = False
                cluster_type = ""

                if common_cves:
                    is_related = True
                    cluster_type = "shared_vulnerabilities"
                elif comp1["max_cvss"] >= 7.0 and comp2["max_cvss"] >= 7.0:
                    # Both are high-severity
                    is_related = True
                    cluster_type = "high_severity_cluster"
                elif len(cves1 | cves2) >= 3:
                    # Combined they have many vulnerabilities
                    is_related = True
                    cluster_type = "vulnerability_density_cluster"

                if is_related:
                    risk_level = (
                        "high"
                        if (comp1["max_cvss"] >= 7.0 or comp2["max_cvss"] >= 7.0)
                        else "medium"
                    )
                    clusters.append(
                        {
                            "components": [
                                comp1["component_name"],
                                comp2["component_name"],
                            ],
                            "common_cves": list(common_cves) if common_cves else [],
                            "all_cves": list(cves1 | cves2),
                            "cluster_type": cluster_type,
                            "risk_level": risk_level,
                            "combined_cvss_max": max(comp1["max_cvss"], comp2["max_cvss"]),
                            "total_vulnerabilities": comp1["vulnerability_count"]
                            + comp2["vulnerability_count"],
                        }
                    )

        return {
            "vulnerability_clusters": clusters,
            "vulnerable_components": vulnerable_components,
            "total_clusters": len(clusters),
            "total_vulnerable_components": len(vulnerable_components),
            "max_hops": max_hops,
            "min_cluster_size": min_cluster_size,
            "analysis_summary": f"Found {len(vulnerable_components)} vulnerable components and {len(clusters)} potential attack clusters",
        }

    def trace_vulnerability_chains(
        self, cve_id: str | None = None, max_hops: int = 3, include_mitigations: bool = True
    ) -> dict[str, Any]:
        """Trace multi-hop vulnerability chains following CVE→CWE→CAPEC relationships."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        # If no CVE ID provided, analyze all CVEs in the SBOM
        if cve_id is None:
            return self._trace_all_vulnerability_chains(max_hops, include_mitigations)

        # Start from the specified CVE
        cve_node = self.kg_manager.get_node(cve_id)
        if not cve_node:
            return {"error": f"CVE {cve_id} not found in knowledge graph"}

        chain_analysis: dict[str, Any] = {
            "starting_cve": {
                "cve_id": cve_id,
                "cvss_score": cve_node.get("cvss_score", 0.0),
                "severity": cve_node.get("cvss_severity", "unknown"),
                "description": cve_node.get("description", ""),
            },
            "vulnerability_chain": [],
            "attack_patterns": [],
            "affected_components": [],
            "mitigations": [] if include_mitigations else None,
        }

        # Hop 1: CVE → CWE
        related_cwes: list[dict[str, Any]] = []
        for edge in self.kg_manager.get_edges_by_source(cve_id):
            if edge.get("type") == "HAS_CWE":
                cwe_id = edge.get("target_id", "")
                if cwe_id.startswith("CWE-"):
                    cwe_node = self.kg_manager.get_node(cwe_id) or {}
                    cwe_info = {
                        "cwe_id": cwe_id,
                        "name": cwe_node.get("name", ""),
                        "description": cwe_node.get("description", ""),
                        "hop": 1,
                        "relationship": "has_weakness",
                    }
                    related_cwes.append(cwe_info)
                    chain_analysis["vulnerability_chain"].append(cwe_info)

        # Hop 2: CWE → CAPEC
        related_capecs: list[dict[str, Any]] = []
        for cwe_info in related_cwes:
            cwe_id = cwe_info["cwe_id"]
            for edge in self.kg_manager.get_edges_by_target(cwe_id):
                if edge.get("type") == "CAPEC_EXPLOITS_CWE":
                    capec_id = edge.get("source_id", "")
                    if capec_id.startswith("CAPEC-"):
                        capec_node = self.kg_manager.get_node(capec_id) or {}
                        capec_info = {
                            "capec_id": capec_id,
                            "name": capec_node.get("name", ""),
                            "description": capec_node.get("description", ""),
                            "hop": 2,
                            "relationship": "exploits_weakness",
                            "exploits_cwe": cwe_id,
                        }
                        related_capecs.append(capec_info)
                        chain_analysis["attack_patterns"].append(capec_info)

        # Find affected components
        for edge in self.kg_manager.get_edges_by_target(cve_id):
            if edge.get("type") == "HAS_VULNERABILITY":
                version_id = edge.get("source_id", "")
                version_node = self.kg_manager.get_node(version_id)
                if version_node:
                    component_info = {
                        "component_name": version_node.get("component_id", version_id),
                        "version": version_node.get("version", "unknown"),
                        "vulnerability_count": version_node.get("vulnerability_count", 0),
                        "max_cvss_score": version_node.get("max_cvss_score", 0.0),
                    }
                    chain_analysis["affected_components"].append(component_info)

        # Add mitigations if requested
        if include_mitigations:
            mitigations: list[dict[str, Any]] = []
            for capec_info in related_capecs:
                capec_id = capec_info["capec_id"]
                # Look for defensive techniques
                for edge in self.kg_manager.get_edges_by_target(capec_id):
                    if edge.get("type") == "MITIGATES":
                        mitigation_id = edge.get("source_id", "")
                        mitigation_node = self.kg_manager.get_node(mitigation_id)
                        if mitigation_node:
                            mitigations.append(
                                {
                                    "technique_id": mitigation_id,
                                    "name": mitigation_node.get("name", ""),
                                    "description": mitigation_node.get("description", ""),
                                    "mitigates_capec": capec_id,
                                }
                            )
            chain_analysis["mitigations"] = mitigations

        return chain_analysis

    def analyze_cwe_patterns(
        self,
        component_filter: str = "",
        severity_threshold: float = 0.0,
        include_hierarchy: bool = True,
    ) -> dict[str, Any]:
        """Analyze weakness patterns by grouping vulnerabilities by CWE types."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        cwe_patterns = {}
        component_cwe_map = {}

        # Process all vulnerable versions
        for version_id, version_node in self.kg_manager.get_nodes_by_type("Version").items():
            if version_node.get("vulnerability_count", 0) == 0:
                continue

            component_name = version_node.get(
                "component_id", version_id.split("@")[0] if "@" in version_id else version_id
            )

            # Apply component filter if specified
            if component_filter and component_filter.lower() not in component_name.lower():
                continue

            max_cvss = version_node.get("max_cvss_score", 0.0) or 0.0
            if max_cvss < severity_threshold:
                continue

            # Find CWEs for this component
            component_cwes = []
            for edge in self.kg_manager.get_edges_by_source(version_id):
                if edge.get("type") == "HAS_CWE":
                    cwe_id = edge.get("target_id", "")
                    if cwe_id.startswith("CWE-"):
                        component_cwes.append(cwe_id)

            if component_name not in component_cwe_map:
                component_cwe_map[component_name] = {
                    "cwes": set(),
                    "max_cvss": max_cvss,
                    "versions": [],
                }

            component_cwe_map[component_name]["cwes"].update(component_cwes)
            component_cwe_map[component_name]["max_cvss"] = max(
                component_cwe_map[component_name]["max_cvss"], max_cvss
            )
            component_cwe_map[component_name]["versions"].append(
                {
                    "version": version_node.get("version", "unknown"),
                    "cvss": max_cvss,
                    "vulnerability_count": version_node.get("vulnerability_count", 0),
                }
            )

            # Build CWE patterns
            for cwe_id in component_cwes:
                if cwe_id not in cwe_patterns:
                    cwe_node = self.kg_manager.get_node(cwe_id) or {}
                    cwe_patterns[cwe_id] = {
                        "cwe_id": cwe_id,
                        "name": cwe_node.get("name", ""),
                        "description": cwe_node.get("description", ""),
                        "affected_components": [],
                        "total_components": 0,
                        "max_cvss_score": 0.0,
                        "parent_cwes": [],
                        "child_cwes": [],
                        "attack_patterns": [],
                    }

                cwe_patterns[cwe_id]["affected_components"].append(
                    {
                        "component_name": component_name,
                        "max_cvss": max_cvss,
                        "versions": len(component_cwe_map[component_name]["versions"]),
                    }
                )
                cwe_patterns[cwe_id]["total_components"] += 1
                cwe_patterns[cwe_id]["max_cvss_score"] = max(
                    cwe_patterns[cwe_id]["max_cvss_score"], max_cvss
                )

        # Add hierarchy information if requested
        if include_hierarchy:
            for cwe_id, pattern in cwe_patterns.items():
                # Find parent CWEs
                for edge in self.kg_manager.get_edges_by_source(cwe_id):
                    if edge.get("type") == "IS_CHILD_OF":
                        parent_id = edge.get("target_id", "")
                        if parent_id.startswith("CWE-"):
                            parent_node = self.kg_manager.get_node(parent_id) or {}
                            pattern["parent_cwes"].append(
                                {"cwe_id": parent_id, "name": parent_node.get("name", "")}
                            )

                # Find child CWEs
                for edge in self.kg_manager.get_edges_by_target(cwe_id):
                    if edge.get("type") == "IS_CHILD_OF":
                        child_id = edge.get("source_id", "")
                        if child_id.startswith("CWE-"):
                            child_node = self.kg_manager.get_node(child_id) or {}
                            pattern["child_cwes"].append(
                                {"cwe_id": child_id, "name": child_node.get("name", "")}
                            )

                # Find related CAPEC attack patterns
                for edge in self.kg_manager.get_edges_by_target(cwe_id):
                    if edge.get("type") == "CAPEC_EXPLOITS_CWE":
                        capec_id = edge.get("source_id", "")
                        if capec_id.startswith("CAPEC-"):
                            capec_node = self.kg_manager.get_node(capec_id) or {}
                            pattern["attack_patterns"].append(
                                {"capec_id": capec_id, "name": capec_node.get("name", "")}
                            )

        # Sort patterns by impact
        sorted_patterns = sorted(
            cwe_patterns.values(),
            key=lambda x: (x["total_components"], x["max_cvss_score"]),
            reverse=True,
        )

        return {
            "cwe_patterns": sorted_patterns,
            "component_cwe_mapping": {
                comp: {
                    "cwes": list(data["cwes"]),
                    "max_cvss": data["max_cvss"],
                    "versions": data["versions"],
                }
                for comp, data in component_cwe_map.items()
            },
            "summary": {
                "total_cwe_patterns": len(cwe_patterns),
                "total_affected_components": len(component_cwe_map),
                "component_filter": component_filter or "all components",
                "severity_threshold": severity_threshold,
                "include_hierarchy": include_hierarchy,
            },
        }

    def map_attack_surface(
        self,
        focus_components: list[str] | None = None,
        network_exposed_only: bool = False,
        min_cvss: float = 5.0,
    ) -> dict[str, Any]:
        """Map the attack surface by identifying exposed components and their interconnected vulnerabilities."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        focus_components = focus_components or []
        exposed_components = []
        attack_vectors = {}

        # Process all vulnerable versions
        for version_id, version_node in self.kg_manager.get_nodes_by_type("Version").items():
            if version_node.get("vulnerability_count", 0) == 0:
                continue

            component_name = version_node.get(
                "component_id", version_id.split("@")[0] if "@" in version_id else version_id
            )
            max_cvss = version_node.get("max_cvss_score", 0.0) or 0.0

            # Apply filters
            if focus_components and component_name not in focus_components:
                continue
            if max_cvss < min_cvss:
                continue

            # Get vulnerabilities for this component
            component_vulns = []
            network_vulns = []

            for edge in self.kg_manager.get_edges_by_source(version_id):
                if edge.get("type") == "HAS_VULNERABILITY":
                    cve_id = edge.get("target_id", "")
                    if cve_id.startswith("CVE-"):
                        cve_node = self.kg_manager.get_node(cve_id) or {}
                        vuln_info = {
                            "cve_id": cve_id,
                            "cvss_score": cve_node.get("cvss_score", 0.0),
                            "attack_vector": cve_node.get("attack_vector", "unknown"),
                            "attack_complexity": cve_node.get("attack_complexity", "unknown"),
                            "privileges_required": cve_node.get("privileges_required", "unknown"),
                        }
                        component_vulns.append(vuln_info)

                        # Check if network exposed
                        if vuln_info["attack_vector"].lower() in ["network", "adjacent"]:
                            network_vulns.append(vuln_info)

            # Skip if network_exposed_only is True but no network vulnerabilities
            if network_exposed_only and not network_vulns:
                continue

            # Analyze attack vectors
            for vuln in component_vulns:
                vector = vuln["attack_vector"]
                if vector not in attack_vectors:
                    attack_vectors[vector] = {
                        "components": set(),
                        "vulnerabilities": [],
                        "max_cvss": 0.0,
                    }
                attack_vectors[vector]["components"].add(component_name)
                attack_vectors[vector]["vulnerabilities"].append(vuln["cve_id"])
                attack_vectors[vector]["max_cvss"] = max(
                    attack_vectors[vector]["max_cvss"], vuln["cvss_score"]
                )

            exposed_component = {
                "component_name": component_name,
                "version": version_node.get("version", "unknown"),
                "total_vulnerabilities": len(component_vulns),
                "network_vulnerabilities": len(network_vulns),
                "max_cvss_score": max_cvss,
                "attack_surface_score": self._calculate_attack_surface_score(component_vulns),
                "vulnerabilities": component_vulns,
                "is_network_exposed": len(network_vulns) > 0,
                "critical_paths": self._find_critical_paths(version_id, component_vulns),
            }
            exposed_components.append(exposed_component)

        # Convert sets to lists for JSON serialization
        for vector_data in attack_vectors.values():
            vector_data["components"] = list(vector_data["components"])

        # Sort by attack surface score
        exposed_components.sort(key=lambda x: x["attack_surface_score"], reverse=True)

        return {
            "exposed_components": exposed_components,
            "attack_vectors": attack_vectors,
            "summary": {
                "total_exposed_components": len(exposed_components),
                "network_exposed_components": sum(
                    1 for c in exposed_components if c["is_network_exposed"]
                ),
                "highest_attack_surface_score": max(
                    c["attack_surface_score"] for c in exposed_components
                )
                if exposed_components
                else 0,
                "focus_components": focus_components,
                "network_exposed_only": network_exposed_only,
                "min_cvss_threshold": min_cvss,
            },
        }

    def analyze_temporal_risk(
        self,
        time_window_days: int = 365,
        include_patch_status: bool = True,
        sort_by: str = "risk_score",
    ) -> dict[str, Any]:
        """Analyze vulnerability risk over time, including age and patch availability."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        from datetime import datetime, timedelta

        current_date = datetime.now()
        cutoff_date = current_date - timedelta(days=time_window_days)

        temporal_risks = []
        age_distribution = {"0-30": 0, "31-90": 0, "91-365": 0, "365+": 0}

        # Process all CVEs
        for cve_id, cve_node in self.kg_manager.get_nodes_by_type("CVE").items():
            published_date_str = cve_node.get("published_date", "")
            if not published_date_str:
                continue

            try:
                # Parse published date (assuming YYYY-MM-DD format)
                published_date = datetime.strptime(published_date_str.split("T")[0], "%Y-%m-%d")

                # Skip if outside time window
                if published_date < cutoff_date:
                    continue

                age_days = (current_date - published_date).days
                cvss_score = cve_node.get("cvss_score", 0.0) or 0.0

                # Calculate risk score (combines age and severity)
                risk_score = self._calculate_temporal_risk_score(age_days, cvss_score)

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
                                }
                            )

                # Categorize by age
                if age_days <= 30:
                    age_distribution["0-30"] += 1
                elif age_days <= 90:
                    age_distribution["31-90"] += 1
                elif age_days <= 365:
                    age_distribution["91-365"] += 1
                else:
                    age_distribution["365+"] += 1

                temporal_risk = {
                    "cve_id": cve_id,
                    "published_date": published_date_str,
                    "age_days": age_days,
                    "cvss_score": cvss_score,
                    "severity": cve_node.get("cvss_severity", "unknown"),
                    "risk_score": risk_score,
                    "affected_components": affected_components,
                    "patch_status": self._get_patch_status(cve_id)
                    if include_patch_status
                    else None,
                }
                temporal_risks.append(temporal_risk)

            except ValueError:
                # Skip CVEs with invalid date formats
                continue

        # Sort based on specified criteria
        if sort_by == "age":
            temporal_risks.sort(key=lambda x: x["age_days"], reverse=True)
        elif sort_by == "severity":
            temporal_risks.sort(key=lambda x: x["cvss_score"], reverse=True)
        else:  # risk_score
            temporal_risks.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "temporal_risks": temporal_risks,
            "age_distribution": age_distribution,
            "summary": {
                "total_vulnerabilities_in_window": len(temporal_risks),
                "time_window_days": time_window_days,
                "highest_risk_score": max(r["risk_score"] for r in temporal_risks)
                if temporal_risks
                else 0,
                "average_age_days": sum(r["age_days"] for r in temporal_risks) / len(temporal_risks)
                if temporal_risks
                else 0,
                "recent_vulnerabilities_30d": age_distribution["0-30"],
                "sort_by": sort_by,
                "include_patch_status": include_patch_status,
            },
        }

    def _calculate_attack_surface_score(self, vulnerabilities: list[dict]) -> float:
        """Calculate attack surface score based on vulnerabilities."""
        if not vulnerabilities:
            return 0.0

        score = 0.0
        for vuln in vulnerabilities:
            cvss = vuln.get("cvss_score", 0.0)
            # Network accessible vulnerabilities get higher weight
            if vuln.get("attack_vector", "").lower() == "network":
                score += cvss * 1.5
            elif vuln.get("attack_vector", "").lower() == "adjacent":
                score += cvss * 1.2
            else:
                score += cvss

        return round(score / len(vulnerabilities), 2)

    def _find_critical_paths(self, version_id: str, vulnerabilities: list[dict]) -> list[dict]:
        """Find critical attack paths for a component."""
        critical_paths = []

        for vuln in vulnerabilities:
            if vuln.get("cvss_score", 0) >= 7.0:  # High/Critical only
                path = {
                    "cve_id": vuln["cve_id"],
                    "attack_vector": vuln.get("attack_vector", "unknown"),
                    "complexity": vuln.get("attack_complexity", "unknown"),
                    "privileges": vuln.get("privileges_required", "unknown"),
                    "impact_score": vuln.get("cvss_score", 0.0),
                }
                critical_paths.append(path)

        return sorted(critical_paths, key=lambda x: x["impact_score"], reverse=True)

    def _calculate_temporal_risk_score(self, age_days: int, cvss_score: float) -> float:
        """Calculate temporal risk score combining age and severity."""
        # Recent vulnerabilities are higher risk
        age_factor = 1.0
        if age_days <= 30:
            age_factor = 1.5  # Very recent
        elif age_days <= 90:
            age_factor = 1.3  # Recent
        elif age_days <= 365:
            age_factor = 1.1  # Somewhat recent

        return round(cvss_score * age_factor, 2)

    def _get_patch_status(self, cve_id: str) -> dict[str, Any]:
        """Get patch status information for a CVE."""
        # This would typically query external sources or patch databases
        # For now, return basic structure
        return {
            "patch_available": "unknown",
            "patch_date": None,
            "vendor_advisory": None,
            "patch_complexity": "unknown",
        }

    def _trace_all_vulnerability_chains(
        self, max_hops: int = 3, include_mitigations: bool = True
    ) -> dict[str, Any]:
        """Trace vulnerability chains for all CVEs in the SBOM."""
        all_chains = []
        all_affected_components = []
        all_attack_patterns = []
        all_mitigations = []

        # Get all CVEs from the knowledge graph
        cve_nodes = self.kg_manager.get_nodes_by_type("CVE")

        if not cve_nodes:
            return {
                "error": "No CVEs found in knowledge graph",
                "total_cves_analyzed": 0,
                "vulnerability_chains": [],
            }

        # Trace chains for each CVE
        for cve_id, _cve_node in cve_nodes.items():
            # Get individual chain analysis
            chain_result = self.trace_vulnerability_chains(cve_id, max_hops, include_mitigations)

            if "error" not in chain_result:
                all_chains.append({"cve_id": cve_id, "chain_analysis": chain_result})

                # Aggregate data
                if "affected_components" in chain_result:
                    all_affected_components.extend(chain_result["affected_components"])

                if "attack_patterns" in chain_result:
                    all_attack_patterns.extend(chain_result["attack_patterns"])

                if (
                    include_mitigations
                    and "mitigations" in chain_result
                    and chain_result["mitigations"]
                ):
                    all_mitigations.extend(chain_result["mitigations"])

        # Remove duplicates and create summary
        unique_components = {
            comp["component_name"]: comp for comp in all_affected_components
        }.values()
        unique_attack_patterns = {
            pattern["capec_id"]: pattern for pattern in all_attack_patterns
        }.values()
        unique_mitigations = (
            {mit["technique_id"]: mit for mit in all_mitigations}.values()
            if include_mitigations
            else []
        )

        # Find the most critical chains
        critical_chains = []
        for chain in all_chains:
            cve_id = chain["cve_id"]
            chain_data = chain["chain_analysis"]
            if "starting_cve" in chain_data:
                cvss_score = chain_data["starting_cve"].get("cvss_score", 0.0)
                attack_pattern_count = len(chain_data.get("attack_patterns", []))
                if cvss_score >= 7.0 or attack_pattern_count >= 2:
                    critical_chains.append(
                        {
                            "cve_id": cve_id,
                            "cvss_score": cvss_score,
                            "attack_patterns": attack_pattern_count,
                            "affected_components": len(chain_data.get("affected_components", [])),
                        }
                    )

        # Sort critical chains by severity
        critical_chains.sort(key=lambda x: x["cvss_score"], reverse=True)

        return {
            "analysis_type": "comprehensive_vulnerability_chains",
            "total_cves_analyzed": len(all_chains),
            "total_chains_found": len(all_chains),
            "critical_chains": critical_chains[:5],  # Top 5 most critical
            "summary": {
                "unique_affected_components": len(unique_components),
                "unique_attack_patterns": len(unique_attack_patterns),
                "unique_mitigations": len(unique_mitigations) if include_mitigations else 0,
                "highest_cvss_score": max(
                    (
                        chain["chain_analysis"]["starting_cve"].get("cvss_score", 0.0)
                        for chain in all_chains
                        if "starting_cve" in chain["chain_analysis"]
                    ),
                    default=0.0,
                ),
            },
            "detailed_chains": all_chains,
            "aggregated_components": list(unique_components),
            "aggregated_attack_patterns": list(unique_attack_patterns),
            "aggregated_mitigations": list(unique_mitigations) if include_mitigations else [],
            "citations": {
                "all_cve_ids": list(cve_nodes.keys()),
                "evidence_source": "comprehensive_vulnerability_chain_analysis",
                "analysis_scope": "all_cves_in_sbom",
            },
        }

    def get_cwe_details(self, cwe_id: str) -> dict[str, Any]:
        """Get comprehensive details about a specific CWE."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        cwe_node = self.kg_manager.get_node(cwe_id)
        if not cwe_node:
            return {"error": f"CWE {cwe_id} not found in knowledge graph"}

        # Get CWE basic information
        cwe_details: dict[str, Any] = {
            "cwe_id": cwe_id,
            "name": cwe_node.get("name", ""),
            "description": cwe_node.get("description", ""),
            "related_cves": [],
            "attack_patterns": [],
            "vulnerability_count": 0,
        }

        # Find CVEs that have this CWE
        for edge in self.kg_manager.get_edges_by_target(cwe_id):
            if edge.get("type") == "HAS_CWE":
                cve_id = edge.get("source_id", "")
                if cve_id.startswith("CVE-"):
                    cve_node = self.kg_manager.get_node(cve_id) or {}
                    cwe_details["related_cves"].append(
                        {
                            "cve_id": cve_id,
                            "cvss_score": cve_node.get("cvss_score"),
                            "cvss_severity": cve_node.get("cvss_severity", ""),
                            "description": cve_node.get("description", "")[:200] + "..."
                            if len(cve_node.get("description", "")) > 200
                            else cve_node.get("description", ""),
                        }
                    )
                    cwe_details["vulnerability_count"] += 1

        # Find CAPEC attack patterns that exploit this CWE
        for edge in self.kg_manager.get_edges_by_target(cwe_id):
            if edge.get("type") == "CAPEC_EXPLOITS_CWE":
                capec_id = edge.get("source_id", "")
                if capec_id.startswith("CAPEC-"):
                    capec_node = self.kg_manager.get_node(capec_id) or {}
                    cwe_details["attack_patterns"].append(
                        {
                            "capec_id": capec_id,
                            "name": capec_node.get("name", ""),
                            "description": capec_node.get("description", "")[:200] + "..."
                            if len(capec_node.get("description", "")) > 200
                            else capec_node.get("description", ""),
                        }
                    )

        # Sort CVEs by CVSS score (highest first)
        cwe_details["related_cves"].sort(key=lambda x: x["cvss_score"] or 0.0, reverse=True)

        return cwe_details

    def get_capec_details(self, capec_id: str) -> dict[str, Any]:
        """Get detailed information about a specific CAPEC attack pattern."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        capec_node = self.kg_manager.get_node(capec_id)
        if not capec_node:
            return {"error": f"CAPEC {capec_id} not found in knowledge graph"}

        # Get CAPEC basic information
        capec_details: dict[str, Any] = {
            "capec_id": capec_id,
            "name": capec_node.get("name", ""),
            "description": capec_node.get("description", ""),
            "exploited_weaknesses": [],
            "related_vulnerabilities": [],
            "attack_prerequisites": capec_node.get("prerequisites", []),
            "typical_likelihood": capec_node.get("likelihood", ""),
            "typical_severity": capec_node.get("typical_severity", ""),
        }

        # Find CWEs that this CAPEC exploits
        for edge in self.kg_manager.get_edges_by_source(capec_id):
            if edge.get("type") == "CAPEC_EXPLOITS_CWE":
                cwe_id = edge.get("target_id", "")
                if cwe_id.startswith("CWE-"):
                    cwe_node = self.kg_manager.get_node(cwe_id) or {}
                    capec_details["exploited_weaknesses"].append(
                        {
                            "cwe_id": cwe_id,
                            "name": cwe_node.get("name", ""),
                            "description": cwe_node.get("description", "")[:200] + "..."
                            if len(cwe_node.get("description", "")) > 200
                            else cwe_node.get("description", ""),
                        }
                    )

                    # Find CVEs with this CWE to show related vulnerabilities
                    for cwe_edge in self.kg_manager.get_edges_by_target(cwe_id):
                        if cwe_edge.get("type") == "HAS_CWE":
                            cve_id = cwe_edge.get("source_id", "")
                            if cve_id.startswith("CVE-"):
                                cve_node = self.kg_manager.get_node(cve_id) or {}
                                capec_details["related_vulnerabilities"].append(
                                    {
                                        "cve_id": cve_id,
                                        "cvss_score": cve_node.get("cvss_score"),
                                        "cvss_severity": cve_node.get("cvss_severity", ""),
                                        "via_cwe": cwe_id,
                                    }
                                )

        # Remove duplicates and sort
        seen_cves = set()
        unique_vulnerabilities = []
        for vuln in capec_details["related_vulnerabilities"]:
            if vuln["cve_id"] not in seen_cves:
                unique_vulnerabilities.append(vuln)
                seen_cves.add(vuln["cve_id"])

        capec_details["related_vulnerabilities"] = sorted(
            unique_vulnerabilities, key=lambda x: x["cvss_score"] or 0.0, reverse=True
        )[:10]  # Limit to top 10 most severe

        return capec_details

    def find_related_attack_patterns(
        self, cve_id: str, include_mitigations: bool = True
    ) -> dict[str, Any]:
        """Find related attack patterns for a CVE by traversing CVE→CWE→CAPEC relationships."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        cve_node = self.kg_manager.get_node(cve_id)
        if not cve_node:
            return {"error": f"CVE {cve_id} not found in knowledge graph"}

        analysis: dict[str, Any] = {
            "cve_id": cve_id,
            "cvss_score": cve_node.get("cvss_score"),
            "cvss_severity": cve_node.get("cvss_severity", ""),
            "description": cve_node.get("description", ""),
            "weakness_chains": [],
            "attack_patterns": [],
            "total_attack_patterns": 0,
        }

        # Find CWEs associated with this CVE
        for edge in self.kg_manager.get_edges_by_source(cve_id):
            if edge.get("type") == "HAS_CWE":
                cwe_id = edge.get("target_id", "")
                if cwe_id.startswith("CWE-"):
                    cwe_node = self.kg_manager.get_node(cwe_id) or {}

                    # Build chain for this CWE
                    chain: dict[str, Any] = {
                        "cwe_id": cwe_id,
                        "cwe_name": cwe_node.get("name", ""),
                        "cwe_description": cwe_node.get("description", ""),
                        "capec_patterns": [],
                    }

                    # Find CAPEC patterns that exploit this CWE
                    for capec_edge in self.kg_manager.get_edges_by_target(cwe_id):
                        if capec_edge.get("type") == "CAPEC_EXPLOITS_CWE":
                            capec_id = capec_edge.get("source_id", "")
                            if capec_id.startswith("CAPEC-"):
                                capec_node = self.kg_manager.get_node(capec_id) or {}

                                pattern_info: dict[str, Any] = {
                                    "capec_id": capec_id,
                                    "name": capec_node.get("name", ""),
                                    "description": capec_node.get("description", ""),
                                    "prerequisites": capec_node.get("prerequisites", []),
                                    "typical_likelihood": capec_node.get("likelihood", ""),
                                }

                                if include_mitigations:
                                    pattern_info["mitigations"] = capec_node.get("mitigations", [])

                                chain["capec_patterns"].append(pattern_info)

                    if chain["capec_patterns"]:
                        analysis["weakness_chains"].append(chain)
                        analysis["attack_patterns"].extend(chain["capec_patterns"])

        # Remove duplicate attack patterns and count
        seen_capecs = set()
        unique_patterns = []
        for pattern in analysis["attack_patterns"]:
            if pattern["capec_id"] not in seen_capecs:
                unique_patterns.append(pattern)
                seen_capecs.add(pattern["capec_id"])

        analysis["attack_patterns"] = unique_patterns
        analysis["total_attack_patterns"] = len(unique_patterns)

        # Sort chains by number of attack patterns (most exploitable first)
        analysis["weakness_chains"].sort(key=lambda x: len(x["capec_patterns"]), reverse=True)

        return analysis
