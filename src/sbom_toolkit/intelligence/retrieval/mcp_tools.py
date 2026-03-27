import re
from typing import Any

from .component_analyzer import ComponentAnalyzer
from .knowledge_graph_manager import KnowledgeGraphManager
from .query_engine import QueryEngine
from .security_analyzer import SecurityAnalyzer


class MCPTools:
    """
    Handles tool definitions and function execution for the MCP system.
    Coordinates between different analyzer modules to execute function calls.
    """

    def __init__(
        self,
        kg_manager: KnowledgeGraphManager,
        security_analyzer: SecurityAnalyzer,
        component_analyzer: ComponentAnalyzer,
        query_engine: QueryEngine,
    ):
        """Initialize with all analyzer modules."""
        self.kg_manager = kg_manager
        self.security_analyzer = security_analyzer
        self.component_analyzer = component_analyzer
        self.query_engine = query_engine

        # Track conversation context for parameter auto-correction
        self.conversation_context: dict[str, Any] = {
            "recent_cves": [],
            "recent_components": [],
            "recent_cwes": [],
            "last_analysis_result": None,
        }

    def get_kg_tools(self) -> list[dict[str, Any]]:
        """Get a strategic set of function definitions that the LLM can use effectively."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_help",
                    "description": "Display available MCP tools and usage scenarios. Call this when users ask for help, available commands, or what you can do.",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_security_comprehensive",
                    "description": "Get comprehensive security analysis including all vulnerabilities, components, CVEs, CWEs, and attack patterns. This is the primary function to start with - it provides overview data that can be used by other functions.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "focus": {
                                "type": "string",
                                "enum": ["comprehensive", "critical", "patterns", "components"],
                                "description": "Analysis focus: 'comprehensive' for full analysis, 'critical' for high-severity only, 'patterns' for attack patterns, 'components' for component-focused",
                                "default": "comprehensive",
                            }
                        },
                        "required": [],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_component",
                    "description": "Get detailed analysis of a specific component including all versions, vulnerabilities, CVE details, CWE mappings, dependencies, and risk assessment. Use this when asked about specific components or packages. **IMPORTANT**: Component name should be extracted from previous analysis results or user queries.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "component_name": {
                                "type": "string",
                                "description": "Name of the component to analyze (e.g., 'flask', 'numpy', 'react', 'spring-boot'). Should be the exact component name from SBOM or previous analysis.",
                                "minLength": 1,
                            }
                        },
                        "required": ["component_name"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_cve_details",
                    "description": """Get comprehensive details about a specific CVE including affected components, related CWEs, attack patterns, impact analysis, and supply chain risk.

                    **CRITICAL**: You MUST provide a CVE ID. If you don't have one:
                    1. First call analyze_security_comprehensive() to discover CVEs
                    2. Extract specific CVE IDs from that response (look for 'cves' array)
                    3. Then use those IDs to call this function

                    Example workflow:
                    1. analyze_security_comprehensive() → finds CVE-2021-44228
                    2. get_cve_details({"cve_id": "CVE-2021-44228"}) → get detailed analysis""",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "CVE identifier in format CVE-YYYY-NNNNN (e.g., 'CVE-2021-44228', 'CVE-2023-46136'). Must be extracted from previous analysis results.",
                                "pattern": "^CVE-\\d{4}-\\d+$",
                                "minLength": 13,
                            }
                        },
                        "required": ["cve_id"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_vulnerable_components",
                    "description": "Get a filtered list of vulnerable components based on severity threshold and other criteria. Use this when you need to find components with specific vulnerability characteristics or severity levels.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "min_severity_score": {
                                "type": "number",
                                "description": "Minimum CVSS score to include (0.0-10.0). Default is 0.0 for all vulnerabilities.",
                                "minimum": 0.0,
                                "maximum": 10.0,
                                "default": 0.0,
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of components to return. Default is 10.",
                                "minimum": 1,
                                "maximum": 50,
                                "default": 10,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "trace_vulnerability_chains",
                    "description": "Trace multi-hop vulnerability chains following CVE→CWE→CAPEC relationships to identify attack patterns and root causes. Essential for understanding vulnerability propagation and attack vectors.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "Optional CVE identifier to start the chain analysis from (e.g., 'CVE-2021-44228'). If not provided, analyzes chains for all CVEs in the SBOM.",
                            },
                            "max_hops": {
                                "type": "integer",
                                "description": "Maximum number of hops to follow in the chain (default: 3)",
                                "minimum": 1,
                                "maximum": 5,
                                "default": 3,
                            },
                            "include_mitigations": {
                                "type": "boolean",
                                "description": "Include defensive techniques and countermeasures in the analysis (default: true)",
                                "default": True,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_cwe_patterns",
                    "description": "Analyze weakness patterns by grouping vulnerabilities by CWE types to identify systemic security issues and common vulnerability classes across components.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "component_filter": {
                                "type": "string",
                                "description": "Optional component name to filter analysis (leave empty for all components)",
                            },
                            "severity_threshold": {
                                "type": "number",
                                "description": "Minimum CVSS score to include in analysis (default: 0.0)",
                                "minimum": 0.0,
                                "maximum": 10.0,
                                "default": 0.0,
                            },
                            "include_hierarchy": {
                                "type": "boolean",
                                "description": "Include CWE parent-child relationships in the analysis (default: true)",
                                "default": True,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "map_attack_surface",
                    "description": "Map the attack surface by identifying exposed components and their interconnected vulnerabilities. Critical for understanding entry points and attack paths.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "focus_components": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Optional list of component names to focus analysis on (leave empty for all)",
                            },
                            "network_exposed_only": {
                                "type": "boolean",
                                "description": "Focus only on network-exposed vulnerabilities (default: false)",
                                "default": False,
                            },
                            "min_cvss": {
                                "type": "number",
                                "description": "Minimum CVSS score for vulnerabilities to include (default: 5.0)",
                                "minimum": 0.0,
                                "maximum": 10.0,
                                "default": 5.0,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_vulnerability_clusters",
                    "description": "Detect components that share similar vulnerability patterns to reveal systemic risks and identify components with related security issues.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "clustering_method": {
                                "type": "string",
                                "description": "Method for clustering: 'cwe_based' (group by weakness types), 'severity_based' (group by CVSS ranges), or 'pattern_based' (group by vulnerability patterns)",
                                "enum": ["cwe_based", "severity_based", "pattern_based"],
                                "default": "cwe_based",
                            },
                            "min_cluster_size": {
                                "type": "integer",
                                "description": "Minimum number of components required to form a cluster (default: 2)",
                                "minimum": 2,
                                "maximum": 20,
                                "default": 2,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_temporal_risk",
                    "description": "Analyze vulnerability risk over time, including vulnerability age, patch availability, and exposure windows to prioritize remediation efforts.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "time_window_days": {
                                "type": "integer",
                                "description": "Time window in days to analyze (default: 365 for 1 year)",
                                "minimum": 30,
                                "maximum": 1825,
                                "default": 365,
                            },
                            "include_patch_status": {
                                "type": "boolean",
                                "description": "Include patch availability and status information (default: true)",
                                "default": True,
                            },
                            "sort_by": {
                                "type": "string",
                                "description": "Sort results by: 'age' (oldest first), 'severity' (highest first), or 'risk_score' (calculated risk)",
                                "enum": ["age", "severity", "risk_score"],
                                "default": "risk_score",
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_supply_chain_impact",
                    "description": "Analyze how component vulnerabilities propagate through the supply chain and dependency tree to identify cascade effects and critical supply chain risks.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "component_name": {
                                "type": "string",
                                "description": "Component name to analyze supply chain impact for",
                            },
                            "depth_limit": {
                                "type": "integer",
                                "description": "Maximum dependency depth to analyze (default: 3)",
                                "minimum": 1,
                                "maximum": 10,
                                "default": 3,
                            },
                            "impact_threshold": {
                                "type": "number",
                                "description": "Minimum impact score to include in results (default: 5.0)",
                                "minimum": 0.0,
                                "maximum": 10.0,
                                "default": 5.0,
                            },
                        },
                        "required": ["component_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_cwe_details",
                    "description": "Get comprehensive details about a specific CWE (Common Weakness Enumeration) including exploits, attack patterns, and defensive techniques. Essential for understanding weakness-specific threats.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cwe_id": {
                                "type": "string",
                                "description": "CWE identifier (e.g., 'CWE-79', 'CWE-89', 'CWE-502')",
                            }
                        },
                        "required": ["cwe_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_capec_details",
                    "description": "Get detailed information about a specific CAPEC (Common Attack Pattern Enumeration and Classification) including attack prerequisites, typical likelihood, and countermeasures.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "capec_id": {
                                "type": "string",
                                "description": "CAPEC identifier (e.g., 'CAPEC-63', 'CAPEC-88', 'CAPEC-126')",
                            }
                        },
                        "required": ["capec_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_cvss_breakdown",
                    "description": "Get detailed CVSS version breakdown for a specific CVE showing all available CVSS versions and scores to understand scoring evolution and version-specific details.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "CVE identifier (e.g., 'CVE-2021-44228', 'CVE-2023-12345')",
                            }
                        },
                        "required": ["cve_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_related_attack_patterns",
                    "description": "Find related attack patterns for a CVE by traversing CVE→CWE→CAPEC relationships to identify specific exploitation methods and techniques.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "CVE identifier to find attack patterns for (e.g., 'CVE-2021-44228')",
                            },
                            "include_mitigations": {
                                "type": "boolean",
                                "description": "Include defensive techniques and countermeasures (default: true)",
                                "default": True,
                            },
                        },
                        "required": ["cve_id"],
                    },
                },
            },
        ]

    def execute_kg_function(self, function_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute a knowledge graph function call with enhanced error handling and parameter validation.

        Args:
            function_name: Name of the function to execute
            arguments: Arguments for the function

        Returns:
            Function execution results with helpful error messages
        """
        # Allow help command to work without knowledge graph loaded
        if not self.kg_manager.is_loaded() and function_name != "get_help":
            return {"error": "Knowledge graph not loaded"}

        # Validate and potentially auto-correct parameters
        validation_result = self._validate_and_correct_parameters(function_name, arguments)
        if "error" in validation_result:
            return validation_result

        # Use corrected arguments
        corrected_arguments = validation_result.get("arguments", arguments)
        auto_corrections = validation_result.get("auto_corrections", [])

        try:
            # Execute the function
            if function_name == "get_help":
                result = self._generate_help_information()
            elif function_name == "analyze_security_comprehensive":
                result = self.security_analyzer.analyze_security_comprehensive(
                    **corrected_arguments
                )
                # Update context with results for future parameter extraction
                self._update_context_from_result(result)
            elif function_name == "analyze_component":
                result = self.component_analyzer.analyze_component(**corrected_arguments)
            elif function_name == "get_cve_details":
                result = self.component_analyzer.get_cve_details(**corrected_arguments)
            elif function_name == "get_vulnerable_components":
                result = self.query_engine.get_vulnerable_components(**corrected_arguments)
            elif function_name == "trace_vulnerability_chains":
                result = self.security_analyzer.trace_vulnerability_chains(**corrected_arguments)
            elif function_name == "analyze_cwe_patterns":
                result = self.security_analyzer.analyze_cwe_patterns(**corrected_arguments)
            elif function_name == "map_attack_surface":
                result = self.security_analyzer.map_attack_surface(**corrected_arguments)
            elif function_name == "find_vulnerability_clusters":
                result = self.query_engine.find_vulnerability_clusters(**corrected_arguments)
            elif function_name == "analyze_temporal_risk":
                result = self.security_analyzer.analyze_temporal_risk(**corrected_arguments)
            elif function_name == "analyze_supply_chain_impact":
                result = self.component_analyzer.analyze_supply_chain_impact(**corrected_arguments)
            elif function_name == "get_cwe_details":
                result = self.security_analyzer.get_cwe_details(**corrected_arguments)
            elif function_name == "get_capec_details":
                result = self.security_analyzer.get_capec_details(**corrected_arguments)
            elif function_name == "get_cvss_breakdown":
                result = self.component_analyzer.get_cvss_breakdown(**corrected_arguments)
            elif function_name == "find_related_attack_patterns":
                result = self.security_analyzer.find_related_attack_patterns(**corrected_arguments)
            else:
                return {"error": f"Unknown function: {function_name}"}

            # Add auto-correction notes if any were made
            if auto_corrections:
                if isinstance(result, dict):
                    result["_auto_corrections"] = auto_corrections
                    result["_note"] = (
                        f"Auto-corrected {len(auto_corrections)} parameter(s) from context"
                    )

            return result

        except TypeError as e:
            error_msg = str(e)
            return {
                "error": f"Parameter error in {function_name}: {error_msg}",
                "function": function_name,
                "provided_parameters": list(corrected_arguments.keys()),
                "help": self._get_function_help(function_name),
                "suggestion": self._suggest_parameter_fix(function_name, error_msg),
            }
        except Exception as e:
            return {
                "error": f"Function execution failed: {str(e)}",
                "function": function_name,
                "help": "Try calling analyze_security_comprehensive() first to gather required data",
            }

    def auto_extract_parameters(
        self, function_name: str, missing_params: list[str]
    ) -> dict[str, Any]:
        """Automatically extract parameters from previous tool results stored in chat history."""
        # This would need access to chat history, which should be injected if needed
        # For now, return empty dict
        return {}

    def extract_component_name_from_result(self, result: dict[str, Any]) -> str | None:
        """Extract component name from tool result."""
        # Check for exposed_components (from analyze_attack_surface)
        if "exposed_components" in result and result["exposed_components"]:
            for component in result["exposed_components"]:
                if "component" in component:
                    return component["component"]
                if "version_id" in component and "@" in component["version_id"]:
                    return component["version_id"].split("@")[0]

        # Check for vulnerable_components (from get_vulnerable_components)
        if "vulnerable_components" in result and result["vulnerable_components"]:
            for component in result["vulnerable_components"]:
                if "component_name" in component:
                    return component["component_name"]
                if "component_id" in component:
                    return component["component_id"]
                if "version_id" in component and "@" in component["version_id"]:
                    return component["version_id"].split("@")[0]

        # Check for high_risk_components (from analyze_supply_chain_risk)
        if "high_risk_components" in result and result["high_risk_components"]:
            for component in result["high_risk_components"]:
                if "component_name" in component:
                    return component["component_name"]
                if "component_id" in component:
                    return component["component_id"]

        return None

    def extract_cve_id_from_result(self, result: dict[str, Any]) -> str | None:
        """Extract CVE ID from tool result."""
        # Check for direct CVE list
        if "cves" in result and result["cves"]:
            for cve in result["cves"]:
                if isinstance(cve, dict) and "cve_id" in cve:
                    return cve["cve_id"]
                elif isinstance(cve, str) and cve.startswith("CVE-"):
                    return cve

        # Check for cve_details
        if "cve_details" in result and result["cve_details"]:
            for cve in result["cve_details"]:
                if isinstance(cve, dict) and "cve_id" in cve:
                    return cve["cve_id"]

        # Check for vulnerable_components with CVEs
        if "vulnerable_components" in result and result["vulnerable_components"]:
            for component in result["vulnerable_components"]:
                if "cves" in component and component["cves"]:
                    for cve in component["cves"]:
                        if isinstance(cve, dict) and "cve_id" in cve:
                            return cve["cve_id"]
                        elif isinstance(cve, str) and cve.startswith("CVE-"):
                            return cve

        return None

    def generate_auto_followup_calls(
        self, function_name: str, result: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Generate automatic follow-up calls based on tool results."""
        followup_calls = []

        # After analyze_attack_surface, automatically get component details
        if function_name == "analyze_attack_surface":
            if "exposed_components" in result and result["exposed_components"]:
                for component in result["exposed_components"]:
                    if "component" in component:
                        followup_calls.append(
                            {
                                "function_name": "get_component_details",
                                "arguments": {"component_name": component["component"]},
                            }
                        )

        # After get_vulnerable_components, automatically get component details
        if function_name == "get_vulnerable_components":
            if "vulnerable_components" in result and result["vulnerable_components"]:
                for component in result["vulnerable_components"]:
                    if "component_name" in component:
                        followup_calls.append(
                            {
                                "function_name": "get_component_details",
                                "arguments": {"component_name": component["component_name"]},
                            }
                        )
                    elif "component_id" in component:
                        followup_calls.append(
                            {
                                "function_name": "get_component_details",
                                "arguments": {"component_name": component["component_id"]},
                            }
                        )

        # After get_component_details, automatically get CVE details for any CVEs found
        if function_name == "get_component_details":
            cve_ids = []
            # Extract CVE IDs from the result
            if "vulnerabilities" in result and result["vulnerabilities"]:
                for vuln in result["vulnerabilities"]:
                    if isinstance(vuln, dict) and "cve_id" in vuln:
                        cve_ids.append(vuln["cve_id"])

            if "cve_details" in result and result["cve_details"]:
                for cve in result["cve_details"]:
                    if isinstance(cve, dict) and "cve_id" in cve:
                        cve_ids.append(cve["cve_id"])

            # Generate CVE detail calls
            for cve_id in cve_ids[:3]:  # Limit to first 3 CVEs to avoid too many calls
                followup_calls.append(
                    {
                        "function_name": "get_cve_details",
                        "arguments": {"cve_id": cve_id},
                    }
                )

        # After find_vulnerability_clusters, get details for clustered components
        if function_name == "find_vulnerability_clusters":
            if "vulnerable_components" in result and result["vulnerable_components"]:
                for component in result["vulnerable_components"]:
                    if "component_name" in component:
                        followup_calls.append(
                            {
                                "function_name": "get_component_details",
                                "arguments": {"component_name": component["component_name"]},
                            }
                        )

        # Limit total follow-up calls to avoid overwhelming the system
        return followup_calls[:5]

    def _validate_and_correct_parameters(
        self, function_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate parameters and attempt auto-correction from context."""
        auto_corrections = []
        corrected_arguments = arguments.copy()

        # Function-specific parameter validation and auto-correction
        if function_name == "get_cve_details":
            if not arguments.get("cve_id"):
                # Try to auto-fill from recent CVEs
                if self.conversation_context["recent_cves"]:
                    corrected_arguments["cve_id"] = self.conversation_context["recent_cves"][0]
                    auto_corrections.append(
                        f"Auto-filled cve_id with '{corrected_arguments['cve_id']}' from recent analysis"
                    )
                    print(f"   ✓ Auto-corrected CVE ID: {corrected_arguments['cve_id']}")
                    # Return the corrected arguments immediately
                    return {"arguments": corrected_arguments, "auto_corrections": auto_corrections}
                else:
                    recent_cves = self.conversation_context["recent_cves"][:3]
                    error_msg = {
                        "error": "MISSING cve_id PARAMETER - You MUST call get_cve_details with a specific CVE ID",
                        "required_format": "CVE-YYYY-NNNNN",
                        "debug_info": {
                            "received_arguments": arguments,
                            "conversation_context_cves": self.conversation_context["recent_cves"],
                            "suggestion": "This appears to be an argument parsing issue. The LLM may be providing parameters that aren't being received correctly.",
                        },
                    }

                    if recent_cves:
                        error_msg["AVAILABLE_CVES"] = recent_cves
                        error_msg["CORRECT_CALL_EXAMPLE"] = (
                            f"get_cve_details({{'cve_id': '{recent_cves[0]}'}})"
                        )
                        error_msg["INSTRUCTION"] = (
                            f"IMMEDIATELY call: get_cve_details({{'cve_id': '{recent_cves[0]}'}})"
                        )
                    else:
                        error_msg["REQUIRED_FIRST_STEP"] = (
                            "Call analyze_security_comprehensive() to discover CVEs first"
                        )

                    return error_msg
            else:
                # Validate CVE format
                cve_id = corrected_arguments["cve_id"]
                if not re.match(r"^CVE-\d{4}-\d+$", cve_id):
                    return {
                        "error": f"Invalid CVE format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN",
                        "example": "CVE-2021-44228",
                        "provided": cve_id,
                    }

        elif function_name == "analyze_component":
            if not arguments.get("component_name"):
                # Try to auto-fill from recent components
                if self.conversation_context["recent_components"]:
                    corrected_arguments["component_name"] = self.conversation_context[
                        "recent_components"
                    ][0]
                    auto_corrections.append(
                        f"Auto-filled component_name with '{corrected_arguments['component_name']}' from recent analysis"
                    )
                    print(f"   ✓ Auto-corrected component: {corrected_arguments['component_name']}")
                else:
                    return {
                        "error": "Missing required parameter 'component_name'. Please provide a component name like 'flask' or 'numpy'",
                        "help": "First call analyze_security_comprehensive() to discover components, then extract component names from the response",
                        "example": "analyze_security_comprehensive() → extract component → analyze_component({'component_name': 'flask'})",
                        "debug_info": {
                            "received_arguments": arguments,
                            "conversation_context_components": self.conversation_context[
                                "recent_components"
                            ],
                        },
                    }

        elif function_name == "get_cwe_details":
            if not arguments.get("cwe_id"):
                # Try to auto-fill from recent CWEs
                if self.conversation_context["recent_cwes"]:
                    corrected_arguments["cwe_id"] = self.conversation_context["recent_cwes"][0]
                    auto_corrections.append(
                        f"Auto-filled cwe_id with '{corrected_arguments['cwe_id']}' from recent analysis"
                    )
                    print(f"   ✓ Auto-corrected CWE ID: {corrected_arguments['cwe_id']}")
                else:
                    return {
                        "error": "Missing required parameter 'cwe_id'. Please provide a CWE ID like 'CWE-79'",
                        "help": "First call analyze_security_comprehensive() to discover CWEs, then extract CWE IDs from the response",
                        "debug_info": {
                            "received_arguments": arguments,
                            "conversation_context_cwes": self.conversation_context["recent_cwes"],
                        },
                    }

        return {"arguments": corrected_arguments, "auto_corrections": auto_corrections}

    def _update_context_from_result(self, result: dict[str, Any]) -> None:
        """Update conversation context with data from function results."""
        if not isinstance(result, dict):
            return

        # Store the complete result
        self.conversation_context["last_analysis_result"] = result

        # Extract and store CVE IDs
        cve_ids = []

        # Look for CVEs in multiple possible locations
        cve_sources = ["cves", "all_cves"]
        for cve_key in cve_sources:
            if cve_key in result and isinstance(result[cve_key], list):
                for cve in result[cve_key]:
                    if isinstance(cve, dict) and "cve_id" in cve:
                        cve_ids.append(cve["cve_id"])
                    elif isinstance(cve, str):
                        cve_ids.append(cve)
                break  # Use the first source that contains data

        if cve_ids:
            self.conversation_context["recent_cves"] = cve_ids[:10]  # Keep last 10

        # Extract and store component names
        components = []
        if "vulnerable_components" in result:
            for comp in result["vulnerable_components"]:
                if isinstance(comp, dict):
                    if "component_name" in comp:
                        components.append(comp["component_name"])
                    elif "name" in comp:
                        components.append(comp["name"])

        if "components" in result:
            for comp in result["components"]:
                if isinstance(comp, dict) and "name" in comp:
                    components.append(comp["name"])
                elif isinstance(comp, str):
                    components.append(comp)

        self.conversation_context["recent_components"] = list(set(components))[:10]

        # Extract and store CWE IDs
        cwe_ids = []

        # Look for CWEs in multiple possible locations
        cwe_sources = ["cwes", "all_cwes"]
        for cwe_key in cwe_sources:
            if cwe_key in result and isinstance(result[cwe_key], list):
                for cwe in result[cwe_key]:
                    if isinstance(cwe, dict) and "cwe_id" in cwe:
                        cwe_ids.append(cwe["cwe_id"])
                    elif isinstance(cwe, str):
                        cwe_ids.append(cwe)
                break  # Use the first source that contains data

        if cwe_ids:
            self.conversation_context["recent_cwes"] = cwe_ids[:10]

    def _get_function_help(self, function_name: str) -> str:
        """Get helpful information about a function and its parameters."""
        help_text = {
            "get_help": "Get comprehensive help. Use topic parameter: 'overview', 'tools', 'workflow', 'examples', or 'troubleshooting'.",
            "get_cve_details": "Requires 'cve_id' parameter. Call analyze_security_comprehensive() first to discover CVEs.",
            "analyze_component": "Requires 'component_name' parameter. Call analyze_security_comprehensive() first to discover components.",
            "get_cwe_details": "Requires 'cwe_id' parameter. Call analyze_security_comprehensive() first to discover CWEs.",
            "get_capec_details": "Requires 'capec_id' parameter. Call analyze_security_comprehensive() first to discover attack patterns.",
            "analyze_security_comprehensive": "Primary analysis function. Use focus parameter: 'comprehensive', 'critical', 'patterns', or 'components'.",
        }
        return help_text.get(
            function_name, "No specific help available. Check function documentation."
        )

    def _suggest_parameter_fix(self, function_name: str, error_msg: str) -> str:
        """Suggest how to fix parameter errors based on the error message."""
        if "missing" in error_msg.lower() and "positional argument" in error_msg:
            return f"Call analyze_security_comprehensive() first to gather data, then extract required parameters for {function_name}"
        elif "unexpected keyword argument" in error_msg:
            return (
                f"Check parameter names for {function_name}. Available parameters may have changed."
            )
        else:
            return f"Verify parameter types and names for {function_name}. Try calling with empty parameters {{}} if optional."

    def clear_conversation_context(self) -> None:
        """Clear the conversation context. Useful for starting fresh conversations."""
        self.conversation_context = {
            "recent_cves": [],
            "recent_components": [],
            "recent_cwes": [],
            "last_analysis_result": None,
        }

    def get_conversation_context(self) -> dict[str, Any]:
        """Get current conversation context for debugging purposes."""
        return self.conversation_context.copy()

    def get_available_context_data(self) -> dict[str, Any]:
        """Get available data that can be used for auto-parameter filling."""
        if not self.kg_manager.is_loaded():
            return {"error": "Knowledge graph not loaded"}

        # Get sample CVEs, components, etc. from the knowledge graph
        try:
            cve_nodes = list(self.kg_manager.get_nodes_by_type("CVE").items())[:5]
            component_nodes = list(self.kg_manager.get_nodes_by_type("Component").items())[:5]

            return {
                "recent_context": self.conversation_context,
                "sample_cves": [node_id for node_id, _ in cve_nodes],
                "sample_components": [
                    node.get("name", node_id) for node_id, node in component_nodes
                ],
                "context_size": {
                    "recent_cves": len(self.conversation_context["recent_cves"]),
                    "recent_components": len(self.conversation_context["recent_components"]),
                    "recent_cwes": len(self.conversation_context["recent_cwes"]),
                },
            }
        except Exception as e:
            return {"error": f"Failed to get context data: {str(e)}"}

    def _generate_help_information(self) -> dict[str, Any]:
        """Generate concise help information showing available commands and usage scenarios."""

        tools = self.get_kg_tools()

        return {
            "system_role": "SBOM Security Analysis Assistant",
            "purpose": "I analyze SBOMs for security vulnerabilities, components, and attack patterns",
            "available_commands": len(tools),
            "help_content": self._build_cli_help(tools),
        }

    def _build_cli_help(self, tools: list[dict[str, Any]]) -> str:
        """Build CLI-style help showing available commands and usage scenarios."""

        # Core analysis commands
        core_commands = [
            (
                "analyze_security_comprehensive",
                "Get overview of all vulnerabilities and components - START HERE",
            ),
            (
                "get_vulnerable_components",
                "List components with vulnerabilities above severity threshold",
            ),
            ("analyze_component", "Deep dive into specific component (requires component name)"),
        ]

        # Vulnerability analysis commands
        vuln_commands = [
            (
                "get_cve_details",
                "Get detailed CVE information (requires CVE ID from previous analysis)",
            ),
            ("trace_vulnerability_chains", "Follow CVE→CWE→CAPEC attack chains"),
            ("find_related_attack_patterns", "Find attack methods for a CVE"),
            ("get_cvss_breakdown", "Get detailed CVSS scoring for a CVE"),
        ]

        # Risk analysis commands
        risk_commands = [
            ("map_attack_surface", "Identify exposed components and entry points"),
            ("find_vulnerability_clusters", "Group components with similar vulnerability patterns"),
            ("analyze_temporal_risk", "Analyze vulnerability age and patch status"),
            ("analyze_supply_chain_impact", "Assess supply chain risks for component"),
        ]

        # Pattern analysis commands
        pattern_commands = [
            ("analyze_cwe_patterns", "Group vulnerabilities by weakness types"),
            ("get_cwe_details", "Get weakness details (requires CWE ID)"),
            ("get_capec_details", "Get attack pattern details (requires CAPEC ID)"),
        ]

        help_text = """SBOM Security Analysis Assistant

USAGE PATTERN:
  1. Start with: analyze_security_comprehensive()
  2. Extract IDs (CVE-2021-44228, component names) from results
  3. Use specific commands for detailed analysis

CORE ANALYSIS:"""

        for cmd, desc in core_commands:
            help_text += f"\n  {cmd:<35} {desc}"

        help_text += "\n\nVULNERABILITY ANALYSIS:"
        for cmd, desc in vuln_commands:
            help_text += f"\n  {cmd:<35} {desc}"

        help_text += "\n\nRISK ANALYSIS:"
        for cmd, desc in risk_commands:
            help_text += f"\n  {cmd:<35} {desc}"

        help_text += "\n\nPATTERN ANALYSIS:"
        for cmd, desc in pattern_commands:
            help_text += f"\n  {cmd:<35} {desc}"

        help_text += """

PARAMETER TIPS:
  • CVE IDs: Extract from analyze_security_comprehensive() results
  • Component names: Use exact names from SBOM (e.g., 'flask', 'numpy')
  • Most commands work without parameters, use defaults
  • System auto-corrects parameters when possible

Use analyze_security_comprehensive() first to discover available data."""

        return help_text

    def _categorize_tool(self, tool_name: str) -> str:
        """Categorize a tool based on its name and purpose."""
        if tool_name in ["analyze_security_comprehensive", "get_help"]:
            return "core"
        elif tool_name in [
            "analyze_component",
            "get_vulnerable_components",
            "analyze_supply_chain_impact",
        ]:
            return "component_analysis"
        elif tool_name in ["get_cve_details", "get_cvss_breakdown"]:
            return "vulnerability_details"
        elif tool_name in ["get_cwe_details", "get_capec_details", "analyze_cwe_patterns"]:
            return "weakness_analysis"
        elif tool_name in [
            "trace_vulnerability_chains",
            "find_related_attack_patterns",
            "map_attack_surface",
        ]:
            return "attack_analysis"
        elif tool_name in ["find_vulnerability_clusters", "analyze_temporal_risk"]:
            return "risk_analysis"
        else:
            return "utility"

    def _group_tools_by_category(
        self, tool_details: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Group tools by category for better organization."""
        categories = {}
        for tool in tool_details:
            category = tool["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(tool)
        return categories
