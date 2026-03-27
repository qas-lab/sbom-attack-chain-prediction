from enum import Enum
from typing import Any


class KGNodeType(Enum):
    """Defines the types of nodes in the Knowledge Graph."""

    CVE = "CVE"
    CWE = "CWE"
    CAPEC = "CAPEC"
    COMPONENT = "Component"
    VERSION = "Version"
    SBOM = "SBOM"
    REPOSITORY = "Repository"
    VULNERABILITY_TYPE = "VulnerabilityType"  # e.g., SQL Injection
    ATTACK_VECTOR = "AttackVector"  # e.g., Network, Local
    SEVERITY = "Severity"  # e.g., CRITICAL, HIGH
    LICENSE = "License"  # e.g., MIT, Apache-2.0
    ECOSYSTEM = "Ecosystem"  # e.g., npm, pypi, maven

    # MITRE ATT&CK Framework nodes
    ATTACK_TECHNIQUE = "AttackTechnique"  # ATT&CK techniques (T1055, etc.)
    ATTACK_TACTIC = "AttackTactic"  # ATT&CK tactics (initial-access, etc.)
    THREAT_ACTOR = "ThreatActor"  # APT groups and threat actors
    MALWARE = "Malware"  # Malicious software
    TOOL = "Tool"  # Attack tools

    # Threat Intelligence nodes
    IOC = "IndicatorOfCompromise"  # IPs, domains, hashes, etc.
    THREAT_SIGNATURE = "ThreatSignature"  # Detection signatures
    CAMPAIGN = "Campaign"  # Threat campaigns
    INCIDENT = "Incident"  # Security incidents

    # Defensive nodes (D3FEND-inspired)
    DEFENSIVE_TECHNIQUE = "DefensiveTechnique"  # D3FEND techniques
    COUNTERMEASURE = "Countermeasure"  # Security controls
    ARTIFACT = "Artifact"  # Digital artifacts

    # Temporal and contextual nodes
    EXPLOIT = "Exploit"  # Exploit code/PoCs
    PATCH = "Patch"  # Security patches
    DISCLOSURE = "Disclosure"  # Vulnerability disclosures


class KGRelationshipType(Enum):
    """Defines the types of relationships in the Knowledge Graph."""

    # CVE-CWE relationships
    HAS_CWE = "HAS_CWE"
    IS_PARENT_OF = "IS_PARENT_OF"  # For hierarchical CWEs
    EXPLOITS_CWE = "EXPLOITS_CWE"

    # Component-Vulnerability relationships
    AFFECTS_COMPONENT = "AFFECTS_COMPONENT"
    AFFECTS_VERSION_RANGE = "AFFECTS_VERSION_RANGE"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"

    # Component-Component relationships
    DEPENDS_ON = "DEPENDS_ON"
    DEV_DEPENDS_ON = "DEV_DEPENDS_ON"
    OPTIONAL_DEPENDS_ON = "OPTIONAL_DEPENDS_ON"

    # Component metadata relationships
    HAS_VERSION = "HAS_VERSION"
    HAS_LICENSE = "HAS_LICENSE"
    BELONGS_TO_ECOSYSTEM = "BELONGS_TO_ECOSYSTEM"

    # SBOM relationships
    CONTAINS_COMPONENT = "CONTAINS_COMPONENT"
    SCANNED_FROM_REPOSITORY = "SCANNED_FROM_REPOSITORY"
    GENERATED_BY_TOOL = "GENERATED_BY_TOOL"

    # Security relationships
    HAS_ATTACK_VECTOR = "HAS_ATTACK_VECTOR"
    HAS_SEVERITY = "HAS_SEVERITY"
    PREDICTED_EXPLOITABILITY = "PREDICTED_EXPLOITABILITY"  # GNN prediction

    # Attack chain relationships
    ENABLES_ATTACK = "ENABLES_ATTACK"
    AMPLIFIES_RISK = "AMPLIFIES_RISK"
    CREATES_ATTACK_PATH = "CREATES_ATTACK_PATH"

    # MITRE ATT&CK relationships
    USES_TECHNIQUE = "USES_TECHNIQUE"  # Threat actor uses technique
    ACHIEVES_TACTIC = "ACHIEVES_TACTIC"  # Technique achieves tactic
    ENABLES_TECHNIQUE = "ENABLES_TECHNIQUE"  # Tool/malware enables technique
    PART_OF_CAMPAIGN = "PART_OF_CAMPAIGN"  # Attack part of campaign
    ATTRIBUTED_TO = "ATTRIBUTED_TO"  # Attack attributed to threat actor

    # Defensive relationships
    DEFENDS_AGAINST = "DEFENDS_AGAINST"  # Countermeasure defends against technique
    MITIGATED_BY = "MITIGATED_BY"  # Technique mitigated by countermeasure
    OPERATES_ON = "OPERATES_ON"  # Defensive technique operates on artifact
    IMPLEMENTED_BY = "IMPLEMENTED_BY"  # Countermeasure implemented by component

    # Threat intelligence relationships
    INDICATES_COMPROMISE = "INDICATES_COMPROMISE"  # IOC indicates compromise
    ASSOCIATED_WITH_CAMPAIGN = "ASSOCIATED_WITH_CAMPAIGN"  # IOC associated with campaign
    EXPLOITED_BY = "EXPLOITED_BY"  # CVE exploited by threat actor/malware
    USED_IN_INCIDENT = "USED_IN_INCIDENT"  # Technique/malware used in incident

    # Temporal relationships
    DISCLOSED_BY = "DISCLOSED_BY"  # CVE disclosed by researcher/vendor
    PATCHED_BY = "PATCHED_BY"  # CVE patched by patch
    EXPLOITED_IN = "EXPLOITED_IN"  # CVE exploited in incident
    DISCOVERED_ON = "DISCOVERED_ON"  # Temporal discovery relationship
    SUPERSEDED_BY = "SUPERSEDED_BY"  # Patch superseded by newer patch


class KGNodeSchema:
    """Defines the schema for different node types in the Knowledge Graph."""

    @staticmethod
    def get_node_schema(node_type: KGNodeType) -> dict[str, Any]:
        """Returns the expected schema for a given node type."""
        schemas = {
            KGNodeType.CVE: {
                "required": ["id", "published", "lastModified"],
                "optional": [
                    "sourceIdentifier",
                    "vulnStatus",
                    "descriptions",
                    "metrics",
                    "references",
                ],
                "id_format": "CVE-YYYY-NNNN",
            },
            KGNodeType.CWE: {
                "required": ["id", "name"],
                "optional": [
                    "description",
                    "extended_description",
                    "related_weaknesses",
                ],
                "id_format": "CWE-NNN",
            },
            KGNodeType.CAPEC: {
                "required": ["id", "name"],
                "optional": ["description", "typical_severity", "related_cwes"],
                "id_format": "CAPEC-NNN",
            },
            KGNodeType.COMPONENT: {
                "required": ["id", "name", "ecosystem"],
                "optional": [
                    "description",
                    "homepage",
                    "repository_url",
                    "download_url",
                ],
                "id_format": "purl_without_version",
            },
            KGNodeType.VERSION: {
                "required": ["id", "version", "component_id"],
                "optional": [
                    "release_date",
                    "is_vulnerable",
                    "vulnerability_count",
                    "max_cvss_score",
                ],
                "id_format": "component_id@version",
            },
            KGNodeType.SBOM: {
                "required": ["id", "bomFormat", "specVersion"],
                "optional": [
                    "serialNumber",
                    "version",
                    "metadata",
                    "created_at",
                    "tool_name",
                ],
                "id_format": "sbom_hash_or_uuid",
            },
            KGNodeType.REPOSITORY: {
                "required": ["id", "url", "owner", "name"],
                "optional": [
                    "description",
                    "stars",
                    "forks",
                    "primary_language",
                    "last_updated",
                ],
                "id_format": "github.com/owner/repo",
            },
            KGNodeType.LICENSE: {
                "required": ["id", "name"],
                "optional": ["url", "osi_approved", "is_copyleft"],
                "id_format": "license_identifier",
            },
            KGNodeType.ECOSYSTEM: {
                "required": ["id", "name"],
                "optional": ["description", "package_manager", "registry_url"],
                "id_format": "ecosystem_name",
            },
        }
        return schemas.get(node_type, {"required": ["id"], "optional": []})


class KGRelationshipSchema:
    """Defines the schema for different relationship types in the Knowledge Graph."""

    @staticmethod
    def get_relationship_schema(rel_type: KGRelationshipType) -> dict[str, Any]:
        """Returns the expected schema for a given relationship type."""
        schemas = {
            KGRelationshipType.DEPENDS_ON: {
                "required": ["source_id", "target_id"],
                "optional": [
                    "dependency_type",
                    "version_constraint",
                    "is_direct",
                    "scope",
                ],
                "source_types": [KGNodeType.COMPONENT, KGNodeType.VERSION],
                "target_types": [KGNodeType.COMPONENT, KGNodeType.VERSION],
            },
            KGRelationshipType.HAS_VULNERABILITY: {
                "required": ["source_id", "target_id"],
                "optional": [
                    "cvss_score",
                    "severity",
                    "fixed_version",
                    "introduced_version",
                ],
                "source_types": [KGNodeType.COMPONENT, KGNodeType.VERSION],
                "target_types": [KGNodeType.CVE],
            },
            KGRelationshipType.AFFECTS_VERSION_RANGE: {
                "required": ["source_id", "target_id"],
                "optional": ["version_range", "fixed_versions", "introduced_versions"],
                "source_types": [KGNodeType.CVE],
                "target_types": [KGNodeType.COMPONENT],
            },
            KGRelationshipType.CONTAINS_COMPONENT: {
                "required": ["source_id", "target_id"],
                "optional": ["is_direct", "dependency_depth", "scope"],
                "source_types": [KGNodeType.SBOM],
                "target_types": [KGNodeType.COMPONENT, KGNodeType.VERSION],
            },
            KGRelationshipType.PREDICTED_EXPLOITABILITY: {
                "required": ["source_id", "target_id", "score"],
                "optional": ["confidence", "model_version", "features_used"],
                "source_types": [KGNodeType.COMPONENT, KGNodeType.VERSION],
                "target_types": [KGNodeType.CVE],
            },
            KGRelationshipType.CREATES_ATTACK_PATH: {
                "required": ["source_id", "target_id"],
                "optional": ["attack_complexity", "path_length", "risk_amplification"],
                "source_types": [KGNodeType.CVE],
                "target_types": [KGNodeType.CVE],
            },
        }
        return schemas.get(rel_type, {"required": ["source_id", "target_id"], "optional": []})
