from typing import Any

from ..schema import KGNodeType, KGRelationshipType
from .base_processor import BaseProcessor


class AttackProcessor(BaseProcessor):
    """Processor for MITRE ATT&CK data."""

    def process(self, data: Any, *args: Any, **kwargs: Any) -> dict[str, int]:
        """Builds graph components from MITRE ATT&CK data.

        Args:
            data: Dictionary containing ATT&CK data (tactics, techniques, groups, software, etc.)

        Returns:
            Statistics about processed data
        """
        attack_data = data
        stats = {
            "tactic_count": 0,
            "technique_count": 0,
            "group_count": 0,
            "malware_count": 0,
            "tool_count": 0,
            "relationship_count": 0,
        }

        # Add tactics
        for tactic in attack_data.get("tactics", []):
            tactic_id = tactic.get("id")
            if tactic_id:
                self.add_node(KGNodeType.ATTACK_TACTIC, tactic_id, tactic)
                stats["tactic_count"] += 1

        # Add techniques
        for technique in attack_data.get("techniques", []):
            technique_id = technique.get("id")
            if technique_id:
                self.add_node(KGNodeType.ATTACK_TECHNIQUE, technique_id, technique)
                stats["technique_count"] += 1

                # Link techniques to tactics via kill chain phases
                for phase in technique.get("kill_chain_phases", []):
                    # Map kill chain phase to tactic (this might need refinement)
                    tactic_mapping = {
                        "initial-access": "TA0001",
                        "execution": "TA0002",
                        "persistence": "TA0003",
                        "privilege-escalation": "TA0004",
                        "defense-evasion": "TA0005",
                        "credential-access": "TA0006",
                        "discovery": "TA0007",
                        "lateral-movement": "TA0008",
                        "collection": "TA0009",
                        "command-and-control": "TA0011",
                        "exfiltration": "TA0010",
                        "impact": "TA0040",
                    }

                    if phase in tactic_mapping:
                        tactic_id = tactic_mapping[phase]
                        self.add_edge(
                            KGNodeType.ATTACK_TECHNIQUE,
                            technique_id,
                            KGNodeType.ATTACK_TACTIC,
                            tactic_id,
                            KGRelationshipType.ACHIEVES_TACTIC,
                        )
                        stats["relationship_count"] += 1

        # Add threat groups/actors
        for group in attack_data.get("groups", []):
            group_id = group.get("id")
            if group_id:
                self.add_node(KGNodeType.THREAT_ACTOR, group_id, group)
                stats["group_count"] += 1

        # Add software (malware and tools)
        for software in attack_data.get("software", []):
            software_id = software.get("id")
            software_type = software.get("type", "")
            if software_id:
                if software_type == "malware":
                    self.add_node(KGNodeType.MALWARE, software_id, software)
                    stats["malware_count"] += 1
                elif software_type == "tool":
                    self.add_node(KGNodeType.TOOL, software_id, software)
                    stats["tool_count"] += 1

        # Process relationships
        for relationship in attack_data.get("relationships", []):
            if self._process_attack_relationship(relationship):
                stats["relationship_count"] += 1

        return stats

    def _process_attack_relationship(self, relationship: dict[str, Any]) -> bool:
        """Process ATT&CK relationships between objects.

        Returns:
            True if relationship was processed, False otherwise
        """
        source_ref = relationship.get("source_ref", "")
        target_ref = relationship.get("target_ref", "")
        rel_type = relationship.get("relationship_type", "")

        if not all([source_ref, target_ref, rel_type]):
            return False

        # Extract IDs from STIX references (format: attack-pattern--uuid)
        source_type, source_id = self._extract_attack_id_from_ref(source_ref)
        target_type, target_id = self._extract_attack_id_from_ref(target_ref)

        if not all([source_type, source_id, target_type, target_id]):
            return False

        # Map STIX relationship types to our KG relationships
        relationship_mapping = {
            "uses": KGRelationshipType.USES_TECHNIQUE,
            "mitigates": KGRelationshipType.MITIGATED_BY,
            "detects": KGRelationshipType.INDICATES_COMPROMISE,
        }

        if (
            rel_type in relationship_mapping
            and source_type
            and source_id
            and target_type
            and target_id
        ):
            kg_rel_type = relationship_mapping[rel_type]
            self.add_edge(source_type, source_id, target_type, target_id, kg_rel_type)
            return True

        return False

    def _extract_attack_id_from_ref(self, stix_ref: str) -> tuple[KGNodeType | None, str | None]:
        """Extract ATT&CK ID and type from STIX reference."""
        # This is a simplified mapping - in reality you'd need to store the mapping
        # between STIX UUIDs and ATT&CK IDs during parsing
        type_mapping = {
            "attack-pattern": KGNodeType.ATTACK_TECHNIQUE,
            "x-mitre-tactic": KGNodeType.ATTACK_TACTIC,
            "intrusion-set": KGNodeType.THREAT_ACTOR,
            "malware": KGNodeType.MALWARE,
            "tool": KGNodeType.TOOL,
        }

        if "--" in stix_ref:
            stix_type = stix_ref.split("--")[0]
            if stix_type in type_mapping:
                # In a real implementation, you'd maintain a UUID->ID mapping
                return type_mapping[stix_type], stix_ref

        return None, None
