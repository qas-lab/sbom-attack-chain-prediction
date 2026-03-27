"""
MITRE ATT&CK data parser for knowledge graph enhancement.
"""

import json
from pathlib import Path
from typing import Any

import requests


class MITREAttackParser:
    """Handles fetching and parsing of MITRE ATT&CK data."""

    # MITRE ATT&CK STIX data URL
    ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def __init__(self, cache_dir: Path = Path("data/attack_cache")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.attack_file = self.cache_dir / "enterprise-attack.json"

    def _fetch_data(self):
        """Fetches the latest MITRE ATT&CK STIX data."""
        print(f"Fetching MITRE ATT&CK data from {self.ATTACK_URL}...")
        response = requests.get(self.ATTACK_URL)
        response.raise_for_status()

        with open(self.attack_file, "w") as f:
            f.write(response.text)
        print(f"ATT&CK data saved to {self.attack_file}")

    def get_attack_data(self) -> dict[str, list[dict[str, Any]]]:
        """Parses ATT&CK STIX data and returns organized data."""
        if not self.attack_file.exists():
            self._fetch_data()

        print(f"Parsing ATT&CK data from {self.attack_file}...")
        with open(self.attack_file) as f:
            data = json.load(f)

        # Organize by object type
        organized_data = {
            "techniques": [],
            "tactics": [],
            "groups": [],
            "software": [],
            "relationships": [],
        }

        for obj in data.get("objects", []):
            obj_type = obj.get("type", "")

            if obj_type == "attack-pattern":
                # These are techniques
                technique_data = self._parse_technique(obj)
                if technique_data:
                    organized_data["techniques"].append(technique_data)

            elif obj_type == "x-mitre-tactic":
                # These are tactics
                tactic_data = self._parse_tactic(obj)
                if tactic_data:
                    organized_data["tactics"].append(tactic_data)

            elif obj_type == "intrusion-set":
                # These are threat groups
                group_data = self._parse_group(obj)
                if group_data:
                    organized_data["groups"].append(group_data)

            elif obj_type == "malware" or obj_type == "tool":
                # These are software/tools
                software_data = self._parse_software(obj)
                if software_data:
                    organized_data["software"].append(software_data)

            elif obj_type == "relationship":
                # These connect different objects
                rel_data = self._parse_relationship(obj)
                if rel_data:
                    organized_data["relationships"].append(rel_data)

        print(
            f"Parsed {len(organized_data['techniques'])} techniques, "
            f"{len(organized_data['tactics'])} tactics, "
            f"{len(organized_data['groups'])} groups, "
            f"{len(organized_data['software'])} software, "
            f"{len(organized_data['relationships'])} relationships"
        )

        return organized_data

    def _parse_technique(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        """Parse ATT&CK technique object."""
        external_refs = obj.get("external_references", [])
        technique_id = None

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        if not technique_id:
            return None

        return {
            "id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "kill_chain_phases": [
                phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])
            ],
            "mitigations": [],  # Will be populated via relationships
            "detection": obj.get("x_mitre_detection", ""),
            "permissions": obj.get("x_mitre_permissions_required", []),
            "is_subtechnique": "." in technique_id,
        }

    def _parse_tactic(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        """Parse ATT&CK tactic object."""
        external_refs = obj.get("external_references", [])
        tactic_id = None

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                tactic_id = ref.get("external_id")
                break

        if not tactic_id:
            return None

        return {
            "id": tactic_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "short_name": obj.get("x_mitre_shortname", ""),
        }

    def _parse_group(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        """Parse threat group object."""
        external_refs = obj.get("external_references", [])
        group_id = None

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id")
                break

        if not group_id:
            return None

        return {
            "id": group_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "aliases": obj.get("aliases", []),
        }

    def _parse_software(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        """Parse software/tool object."""
        external_refs = obj.get("external_references", [])
        software_id = None

        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                software_id = ref.get("external_id")
                break

        if not software_id:
            return None

        return {
            "id": software_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "type": obj.get("type", ""),  # malware or tool
            "platforms": obj.get("x_mitre_platforms", []),
            "aliases": obj.get("x_mitre_aliases", []),
        }

    def _parse_relationship(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        """Parse relationship object."""
        return {
            "source_ref": obj.get("source_ref", ""),
            "target_ref": obj.get("target_ref", ""),
            "relationship_type": obj.get("relationship_type", ""),
            "description": obj.get("description", ""),
        }


if __name__ == "__main__":
    parser = MITREAttackParser()
    try:
        attack_data = parser.get_attack_data()
        print("\nSample Technique:")
        if attack_data["techniques"]:
            print(json.dumps(attack_data["techniques"][0], indent=2))

        print("\nSample Tactic:")
        if attack_data["tactics"]:
            print(json.dumps(attack_data["tactics"][0], indent=2))

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
