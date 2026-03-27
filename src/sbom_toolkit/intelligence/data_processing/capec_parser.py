import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import requests
from requests.exceptions import RequestException


class CAPECParser:
    """Handles fetching and parsing of CAPEC data."""

    CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

    def __init__(self, cache_dir: Path = Path("data/capec_cache")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.capec_file = self.cache_dir / "capec_latest.xml"
        self.logger = logging.getLogger(__name__)

    def _fetch_data(self):
        """Fetches the latest CAPEC XML data."""
        print(f"Fetching CAPEC data from {self.CAPEC_URL}...")
        response = requests.get(self.CAPEC_URL)
        response.raise_for_status()
        with open(self.capec_file, "wb") as f:
            f.write(response.content)
        print(f"CAPEC data saved to {self.capec_file}")

    def get_capec_data(self) -> list[dict[str, Any]]:
        """Parses the CAPEC XML data and returns a list of CAPECs."""
        if not self.capec_file.exists():
            self._fetch_data()

        print(f"Parsing CAPEC data from {self.capec_file}...")
        tree = ET.parse(self.capec_file)
        root = tree.getroot()

        # Handle XML namespace if present
        namespace = None
        if "}" in root.tag:
            namespace = root.tag.split("}")[0][1:]

        ns = {"capec": namespace} if namespace else {}

        capec_list = []
        # Look for Attack_Pattern elements with proper namespace handling
        if namespace:
            attack_pattern_elements = root.findall(".//capec:Attack_Pattern", ns)
        else:
            attack_pattern_elements = root.findall(".//Attack_Pattern")

        for attack_pattern in attack_pattern_elements:
            capec_id = attack_pattern.get("ID")
            name = attack_pattern.get("Name")

            # Find description with namespace handling
            if namespace:
                description_elem = attack_pattern.find("capec:Description", ns)
            else:
                description_elem = attack_pattern.find("Description")

            # Extract associated CWEs from Related_Weaknesses section
            related_cwes = []
            if namespace:
                related_weaknesses = attack_pattern.findall(
                    ".//capec:Related_Weaknesses/capec:Related_Weakness", ns
                )
            else:
                related_weaknesses = attack_pattern.findall(
                    ".//Related_Weaknesses/Related_Weakness"
                )

            for weakness in related_weaknesses:
                cwe_id = weakness.get("CWE_ID")
                if cwe_id:
                    related_cwes.append(f"CWE-{cwe_id}")

            # Also check for older relationship format (backup)
            if namespace:
                relationships = attack_pattern.findall(".//capec:Relationship", ns)
            else:
                relationships = attack_pattern.findall(".//Relationship")

            for relationship in relationships:
                rel_nature = relationship.get("Relationship_Nature")
                if rel_nature in [
                    "ChildOf",
                    "CanFollow",
                    "CanPrecede",
                    "RequiredBy",
                    "Exploits",
                ]:
                    if namespace:
                        targets = relationship.findall(".//capec:Relationship_Target", ns)
                    else:
                        targets = relationship.findall(".//Relationship_Target")
                    for target in targets:
                        if target.get("Relationship_Target_Form") == "CWE":
                            related_cwes.append(f"CWE-{target.get('Relationship_Target_ID')}")

            # Extract CWE references from text content as additional backup
            import re

            if namespace:
                text_elements = attack_pattern.findall(
                    ".//capec:Prerequisites/capec:Prerequisite", ns
                ) + attack_pattern.findall(".//capec:Consequences/capec:Consequence", ns)
            else:
                text_elements = attack_pattern.findall(
                    ".//Prerequisites/Prerequisite"
                ) + attack_pattern.findall(".//Consequences/Consequence")

            for elem in text_elements:
                if elem.text:
                    cwe_matches = re.findall(r"CWE-\d+", elem.text)
                    related_cwes.extend(cwe_matches)

            if capec_id and name and description_elem is not None:
                capec_list.append(
                    {
                        "id": f"CAPEC-{capec_id}",
                        "name": name,
                        "description": (
                            description_elem.text.strip() if description_elem.text else ""
                        ),
                        "related_cwes": related_cwes,
                    }
                )
        self.logger.debug(f"Parsed {len(capec_list)} CAPECs.")
        return capec_list


if __name__ == "__main__":
    parser = CAPECParser()
    try:
        capec_data = parser.get_capec_data()
        if capec_data:
            print("\nSample CAPEC:")
            import json

            print(json.dumps(capec_data[0], indent=2))
    except RequestException as e:
        print(f"Error fetching CAPEC data: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
