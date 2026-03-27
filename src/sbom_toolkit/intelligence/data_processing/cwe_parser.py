import json
import logging
import sys
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests
from requests.exceptions import RequestException


class CWEParser:
    """Handles fetching and parsing of CWE data."""

    CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml"

    def __init__(self, cache_dir: Path = Path("data/cwe_cache")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cwe_file = self.cache_dir / "cwec_latest.xml"
        self.logger = logging.getLogger(__name__)

    def _fetch_data(self):
        """Fetches the latest CWE XML data."""
        self.logger.debug(f"Fetching CWE data from {self.CWE_URL}...")
        response = requests.get(self.CWE_URL)
        response.raise_for_status()
        with open(self.cwe_file, "wb") as f:
            f.write(response.content)
        self.logger.debug(f"CWE data saved to {self.cwe_file}")

    def get_cwe_data(self) -> list[dict[str, Any]]:
        """Parses the CWE XML data and returns a list of CWEs."""
        if not self.cwe_file.exists():
            self._fetch_data()

        self.logger.debug(f"Parsing CWE data from {self.cwe_file}...")

        # Handle the fact that the CWE file is actually a zip file
        try:
            with zipfile.ZipFile(self.cwe_file, "r") as zip_ref:
                # Find the XML file inside the zip
                xml_files = [f for f in zip_ref.namelist() if f.endswith(".xml")]
                if not xml_files:
                    raise ValueError("No XML file found in the CWE zip archive")

                xml_file = xml_files[0]  # Use the first XML file
                self.logger.debug(f"Extracting XML file: {xml_file}")

                with zip_ref.open(xml_file) as xml_data:
                    tree = ET.parse(xml_data)
                    root = tree.getroot()
        except zipfile.BadZipFile:
            # If it's not a zip file, try parsing it directly as XML
            tree = ET.parse(self.cwe_file)
            root = tree.getroot()

        # Handle XML namespace if present
        namespace = None
        if "}" in root.tag:
            namespace = root.tag.split("}")[0][1:]

        ns = {"cwe": namespace} if namespace else {}

        cwe_list = []
        # Look for Weakness elements with proper namespace handling
        if namespace:
            weakness_elements = root.findall(".//cwe:Weakness", ns)
        else:
            weakness_elements = root.findall(".//Weakness")

        for weakness in weakness_elements:
            cwe_id = weakness.get("ID")
            name = weakness.get("Name")

            # Find description with namespace handling
            if namespace:
                description = weakness.find("cwe:Description", ns)
            else:
                description = weakness.find("Description")

            if cwe_id and name and description is not None:
                cwe_list.append(
                    {
                        "id": f"CWE-{cwe_id}",
                        "name": name,
                        "description": description.text.strip() if description.text else "",
                    }
                )
        self.logger.debug(f"Parsed {len(cwe_list)} CWEs.")
        return cwe_list

    def get_cwe_data_parallel(self, batch_size: int = 100) -> list[dict[str, Any]]:
        """Gets CWE data with parallel processing using Python 3.13 free-threading.

        Args:
            batch_size: Number of weakness elements to process per batch

        Returns:
            List of parsed CWE data
        """
        # Fall back to sequential if GIL is enabled
        if sys._is_gil_enabled():
            return self.get_cwe_data()

        self.logger.debug("Using parallel CWE parsing with free-threading")

        if not self.cwe_file.exists():
            self.logger.debug("CWE data not found. Downloading...")
            self._fetch_data()  # Changed from _download_cwe_data to _fetch_data

        # Parse XML
        tree = None
        try:
            with zipfile.ZipFile(self.cwe_file, "r") as zip_ref:
                xml_files = [f for f in zip_ref.namelist() if f.endswith(".xml")]
                if not xml_files:
                    raise ValueError("No XML file found in the CWE zip archive")

                xml_file = xml_files[0]
                self.logger.debug(f"Extracting XML file: {xml_file}")

                with zip_ref.open(xml_file) as xml_data:
                    tree = ET.parse(xml_data)
                    root = tree.getroot()
        except zipfile.BadZipFile:
            tree = ET.parse(self.cwe_file)
            root = tree.getroot()

        # Handle XML namespace
        namespace = None
        if "}" in root.tag:
            namespace = root.tag.split("}")[0][1:]

        ns = {"cwe": namespace} if namespace else {}

        # Get all weakness elements
        if namespace:
            weakness_elements = root.findall(".//cwe:Weakness", ns)
        else:
            weakness_elements = root.findall(".//Weakness")

        self.logger.debug(f"Found {len(weakness_elements)} weakness elements to process")

        # Create batches
        batches = [
            weakness_elements[i : i + batch_size]
            for i in range(0, len(weakness_elements), batch_size)
        ]

        def process_weakness_batch(batch, namespace, ns):
            """Process a batch of weakness elements."""
            batch_results = []
            for weakness in batch:
                cwe_id = weakness.get("ID")
                name = weakness.get("Name")

                # Find description
                if namespace:
                    description = weakness.find("cwe:Description", ns)
                else:
                    description = weakness.find("Description")

                if cwe_id and name and description is not None:
                    batch_results.append(
                        {
                            "id": f"CWE-{cwe_id}",
                            "name": name,
                            "description": description.text.strip() if description.text else "",
                        }
                    )
            return batch_results

        # Process batches in parallel
        max_workers = min(4, len(batches))
        all_cwes = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all batches
            futures = {
                executor.submit(process_weakness_batch, batch, namespace, ns): i
                for i, batch in enumerate(batches)
            }

            # Collect results
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_results = future.result()
                    all_cwes.extend(batch_results)
                    self.logger.debug(
                        f"Processed batch {batch_idx + 1}/{len(batches)}: {len(batch_results)} CWEs"
                    )
                except Exception as e:
                    self.logger.error(f"Failed to process batch {batch_idx}: {e}")

        self.logger.debug(f"Parsed {len(all_cwes)} CWEs in parallel.")
        return all_cwes


if __name__ == "__main__":
    parser = CWEParser()
    try:
        cwe_data = parser.get_cwe_data()
        if cwe_data:
            print("\nSample CWE:")
            print(json.dumps(cwe_data[0], indent=2))
    except RequestException as e:
        print(f"Error fetching CWE data: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
