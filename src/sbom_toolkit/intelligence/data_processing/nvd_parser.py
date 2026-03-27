import os
from pathlib import Path
from typing import Any

import requests
from requests.exceptions import RequestException


class NVDParser:
    """Handles fetching and parsing of NVD CVE data."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.getenv("NVD_API_KEY")

    def __init__(self, cache_dir: Path = Path("data/nvd_cache")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _fetch_data(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {}
        if self.NVD_API_KEY:
            headers["apiKey"] = self.NVD_API_KEY

        response = requests.get(self.BASE_URL, params=params, headers=headers)
        response.raise_for_status()
        return response.json()

    def get_cves(
        self,
        results_per_page: int = 50,
        start_index: int = 0,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetches CVEs from NVD API.

        Args:
            results_per_page: Number of results per API call (max 2000)
            start_index: Starting index for pagination
            max_results: Maximum total number of CVEs to fetch (None for all)
        """
        all_cves = []
        total_results = -1

        while total_results == -1 or start_index < total_results:
            # Check if we've reached our limit
            if max_results and len(all_cves) >= max_results:
                print(f"Reached maximum limit of {max_results} CVEs")
                break

            # Adjust results_per_page if we're near the limit
            if max_results:
                remaining = max_results - len(all_cves)
                current_page_size = min(results_per_page, remaining)
            else:
                current_page_size = results_per_page

            params = {"resultsPerPage": current_page_size, "startIndex": start_index}
            print(f"Fetching NVD data with params: {params}")
            data = self._fetch_data(params)

            if total_results == -1:
                total_results = data.get("totalResults", 0)
                if max_results:
                    print(f"Total NVD CVEs available: {total_results}, limiting to {max_results}")
                else:
                    print(f"Total NVD CVEs available: {total_results}")

            cves = data.get("vulnerabilities", [])
            all_cves.extend(cve.get("cve", {}) for cve in cves)

            start_index += len(cves)

            if max_results:
                print(f"Fetched {len(all_cves)} / {max_results} CVEs (limit)")
            else:
                print(f"Fetched {len(all_cves)} / {total_results} CVEs")

            if not cves:  # No more CVEs to fetch
                break

        return all_cves

    def parse_cve_data(self, cve_data: dict[str, Any]) -> dict[str, Any]:
        """Parses raw CVE data into a standardized format for the KG."""
        parsed = {
            "id": cve_data.get("id"),
            "sourceIdentifier": cve_data.get("sourceIdentifier"),
            "published": cve_data.get("published"),
            "lastModified": cve_data.get("lastModified"),
            "vulnStatus": cve_data.get("vulnStatus"),
            "descriptions": [
                desc.get("value")
                for desc in cve_data.get("descriptions", [])
                if desc.get("lang") == "en"
            ],
            "metrics": cve_data.get("metrics", {}),
            "weaknesses": [
                weakness_node.get("description", [])[0].get("value")
                for weakness in cve_data.get("weaknesses", [])
                for weakness_node in weakness.get("description", [])
                if weakness_node.get("lang") == "en"
            ],
            "configurations": cve_data.get("configurations", []),
            "references": [ref.get("url") for ref in cve_data.get("references", [])],
        }
        return parsed

    def fetch_and_parse_recent_cves(self, days_back: int = 7) -> list[dict[str, Any]]:
        """Fetches recent CVEs and parses them."""
        # NVD API doesn't directly support 'days_back' for filtering.
        # For now, we'll fetch all and filter, or rely on a time-based API if available.
        # This is a placeholder for more sophisticated time-based fetching.
        print(
            f"Fetching and parsing recent CVEs (last {days_back} days - not yet implemented for NVD API)"
        )
        return self.get_cves(results_per_page=50)  # Fetch a small batch for testing


if __name__ == "__main__":
    # Example Usage:
    # Set your NVD_API_KEY environment variable for production use
    # export NVD_API_KEY="YOUR_API_KEY"

    parser = NVDParser()
    try:
        # Fetch and parse a small number of recent CVEs
        recent_cves = parser.fetch_and_parse_recent_cves(days_back=1)
        print(f"\nFetched and parsed {len(recent_cves)} recent CVEs.")
        if recent_cves:
            print("First CVE ID:", recent_cves[0].get("id"))
            print("First CVE Description:", recent_cves[0].get("descriptions", [])[0])

        # Example of fetching all CVEs (can be very large)
        # all_cves = parser.get_cves()
        # print(f"\nFetched {len(all_cves)} total CVEs.")

    except RequestException as e:
        print(f"Error fetching data from NVD: {e}")
        if "403 Client Error: Forbidden" in str(e) and not parser.NVD_API_KEY:
            print("Consider setting the NVD_API_KEY environment variable for higher rate limits.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
