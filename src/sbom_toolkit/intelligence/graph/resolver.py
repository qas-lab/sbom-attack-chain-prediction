import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Semaphore

import requests
from requests.exceptions import RequestException


class CVECWEResolver:
    """Resolves CVE IDs to their associated CWE IDs using the NVD API."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cache_dir: Path = Path("data/cve_cache")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()

        # Check for API key and set appropriate rate limits
        self.api_key = os.getenv("NVD_API_KEY")
        if self.api_key:
            # With API key: 50 requests per 30 seconds = 0.6 seconds between requests
            self.request_delay = 0.7  # seconds between requests (with small buffer)
            self.logger.debug("Using NVD API key - faster rate limiting enabled")
        else:
            # Without API key: 5 requests per 30 seconds = 6 seconds between requests
            self.request_delay = 6.1  # seconds between requests
            self.logger.debug("No NVD API key found - using slower rate limiting")
            self.logger.debug("Set NVD_API_KEY environment variable for faster processing")

        self.last_request_time = 0

        # For parallel processing with rate limiting
        # Create a semaphore to control concurrent API requests
        self.rate_limit_semaphore = Semaphore(1)  # Only 1 request at a time due to rate limits

    def resolve_cves_to_cwes(self, cve_ids: list[str]) -> dict[str, list[str]]:
        """Resolve a list of CVE IDs to their associated CWE IDs.

        Args:
            cve_ids: List of CVE IDs to resolve

        Returns:
            Dictionary mapping CVE ID to list of associated CWE IDs
        """
        # Check if free-threading is available and if we have enough CVEs to benefit
        if not sys._is_gil_enabled() and len(cve_ids) > 5:
            return self.resolve_cves_to_cwes_parallel(cve_ids)
        else:
            return self.resolve_cves_to_cwes_sequential(cve_ids)

    def resolve_cves_to_cwes_sequential(self, cve_ids: list[str]) -> dict[str, list[str]]:
        """Sequential version of CVE to CWE resolution (original implementation).

        Args:
            cve_ids: List of CVE IDs to resolve

        Returns:
            Dictionary mapping CVE ID to list of associated CWE IDs
        """
        cve_to_cwes = {}

        for cve_id in cve_ids:
            # Check cache first
            cached_cwes = self._get_cached_cwes(cve_id)
            if cached_cwes is not None:
                cve_to_cwes[cve_id] = cached_cwes
                self.logger.debug(f"Found cached CWE data for {cve_id}: {cached_cwes}")
                continue

            # Fetch from NVD API
            try:
                cwes = self._fetch_cwes_for_cve(cve_id)
                cve_to_cwes[cve_id] = cwes
                self._cache_cwes(cve_id, cwes)
                if cwes:
                    self.logger.debug(f"Fetched CWE data for {cve_id}: {cwes}")
                else:
                    self.logger.debug(f"No CWE data found for {cve_id}")
            except Exception as e:
                self.logger.error(f"Failed to fetch CWE data for {cve_id}: {e}")
                cve_to_cwes[cve_id] = []

        return cve_to_cwes

    def resolve_cves_to_cwes_parallel(self, cve_ids: list[str]) -> dict[str, list[str]]:
        """Parallel version of CVE to CWE resolution with proper rate limiting.

        This method leverages Python 3.13 free-threading to process cached lookups
        in parallel while still respecting NVD API rate limits for uncached CVEs.

        Args:
            cve_ids: List of CVE IDs to resolve

        Returns:
            Dictionary mapping CVE ID to list of associated CWE IDs
        """
        self.logger.debug(f"Using parallel CVE resolution for {len(cve_ids)} CVEs")
        cve_to_cwes = {}

        def resolve_single_cve(cve_id: str) -> tuple[str, list[str]]:
            """Resolve a single CVE, checking cache first."""
            # Check cache first (no rate limiting needed)
            cached_cwes = self._get_cached_cwes(cve_id)
            if cached_cwes is not None:
                self.logger.debug(f"Found cached CWE data for {cve_id}: {cached_cwes}")
                return cve_id, cached_cwes

            # For API calls, we need rate limiting
            # Use semaphore to ensure only one API call at a time
            with self.rate_limit_semaphore:
                try:
                    cwes = self._fetch_cwes_for_cve(cve_id)
                    self._cache_cwes(cve_id, cwes)
                    if cwes:
                        self.logger.debug(f"Fetched CWE data for {cve_id}: {cwes}")
                    else:
                        self.logger.debug(f"No CWE data found for {cve_id}")
                    return cve_id, cwes
                except Exception as e:
                    self.logger.error(f"Failed to fetch CWE data for {cve_id}: {e}")
                    return cve_id, []

        # Process CVEs in parallel
        # Cache lookups will be truly parallel, API calls will be serialized by semaphore
        max_workers = min(4, len(cve_ids))  # Don't create too many threads

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_cve = {
                executor.submit(resolve_single_cve, cve_id): cve_id for cve_id in cve_ids
            }

            # Collect results as they complete
            for future in as_completed(future_to_cve):
                try:
                    cve_id, cwes = future.result()
                    cve_to_cwes[cve_id] = cwes
                except Exception as e:
                    cve_id = future_to_cve[future]
                    self.logger.error(f"Unexpected error for {cve_id}: {e}")
                    cve_to_cwes[cve_id] = []

        return cve_to_cwes

    def _fetch_cwes_for_cve(self, cve_id: str) -> list[str]:
        """Fetch CWE IDs for a specific CVE from the NVD API.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-1234")

        Returns:
            List of CWE IDs associated with the CVE
        """
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.request_delay:
            sleep_time = self.request_delay - time_since_last
            self.logger.debug(f"Rate limiting: waiting {sleep_time:.1f}s before fetching {cve_id}")
            time.sleep(sleep_time)

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = self.session.get(
                self.NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=30
            )
            self.last_request_time = time.time()

            if response.status_code == 404:
                self.logger.warning(f"CVE {cve_id} not found in NVD")
                return []

            response.raise_for_status()
            data = response.json()

            cwes = []
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})

                # Extract CWEs from weaknesses
                for weakness in cve_data.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        if desc.get("lang") == "en":
                            description_text = desc.get("value", "")
                            # Extract CWE ID from description
                            cwe_match = re.search(r"CWE-\d+", description_text)
                            if cwe_match:
                                cwes.append(cwe_match.group(0))

                # Also check problemTypes (alternative location for CWEs)
                for problem_type in cve_data.get("problemTypes", []):
                    for desc in problem_type.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description_text = desc.get("value", "")
                            cwe_match = re.search(r"CWE-\d+", description_text)
                            if cwe_match:
                                cwes.append(cwe_match.group(0))

            # Remove duplicates and return
            return list(set(cwes))

        except RequestException as e:
            raise Exception(f"Failed to fetch CVE data from NVD: {e}") from e

    def _get_cached_cwes(self, cve_id: str) -> list[str] | None:
        """Get cached CWE data for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            List of CWE IDs if cached, None otherwise
        """
        cache_file = self.cache_dir / f"{cve_id}.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    cache_data = json.load(f)
                    return cache_data.get("cwes", [])
            except (json.JSONDecodeError, KeyError):
                # Invalid cache file, remove it
                cache_file.unlink(missing_ok=True)
        return None

    def _cache_cwes(self, cve_id: str, cwes: list[str]) -> None:
        """Cache CWE data for a CVE.

        Args:
            cve_id: CVE identifier
            cwes: List of associated CWE IDs
        """
        cache_file = self.cache_dir / f"{cve_id}.json"
        cache_data = {"cve_id": cve_id, "cwes": cwes, "cached_at": time.time()}

        try:
            with open(cache_file, "w") as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to cache CWE data for {cve_id}: {e}")


if __name__ == "__main__":
    # Test the resolver
    resolver = CVECWEResolver()
    test_cves = ["CVE-2023-1234", "CVE-2022-12345"]  # Replace with actual CVE IDs

    print("Testing CVE-CWE resolver...")
    result = resolver.resolve_cves_to_cwes(test_cves)

    print("\nResults:")
    for cve_id, cwes in result.items():
        print(f"  {cve_id}: {cwes}")
