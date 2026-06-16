"""CTI Platform — Threat Intelligence Feed Collectors

HTTP clients for fetching raw IOC data from external threat intelligence
sources (AlienVault OTX, AbuseIPDB, MISP, and generic JSON/CSV/TEXT feeds).
"""

import logging
import time
from typing import Any, Dict, Optional

import requests

from backend.core.config import settings

logger = logging.getLogger("cti_platform.collectors")

DEFAULT_TIMEOUT = 30
DEFAULT_RETRY = 2


class FeedCollector:
    """Generic HTTP collector with retry, backoff, and auth support."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_RETRY,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = {
            "User-Agent": (
                f"{settings.PROJECT_NAME.replace(' ', '-')}/"
                f"{settings.PROJECT_VERSION}"
            ),
            "Accept": "application/json, text/csv, text/plain",
        }
        if extra_headers:
            self.headers.update(extra_headers)

    # ------------------------------------------------------------------
    # Core fetch
    # ------------------------------------------------------------------
    def fetch_feed(
        self,
        url: str,
        auth_token: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Fetch raw text from *url* with retries and optional Bearer auth."""
        headers = self.headers.copy()
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.get(
                    url, headers=headers, params=params, timeout=self.timeout
                )
                response.raise_for_status()
                logger.info("Fetched feed | url=%s bytes=%s", url, len(response.text))
                return response.text
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response else 0
                logger.warning(
                    "Feed HTTP error | url=%s status=%s attempt=%s/%s",
                    url,
                    status_code,
                    attempt,
                    self.max_retries,
                )
                last_exc = exc
            except requests.RequestException as exc:
                logger.warning(
                    "Feed fetch error | url=%s attempt=%s/%s error=%s",
                    url,
                    attempt,
                    self.max_retries,
                    exc,
                )
                last_exc = exc

            if attempt < self.max_retries:
                time.sleep(2 ** attempt)  # exponential backoff

        logger.error(
            "Failed to fetch feed after %s attempts | url=%s error=%s",
            self.max_retries,
            url,
            last_exc,
        )
        return None

    def fetch_json(
        self,
        url: str,
        auth_token: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Fetch and parse JSON from *url*.  Returns Python object or None."""
        raw = self.fetch_feed(url, auth_token=auth_token, params=params)
        if raw is None:
            return None
        try:
            import json
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse JSON feed | url=%s error=%s", url, exc)
            return None


# ------------------------------------------------------------------
# AlienVault OTX
# ------------------------------------------------------------------
class OTXCollector(FeedCollector):
    """AlienVault Open Threat Exchange (OTX) pulse/subscription collector."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.headers["X-OTX-API-KEY"] = api_key

    def get_subscribed_pulses(self, limit: int = 20) -> Optional[Any]:
        """Return JSON list of subscribed pulses."""
        url = f"{self.BASE_URL}/pulses/subscribed"
        return self.fetch_json(url, params={"limit": limit})

    def get_pulse_indicators(self, pulse_id: str) -> Optional[Any]:
        """Return indicators for a specific pulse."""
        url = f"{self.BASE_URL}/pulses/{pulse_id}/indicators"
        return self.fetch_json(url)

    def get_indicator_details(self, indicator_type: str, indicator: str) -> Optional[Any]:
        """Return general indicator details (reputation, geo, etc.)."""
        url = f"{self.BASE_URL}/indicators/{indicator_type}/{indicator}/general"
        return self.fetch_json(url)


# ------------------------------------------------------------------
# AbuseIPDB
# ------------------------------------------------------------------
class AbuseIPDBCollector(FeedCollector):
    """AbuseIPDB v2 API collector for IP reputation data."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.headers["Key"] = api_key

    def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> Optional[Any]:
        """Check reputation for a single IP address."""
        url = f"{self.BASE_URL}/check"
        return self.fetch_json(
            url, params={"ipAddress": ip_address, "maxAgeInDays": max_age_in_days}
        )

    def check_cidr(self, cidr: str, max_age_in_days: int = 90) -> Optional[Any]:
        """Check reputation for a CIDR block."""
        url = f"{self.BASE_URL}/check-block"
        return self.fetch_json(
            url, params={"network": cidr, "maxAgeInDays": max_age_in_days}
        )

    def get_blacklist(
        self, confidence_minimum: int = 100, limit: int = 10_000
    ) -> Optional[Any]:
        """Download the AbuseIPDB blacklist."""
        url = f"{self.BASE_URL}/blacklist"
        return self.fetch_json(
            url, params={"confidenceMinimum": confidence_minimum, "limit": limit}
        )


# ------------------------------------------------------------------
# VirusTotal
# ------------------------------------------------------------------
class VirusTotalCollector(FeedCollector):
    """VirusTotal v3 API collector for file/IP/URL/domain intelligence."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.headers["x-apikey"] = api_key

    def get_ip_report(self, ip_address: str) -> Optional[Any]:
        url = f"{self.BASE_URL}/ip_addresses/{ip_address}"
        return self.fetch_json(url)

    def get_domain_report(self, domain: str) -> Optional[Any]:
        url = f"{self.BASE_URL}/domains/{domain}"
        return self.fetch_json(url)

    def get_file_report(self, file_hash: str) -> Optional[Any]:
        url = f"{self.BASE_URL}/files/{file_hash}"
        return self.fetch_json(url)

    def get_url_report(self, url_id: str) -> Optional[Any]:
        url = f"{self.BASE_URL}/urls/{url_id}"
        return self.fetch_json(url)


# ------------------------------------------------------------------
# MISP
# ------------------------------------------------------------------
class MISPCollector(FeedCollector):
    """MISP (Malware Information Sharing Platform) REST API collector."""

    def __init__(self, base_url: str, api_key: str, **kwargs: Any):
        super().__init__(**kwargs)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers["Authorization"] = api_key
        self.headers["Accept"] = "application/json"
        self.headers["Content-Type"] = "application/json"

    def get_events(self, limit: int = 100, page: int = 1) -> Optional[Any]:
        url = f"{self.base_url}/events/index"
        return self.fetch_json(url, params={"limit": limit, "page": page})

    def get_event(self, event_id: str) -> Optional[Any]:
        url = f"{self.base_url}/events/view/{event_id}"
        return self.fetch_json(url)

    def get_attributes(
        self,
        type_attribute: Optional[str] = None,
        tags: Optional[str] = None,
        limit: int = 100,
    ) -> Optional[Any]:
        url = f"{self.base_url}/attributes/restSearch"
        params: Dict[str, Any] = {"limit": limit}
        if type_attribute:
            params["type"] = type_attribute
        if tags:
            params["tags"] = tags
        return self.fetch_json(url, params=params)
