"""CTI Platform — Threat Intelligence Feed Parsers

Normalizes raw data from external threat feeds (JSON, CSV, STIX/TAXII,
MISP, OTX, AbuseIPDB) into the platform's internal IOC schema.
"""

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cti_platform.feed_parsers")


# ---------------------------------------------------------------------------
# Normalized IOC record
# ---------------------------------------------------------------------------
def _make_ioc(
    ioc_type: str,
    value: str,
    source: str,
    confidence: Optional[float] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    tags: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a normalized IOC dict matching IndicatorCreate fields."""
    return {
        "ioc_type": ioc_type,
        "value": value,
        "source": source,
        "confidence": confidence,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "tags": tags,
        "is_active": True,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Generic parsers
# ---------------------------------------------------------------------------
class FeedParser:
    """Static utility class for parsing common threat-feed formats."""

    @staticmethod
    def parse_json_feed(
        raw_data: str,
        mapping: Dict[str, str],
        source_name: str = "unknown",
    ) -> List[Dict[str, Any]]:
        """Parse a JSON feed using a field-mapping dict.

        *mapping* maps external field names to internal field names:
            {"external_type": "ioc_type", "external_value": "value"}
        """
        normalized: List[Dict[str, Any]] = []
        try:
            data = json.loads(raw_data)
            items = data if isinstance(data, list) else data.get("results", data.get("data", []))
            if not isinstance(items, list):
                logger.warning("JSON feed root is not a list and has no 'results'/'data' key")
                return normalized
            for entry in items:
                if not isinstance(entry, dict):
                    continue
                record = {}
                for ext_key, int_key in mapping.items():
                    record[int_key] = entry.get(ext_key)
                record.setdefault("source", source_name)
                record.setdefault("is_active", True)
                normalized.append(record)
        except json.JSONDecodeError as exc:
            logger.error("JSON decode error | source=%s error=%s", source_name, exc)
        except Exception as exc:
            logger.error("JSON feed parse error | source=%s error=%s", source_name, exc)
        return normalized

    @staticmethod
    def parse_csv_feed(
        raw_data: str,
        delimiter: str = ",",
        source_name: str = "unknown",
    ) -> List[Dict[str, Any]]:
        """Parse a CSV threat feed into a list of dicts."""
        normalized: List[Dict[str, Any]] = []
        try:
            f = io.StringIO(raw_data)
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                record = dict(row)
                record.setdefault("source", source_name)
                record.setdefault("is_active", True)
                normalized.append(record)
        except csv.Error as exc:
            logger.error("CSV parse error | source=%s error=%s", source_name, exc)
        except Exception as exc:
            logger.error("CSV feed parse error | source=%s error=%s", source_name, exc)
        return normalized

    @staticmethod
    def parse_text_list(
        raw_data: str,
        ioc_type: str,
        source_name: str = "unknown",
        comment_char: str = "#",
    ) -> List[Dict[str, Any]]:
        """Parse a plain-text line-delimited IOC list (e.g. IP blocklists)."""
        normalized: List[Dict[str, Any]] = []
        for line in raw_data.splitlines():
            line = line.strip()
            if not line or line.startswith(comment_char):
                continue
            normalized.append(_make_ioc(ioc_type=ioc_type, value=line, source=source_name))
        return normalized


# ---------------------------------------------------------------------------
# STIX / TAXII helpers
# ---------------------------------------------------------------------------
class STIXParser:
    """Parse STIX 2.0/2.1 Indicator objects into normalized IOCs."""

    @staticmethod
    def parse_indicators(raw_data: str, source_name: str = "stix") -> List[Dict[str, Any]]:
        """Parse STIX 2.1 bundle or single indicator object."""
        normalized: List[Dict[str, Any]] = []
        try:
            data = json.loads(raw_data)
            objects = []
            if data.get("type") == "bundle":
                objects = data.get("objects", [])
            elif data.get("type") == "indicator":
                objects = [data]
            else:
                objects = data if isinstance(data, list) else []

            for obj in objects:
                if obj.get("type") != "indicator":
                    continue
                pattern = obj.get("pattern", "")
                ioc_type, value = STIXParser._extract_from_pattern(pattern)
                if not value:
                    continue
                normalized.append(
                    _make_ioc(
                        ioc_type=ioc_type,
                        value=value,
                        source=source_name,
                        confidence=obj.get("confidence"),
                        first_seen=obj.get("created"),
                        last_seen=obj.get("modified"),
                        tags=",".join(obj.get("labels", [])),
                        notes=obj.get("description"),
                    )
                )
        except json.JSONDecodeError as exc:
            logger.error("STIX JSON decode error | error=%s", exc)
        except Exception as exc:
            logger.error("STIX parse error | error=%s", exc)
        return normalized

    @staticmethod
    def _extract_from_pattern(pattern: str) -> tuple:
        """Extract (ioc_type, value) from a STIX pattern string.

        Supports common patterns like:
            [ipv4-addr:value = '1.2.3.4']
            [domain-name:value = 'evil.com']
            [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
            [url:value = 'http://evil.com']
            [email-addr:value = 'bad@evil.com']
        """
        pattern = pattern.strip()
        # Simple heuristic extraction
        type_map = {
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "domain-name": "domain",
            "url": "url",
            "file": "md5",  # default; refined below
            "email-addr": "email",
        }

        ioc_type = "file_path"  # fallback
        for stix_type, mapped in type_map.items():
            if stix_type in pattern:
                ioc_type = mapped
                break

        # Refine file hash type
        if "file:hashes.MD5" in pattern:
            ioc_type = "md5"
        elif "file:hashes.SHA-1" in pattern:
            ioc_type = "sha1"
        elif "file:hashes.SHA-256" in pattern:
            ioc_type = "sha256"

        # Extract quoted value
        value = ""
        if "= '" in pattern:
            parts = pattern.split("= '")
            if len(parts) > 1:
                value = parts[1].split("'")[0]
        elif '= "' in pattern:
            parts = pattern.split('= "')
            if len(parts) > 1:
                value = parts[1].split('"')[0]

        return ioc_type, value


# ---------------------------------------------------------------------------
# MISP parser
# ---------------------------------------------------------------------------
class MISPFeedParser:
    """Parse MISP event JSON into normalized IOC records."""

    MISP_TYPE_MAP: Dict[str, str] = {
        "ip-dst": "ipv4",
        "ip-src": "ipv4",
        "domain": "domain",
        "domain|ip": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "filename|md5": "md5",
        "filename|sha1": "sha1",
        "filename|sha256": "sha256",
        "email-src": "email",
        "email-dst": "email",
        "mutex": "mutex",
        "yara": "yara",
        "filename": "file_path",
    }

    @classmethod
    def parse_event(cls, raw_data: str, source_name: str = "misp") -> List[Dict[str, Any]]:
        """Parse a MISP event JSON response into normalized IOCs."""
        normalized: List[Dict[str, Any]] = []
        try:
            data = json.loads(raw_data)
            event = data.get("Event", data)
            attributes = event.get("Attribute", [])
            if not isinstance(attributes, list):
                attributes = [attributes]
            for attr in attributes:
                misp_type = attr.get("type", "")
                ioc_type = cls.MISP_TYPE_MAP.get(misp_type, "file_path")
                value = attr.get("value", "")
                # Handle composite types (domain|ip, filename|hash)
                if "|" in value:
                    value = value.split("|")[0]
                normalized.append(
                    _make_ioc(
                        ioc_type=ioc_type,
                        value=value,
                        source=source_name,
                        first_seen=attr.get("timestamp"),
                        tags=attr.get("Tag", [{}])[0].get("name") if attr.get("Tag") else None,
                        notes=attr.get("comment"),
                    )
                )
        except json.JSONDecodeError as exc:
            logger.error("MISP JSON decode error | error=%s", exc)
        except Exception as exc:
            logger.error("MISP parse error | error=%s", exc)
        return normalized


# ---------------------------------------------------------------------------
# OTX parser
# ---------------------------------------------------------------------------
class OTXFeedParser:
    """Parse AlienVault OTX pulse/indicator responses into normalized IOCs."""

    OTX_TYPE_MAP: Dict[str, str] = {
        "IPv4": "ipv4",
        "IPv6": "ipv6",
        "domain": "domain",
        "URL": "url",
        "MD5": "md5",
        "SHA1": "sha1",
        "SHA256": "sha256",
        "email": "email",
        "FileHash-MD5": "md5",
        "FileHash-SHA1": "sha1",
        "FileHash-SHA256": "sha256",
        "Mutex": "mutex",
        "YARA": "yara",
        "FilePath": "file_path",
    }

    @classmethod
    def parse_pulse(cls, raw_data: str, source_name: str = "otx") -> List[Dict[str, Any]]:
        """Parse an OTX pulse JSON response into normalized IOCs."""
        normalized: List[Dict[str, Any]] = []
        try:
            data = json.loads(raw_data)
            indicators = data.get("indicators", [])
            for ind in indicators:
                otx_type = ind.get("type", "")
                ioc_type = cls.OTX_TYPE_MAP.get(otx_type, "file_path")
                normalized.append(
                    _make_ioc(
                        ioc_type=ioc_type,
                        value=ind.get("indicator", ""),
                        source=source_name,
                        first_seen=ind.get("created"),
                        notes=ind.get("description"),
                    )
                )
        except json.JSONDecodeError as exc:
            logger.error("OTX JSON decode error | error=%s", exc)
        except Exception as exc:
            logger.error("OTX parse error | error=%s", exc)
        return normalized


# ---------------------------------------------------------------------------
# AbuseIPDB parser
# ---------------------------------------------------------------------------
class AbuseIPDBParser:
    """Parse AbuseIPDB check/blacklist responses into normalized IOCs."""

    @staticmethod
    def parse_check(raw_data: str, source_name: str = "abuseipdb") -> List[Dict[str, Any]]:
        """Parse AbuseIPDB /check response."""
        try:
            data = json.loads(raw_data)
            record = data.get("data", {})
            ip = record.get("ipAddress")
            if not ip:
                return []
            confidence = record.get("abuseConfidencePercentage")
            conf_float = confidence / 100.0 if isinstance(confidence, int) else None
            notes_parts = []
            if record.get("isp"):
                notes_parts.append(f"ISP: {record['isp']}")
            if record.get("countryCode"):
                notes_parts.append(f"Country: {record['countryCode']}")
            if record.get("totalReports"):
                notes_parts.append(f"Reports: {record['totalReports']}")
            return [
                _make_ioc(
                    ioc_type="ipv4",
                    value=ip,
                    source=source_name,
                    confidence=conf_float,
                    last_seen=record.get("lastReportedAt"),
                    notes="; ".join(notes_parts) if notes_parts else None,
                )
            ]
        except json.JSONDecodeError as exc:
            logger.error("AbuseIPDB JSON decode error | error=%s", exc)
        except Exception as exc:
            logger.error("AbuseIPDB parse error | error=%s", exc)
        return []

    @staticmethod
    def parse_blacklist(raw_data: str, source_name: str = "abuseipdb") -> List[Dict[str, Any]]:
        """Parse AbuseIPDB /blacklist response."""
        normalized: List[Dict[str, Any]] = []
        try:
            data = json.loads(raw_data)
            records = data.get("data", [])
            for record in records:
                ip = record.get("ipAddress")
                if not ip:
                    continue
                confidence = record.get("abuseConfidencePercentage")
                conf_float = confidence / 100.0 if isinstance(confidence, int) else None
                normalized.append(
                    _make_ioc(
                        ioc_type="ipv4",
                        value=ip,
                        source=source_name,
                        confidence=conf_float,
                        last_seen=record.get("lastReportedAt"),
                    )
                )
        except json.JSONDecodeError as exc:
            logger.error("AbuseIPDB blacklist JSON decode error | error=%s", exc)
        except Exception as exc:
            logger.error("AbuseIPDB blacklist parse error | error=%s", exc)
        return normalized
