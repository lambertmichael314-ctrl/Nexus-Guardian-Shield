import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)

logger = logging.getLogger("cti_platform.analysis_engine")


class TrojanAnalyzer(MalwareDetectorBase):
    """Detects trojan / backdoor / RAT patterns: connect-back sockets, command execution, persistence."""

    def __init__(self):
        super().__init__("trojan_analyzer")

        # Simulated known-threat database (replace with real IOC feed in production)
        self.known_trojan_hashes: Dict[str, Dict[str, str]] = {}

        self.content_indicators = [
            # Connect-back / C2
            r"socket\.socket", r"s\.connect", r"s\.sendall",
            # Command execution
            r"subprocess\.Popen", r"os\.system", r"shlex\.split",
            # Persistence / artifacts
            r"backdoor\.py", r"temp\.exe", r"schtasks",
            # Input capture
            r"getpass", r"pynput", r"keyboard",
            # Remote control
            r"import paramiko", r"paramiko\.SSHClient",
        ]

    def analyze(self, target_path: str) -> Dict[str, Any]:
        self.reset()

        # 1. Hash check against known database
        try:
            file_hash = self.calculate_file_hash(target_path)
            if file_hash in self.known_trojan_hashes:
                info = self.known_trojan_hashes[file_hash]
                self.add_finding(
                    f"Hash matched known Trojan: {info.get('name')}", 1.0
                )
                return self.build_result(details={"hash_match": info, "hash": file_hash})
        except Exception as exc:
            logger.debug("Hash calculation skipped for %s: %s", target_path, exc)

        # 2. Filename heuristics
        filename = Path(target_path).name.lower()
        if "trojan" in filename or "backdoor" in filename:
            self.add_finding("Filename contains suspicious keywords (trojan/backdoor)", 0.6)

        # 3. Content analysis
        try:
            content = self.read_target(target_path)
        except Exception as exc:
            self.add_finding(f"Failed to read target: {exc}", 0.1)
            return self.build_result()

        for pattern in self.content_indicators:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.add_finding(
                    f"Found code pattern: {pattern} (potential backdoor/RAT function)", 0.7
                )

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, TrojanAnalyzer())
