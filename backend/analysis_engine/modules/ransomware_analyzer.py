import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class RansomwareAnalyzer(MalwareDetectorBase):
    """Detects ransomware patterns: bulk encryption, file renaming, ransom notes, wallet addresses."""

    def __init__(self):
        super().__init__("ransomware_analyzer")

        self.indicators = [
            # Encryption libraries and functions
            r"from Crypto", r"AES\.new", r"AES\.MODE_(?:CBC|GCM|EAX)", r"\.encrypt\(", r"\.decrypt\(",
            r"import rsa", r"rsa\.encrypt", r"from cryptography\.fernet",
            r"Fernet\((.*?)\)\.encrypt_file",
            # File I/O and renaming
            r"os\.walk", r"os\.listdir", r"os\.rename\(", r"\.key", r"\.pub", r"\.priv",
            r"exclude_files = \[(.*?)\"exe\"", r"except PermissionError",
            # Ransom indicators
            r"ransom\.txt", r"how_to_decrypt", r"bitcoin", r"wallet_address", r"decr\.ypt",
            r"read_me", r"read_this", r"payment",
        ]

    def analyze(self, target_path: str) -> Dict[str, Any]:
        self.reset()
        try:
            content = self.read_target(target_path)
        except Exception as exc:
            self.add_finding(f"Failed to read target: {exc}", 0.1)
            return self.build_result()

        for pattern in self.indicators:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_finding(f"Found ransomware pattern: {pattern}", 0.95)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, RansomwareAnalyzer())
