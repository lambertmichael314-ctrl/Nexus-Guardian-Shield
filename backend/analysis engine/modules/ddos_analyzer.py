import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class DdosAnalyzer(MalwareDetectorBase):
    """Detects DDoS / network-flooding patterns in Python scripts."""

    def __init__(self):
        super().__init__("ddos_analyzer")

        self.indicators = [
            # High-volume network I/O and low-level socket programming
            r"socket\.AF_INET", r"socket\.SOCK_STREAM", r"socket\.SOCK_DGRAM",
            r"\.sendto\(", r"\.sendall\(", r"\.connect\((.*?)\)", r"\.settimeout\(0\)",
            # Flooding loops and multithreading for concurrency
            r"for i in range\((?:\d+|target)", r"while True:", r"import threading",
            # Common DDoS script tool names/variables
            r"target_ip", r"target_port", r"ip_flood", r"flood_count", r"packet_size",
            # Common DDoS script imports
            r"import ssl", r"import struct", r"import gevent",
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
                self.add_finding(f"Found DDoS pattern: {pattern}", 0.7)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, DdosAnalyzer())