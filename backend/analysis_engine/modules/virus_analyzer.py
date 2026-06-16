import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class VirusAnalyzer(MalwareDetectorBase):
    """Detects virus patterns: file infection, code injection, self-replication, payload delivery."""

    def __init__(self):
        super().__init__("virus_analyzer")

        self.indicators = [
            # File infection / appending
            r"open\((.*?)\).*(?:w|a)\+",
            r"\.write\((.*?)\)",
            r"\.read\(\)",
            r"os\.path\.getsize",
            r"shutil\.copy",
            r"shutil\.copyfile",
            # Self-replication
            r"sys\.argv\[0\]",
            r"__file__",
            r"os\.path\.basename",
            r"os\.path\.realpath",
            r"glob\.glob",
            r"os\.listdir",
            r"os\.walk",
            # Code injection / marker patterns
            r"# VIRUS",
            r"# INFECTED",
            r"infection_marker",
            r"payload_start",
            r"payload_end",
            # Host file manipulation
            r"\.exe",
            r"\.py",
            r"\.bat",
            r"\.sh",
            # Execution of infected hosts
            r"subprocess\.call",
            r"os\.execv",
            r"os\.spawn",
            # Obfuscation / evasion
            r"base64",
            r"marshal",
            r"compile\(",
            r"exec\(",
            r"eval\(",
            # Trigger conditions
            r"if.*date",
            r"if.*count",
            r"random\.randint",
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
                self.add_finding(f"Found virus pattern: {pattern}", 0.7)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, VirusAnalyzer())
