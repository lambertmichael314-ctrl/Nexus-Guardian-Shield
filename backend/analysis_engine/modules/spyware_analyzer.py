import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class SpywareAnalyzer(MalwareDetectorBase):
    """Detects spyware patterns: credential theft, screen capture, browser data harvesting."""

    def __init__(self):
        super().__init__("spyware_analyzer")

        self.indicators = [
            # Credential / data collection
            r"getpass", r"getlogin", r"platform\.uname", r"os\.getenv", r"sqlite3",
            r"browser\.profile", r"chrome\.exe", r"firefox\.exe", r"cookies", r"passwords",
            # Screen capture / recording
            r"from PIL import ImageGrab", r"PyQt5\.QtWidgets", r"\.grab\((.*?)\)",
            r"screenshot", r"scrot", r"os\.system\((.*?)\"screencapture",
            # Exfiltration
            r"requests\.post", r"\.upload_file", r"ftp\.storlines",
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
                self.add_finding(f"Found spyware pattern: {pattern}", 0.75)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, SpywareAnalyzer())
