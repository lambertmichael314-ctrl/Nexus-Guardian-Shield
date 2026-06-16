import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class KeyloggerAnalyzer(MalwareDetectorBase):
    """Detects keylogger / input-capture patterns in Python scripts."""

    def __init__(self):
        super().__init__("keylogger_analyzer")

        self.indicators = [
            # Common keylogger libraries
            r"from pynput", r"import keyboard", r"import mouse", r"from pyxhook",
            # Input capture functions
            r"\.on_press", r"\.on_release", r"\.listen\(", r"listener\.start\(",
            r"raw_input", r"input\((.*?)\)",
            # Windows/OS hooks
            r"win32api", r"SetWindowsHookEx", r"GetKeyState", r"user32\.dll",
            # Log file / exfiltration
            r"\.log", r"log_keys", r"\.send\((.*?)log_k", r"\.write\((.*?)log_k",
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
                self.add_finding(f"Found keylogger pattern: {pattern}", 0.8)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, KeyloggerAnalyzer())
