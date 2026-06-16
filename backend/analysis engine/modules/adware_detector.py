import logging
import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)

logger = logging.getLogger("cti_platform.analysis_engine")


class AdwareDetector(MalwareDetectorBase):
    """Detects adware-like behavior in Python scripts (popup loops, GUI ads, data exfil)."""

    def __init__(self):
        super().__init__("adware_detector")

        self.filename_indicators = [
            "adware", "popup", "ads", "toolbar", "sponser",
            "offer", "deal", "coupon", "prize", "winne",
            "cash", "money", "free", "bonus", "discount",
        ]

        self.content_indicators = [
            r"show_ad\(", r"display_ad\(", r"create_ad\(",
            r"\.show\(\)", r"\.display\(\)", r"advertisement",
            r"pop.up", r"pop_up", r"popup",
            r"track_user", r"user_data", r"send_data",
            r"http.*post", r"http.*send", r"http.*upload",
        ]

        self.tkinter_indicators = [
            "tkinter", "tk.Tk()", "tk.Label", "tk.Button",
            "root.mainloop()", "title.*Advertisement",
            "title.*Advert", "tkinter as tk",
        ]

        self.network_indicators = [
            "requests.post", "urllib", "socket", "http.client",
            "ftplib", "smtplib", "paramiko", "twisted",
        ]

        self.suspicious_imports = [
            "tkinter", "base64", "requests", "socket",
            "urllib", "threading", "subprocess",
        ]

    def analyze(self, target_path: str) -> Dict[str, Any]:
        self.reset()
        try:
            content = self.read_target(target_path)
        except Exception as exc:
            self.add_finding(f"Failed to read target: {exc}", 0.1)
            return self.build_result()

        # --- Filename heuristics ---
        filename = target_path.lower()
        for indicator in self.filename_indicators:
            if indicator in filename:
                self.add_finding(f"Filename contains adware indicator: {indicator}", 0.4)

        # --- GUI ad indicators ---
        for indicator in self.tkinter_indicators:
            if indicator in content:
                self.add_finding(f"Found GUI adware indicator: {indicator}", 0.5)

        # --- Network exfiltration ---
        for indicator in self.network_indicators:
            if indicator in content:
                self.add_finding(f"Found network communication indicator: {indicator}", 0.3)

        # --- Suspicious imports ---
        for indicator in self.suspicious_imports:
            if f"import {indicator}" in content or f"from {indicator}" in content:
                self.add_finding(f"Found suspicious import: {indicator}", 0.2)

        # --- Regex behaviour patterns ---
        for pattern in self.content_indicators:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.add_finding(f"Found adware behavior pattern: {pattern}", 0.6)

        # --- Structural heuristics ---
        if "while True:" in content and "sleep(" in content:
            self.add_finding("Periodic execution pattern (potential ad display loop)", 0.4)

        if "threading" in content and ("tk." in content or "Tk()" in content):
            self.add_finding("Multithreaded GUI application (common in adware)", 0.3)

        if "base64" in content and ("b64encode" in content or "b64decode" in content):
            self.add_finding("Base64 encoding/decoding (potential data obfuscation)", 0.2)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    """Entrypoint for subprocess dispatch (tasks.py)."""
    return analyze_file_path(target_path, AdwareDetector())