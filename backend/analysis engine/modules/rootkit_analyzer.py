import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class RootkitAnalyzer(MalwareDetectorBase):
    """Detects rootkit patterns: privilege escalation, process hiding, syscall hooks, kernel modules."""

    def __init__(self):
        super().__init__("rootkit_analyzer")

        self.indicators = [
            # Privilege escalation / execution
            r"os\.system\((.*?)\"sudo", r"os\.system\((.*?)\"whoami", r"\.execve", r"setuid\(0\)",
            # Hiding / Hooking
            r"LD_PRELOAD", r"syscall", r"procfs", r"import ctypes", r"ctypes\.CDLL",
            r"sys\.modules", r"__import__", r"set_process_visibility", r"\.hide_process\(",
            r"import ptrace", r"ptrace\.syscall",
            # Kernel / module interaction
            r"\.ko", r"\.o", r"insmod", r"rmmod", r"modprobe",
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
                self.add_finding(f"Found rootkit pattern: {pattern}", 0.85)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, RootkitAnalyzer())