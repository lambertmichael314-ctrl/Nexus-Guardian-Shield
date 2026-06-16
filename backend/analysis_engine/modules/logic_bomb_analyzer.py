import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class LogicBombAnalyzer(MalwareDetectorBase):
    """Detects logic-bomb patterns: time triggers, counters, registry checks, file existence gates."""

    def __init__(self):
        super().__init__("logic_bomb_analyzer")

        self.indicators = [
            # Time-based triggers
            r"datetime\.datetime\.now", r"if datetime\.now\(\) (?:>=|<=)", r"date_to_trigger",
            r"time\.ctime", r"time\.strptime", r"os\.environ\.get\((.*?)\"DATE\"",
            # Event/Counter-based triggers
            r"file_count > \d+", r"if len\((.*?)\) == \d+", r"import winreg", r"registry_check",
            r"if os\.path\.exists\((.*?)\) == False",
            # Suspicious delay + destructive action combos
            r"time\.sleep\(.*\).*os\.remove",
            r"time\.sleep\(.*\).*shutil\.rmtree",
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
                self.add_finding(f"Found logic-bomb pattern: {pattern}", 0.9)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, LogicBombAnalyzer())
