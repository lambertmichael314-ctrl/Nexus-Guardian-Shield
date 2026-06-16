import logging
from typing import TYPE_CHECKING

logger = logging.getLogger("cti_platform.analysis_engine")

# Package metadata
__version__ = "1.0.0"
__author__ = "Security Analysis Team"
__description__ = "Malware analysis engine for CTI platform"

# ---------------------------------------------------------------------------
# Lazy module loader — prevents import crashes when detector modules
# are still under development or missing from the environment.
# ---------------------------------------------------------------------------
class _LazyAnalyzer:
    """Placeholder analyzer returned when a module fails to load."""

    def __init__(self, name: str):
        self.name = name

    def analyze(self, *args, **kwargs):
        logger.warning("Analyzer '%s' is not available (module missing or broken)", self.name)
        return {"detected": False, "confidence": 0.0, "error": f"Module {self.name} unavailable"}


def _load_analyzer(module_name: str, class_name: str):
    """Safely import a detector module; return _LazyAnalyzer on failure."""
    try:
        mod = __import__(f"backend.analysis_engine.modules.{module_name}", fromlist=[class_name])
        return getattr(mod, class_name)
    except Exception as exc:
        logger.debug("Failed to load analyzer %s.%s: %s", module_name, class_name, exc)
        return _LazyAnalyzer(module_name)


# Core base classes (try to load, fallback to None if missing)
MalwareDetectorBase = _load_analyzer("malware_detector_base", "MalwareDetectorBase")
ThreatAnalyzer = _load_analyzer("threat_analyzer", "ThreatAnalyzer")

# Specific analyzers
AdwareDetector = _load_analyzer("adware_detector", "AdwareDetector")
TrojanAnalyzer = _load_analyzer("trojan_analyzer", "TrojanAnalyzer")
DdosAnalyzer = _load_analyzer("ddos_analyzer", "DdosAnalyzer")
KeyloggerAnalyzer = _load_analyzer("keylogger_analyzer", "KeyloggerAnalyzer")
LogicBombAnalyzer = _load_analyzer("logic_bomb_analyzer", "LogicBombAnalyzer")
RansomwareAnalyzer = _load_analyzer("ransomware_analyzer", "RansomwareAnalyzer")
RootkitAnalyzer = _load_analyzer("rootkit_analyzer", "RootkitAnalyzer")
SpywareAnalyzer = _load_analyzer("spyware_analyzer", "SpywareAnalyzer")
VirusAnalyzer = _load_analyzer("virus_analyzer", "VirusAnalyzer")
WormAnalyzer = _load_analyzer("worm_analyzer", "WormAnalyzer")

__all__ = [
    "MalwareDetectorBase",
    "ThreatAnalyzer",
    "AdwareDetector",
    "TrojanAnalyzer",
    "DdosAnalyzer",
    "KeyloggerAnalyzer",
    "LogicBombAnalyzer",
    "RansomwareAnalyzer",
    "RootkitAnalyzer",
    "SpywareAnalyzer",
    "VirusAnalyzer",
    "WormAnalyzer",
]
