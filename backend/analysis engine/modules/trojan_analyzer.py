import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.analysis_engine.modules.malware_detector_base import MalwareDetectorBase

logger = logging.getLogger("cti_platform.analysis_engine")


class ThreatAnalyzer:
    """Orchestrates all malware detectors against a single target file.

    Provides a unified ``analyze(target_path)`` interface that runs every
    available detector, aggregates results, and returns a summary compatible
    with the ``tasks.py`` result format.
    """

    def __init__(self):
        self.detectors: Dict[str, MalwareDetectorBase] = {}
        self._register_all()

    def _register_all(self) -> None:
        """Attempt to import and register every detector.  Missing modules
        are silently skipped so the orchestrator starts cleanly even when
        some analyzers are still under development."""
        detector_map = {
            "adware": ("backend.analysis_engine.modules.adware_detector", "AdwareDetector"),
            "trojan": ("backend.analysis_engine.modules.trojan_analyzer", "TrojanAnalyzer"),
            "ddos": ("backend.analysis_engine.modules.ddos_analyzer", "DdosAnalyzer"),
            "keylogger": ("backend.analysis_engine.modules.keylogger_analyzer", "KeyloggerAnalyzer"),
            "logic_bomb": ("backend.analysis_engine.modules.logic_bomb_analyzer", "LogicBombAnalyzer"),
            "ransomware": ("backend.analysis_engine.modules.ransomware_analyzer", "RansomwareAnalyzer"),
            "rootkit": ("backend.analysis_engine.modules.rootkit_analyzer", "RootkitAnalyzer"),
            "spyware": ("backend.analysis_engine.modules.spyware_analyzer", "SpywareAnalyzer"),
            "virus": ("backend.analysis_engine.modules.virus_analyzer", "VirusAnalyzer"),
            "worm": ("backend.analysis_engine.modules.worm_analyzer", "WormAnalyzer"),
        }

        for name, (module_path, class_name) in detector_map.items():
            try:
                mod = __import__(module_path, fromlist=[class_name])
                cls = getattr(mod, class_name)
                self.detectors[name] = cls()
                logger.debug("ThreatAnalyzer registered: %s", name)
            except Exception as exc:
                logger.debug("ThreatAnalyzer skipping %s: %s", name, exc)

    def analyze(
        self,
        target_path: str,
        detector_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run analysis on *target_path* using specified detectors.

        Args:
            target_path: Absolute path to the file under analysis.
            detector_names: Subset of detector keys to run (None = all available).

        Returns:
            Standardized result dict:

                {
                    "detected": bool,
                    "confidence": float,
                    "details": {
                        "timestamp": str,
                        "detectors_used": list[str],
                        "results": dict[str, dict],
                    },
                    "error": str | None,
                }
        """
        detectors_to_use = detector_names or list(self.detectors.keys())
        results: Dict[str, Dict[str, Any]] = {}
        overall_detected = False
        max_confidence = 0.0

        for name in detectors_to_use:
            detector = self.detectors.get(name)
            if detector is None:
                results[name] = {
                    "detected": False,
                    "confidence": 0.0,
                    "details": {},
                    "error": "Detector not available",
                }
                continue

            try:
                result = detector.analyze(target_path)
                results[name] = result
                if result.get("detected"):
                    overall_detected = True
                conf = result.get("confidence", 0.0)
                if isinstance(conf, (int, float)) and conf > max_confidence:
                    max_confidence = conf
            except Exception as exc:
                logger.exception("Detector %s failed on %s", name, target_path)
                results[name] = {
                    "detected": False,
                    "confidence": 0.0,
                    "details": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }

        return {
            "detected": overall_detected,
            "confidence": round(max_confidence, 4),
            "details": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detectors_used": detectors_to_use,
                "results": results,
            },
            "error": None,
        }