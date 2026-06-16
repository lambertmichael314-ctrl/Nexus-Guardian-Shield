import os
import json
import logging
from typing import Dict, List, Any
from modules.malware_detector_base import MalwareDetectorBase
from modules.adware_detector import AdwareDetector
from modules.trojan_analyzer import TrojanAnalyzer
from modules.ddos_analyzer import DdosAnalyzer
from modules.keylogger_analyzer import KeyloggerAnalyzer
from modules.logic_bomb_analyzer import LogicBombAnalyzer
from modules.ransomware_analyzer import RansomwareAnalyzer
from modules.rootkit_analyzer import RootkitAnalyzer
from modules.spyware_analyzer import SpywareAnalyzer
from modules.virus_analyzer import VirusAnalyzer
from modules.worm_analyzer import WormAnalyzer

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    """Main threat analysis orchestrator"""
    
    def __init__(self):
        self.detectors = {}
        # Register all the detectors
        self.register_detector("adware", AdwareDetector())
        self.register_detector("trojan", TrojanAnalyzer())
        self.register_detector("ddos", DdosAnalyzer())
        self.register_detector("keylogger", KeyloggerAnalyzer())
        self.register_detector("logic_bomb", LogicBombAnalyzer())
        self.register_detector("ransomware", RansomwareAnalyzer())
        self.register_detector("rootkit", RootkitAnalyzer())
        self.register_detector("spyware", SpywareAnalyzer())
        self.register_detector("virus", VirusAnalyzer())
        self.register_detector("worm", WormAnalyzer())
    
    def register_detector(self, name: str, detector: MalwareDetectorBase):
        """Register a malware detector."""
        self.detectors[name] = detector
    
    def analyze(self, input_data: Dict[str, Any], detector_names: List[str] = None) -> Dict[str, Any]:
        """
        Analyze input data using specified detectors.
        
        Args:
            input_data: Data to analyze
            detector_names: List of detector names to use (None for all)
            
        Returns:
            Combined analysis results
        """
        results = {}
        overall_malware_detected = False
        max_confidence = 0.0
        
        # Determine which detectors to use
        detectors_to_use = list(self.detectors.keys()) if detector_names is None else \
                           [name for name in detector_names if name in self.detectors]
        
        # Run analysis with each detector
        for detector_name in detectors_to_use:
            try:
                detector = self.detectors[detector_name]
                logger.info(f"Running analysis with {detector_name} detector")
                result = detector.analyze(input_data)
                results[detector_name] = result
                
                # Update overall status
                if result.get("is_malware"):
                    overall_malware_detected = True
                if result.get("confidence", 0.0) > max_confidence:
                    max_confidence = result["confidence"]
                    
            except Exception as e:
                logger.error(f"Error running {detector_name} detector: {e}")
                results[detector_name] = {
                    "analyzer": detector_name,
                    "error": str(e),
                    "is_malware": False,
                    "confidence": 0.0
                }
        
        # Return combined results
        return {
            "timestamp": datetime.now().isoformat(),
            "input_data": input_data,
            "is_malware": overall_malware_detected,
            "confidence": max_confidence,
            "detectors_used": detectors_to_use,
            "results": results
        }
