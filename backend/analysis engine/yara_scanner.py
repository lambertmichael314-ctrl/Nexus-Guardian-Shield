import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logger = logging.getLogger("cti_platform.analysis_engine")
RULES_DIR = Path(__file__).parent / "yara_rules"

class YaraScanner:
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or RULES_DIR
        self.rules = None
        self.rule_names: List[str] = []
        self._compile_rules()

    def _compile_rules(self) -> None:
        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed; YARA scanning disabled")
            return
        yar_files = list(self.rules_dir.glob("*.yar"))
        if not yar_files:
            logger.warning("No YARA rule files found in %s", self.rules_dir)
            return
        file_paths = {f.name: str(f) for f in yar_files}
        try:
            self.rules = yara.compile(filepaths=file_paths)
            self.rule_names = list(file_paths.keys())
            logger.info("YARA rules compiled: %s", ", ".join(self.rule_names))
        except Exception as exc:
            logger.error("YARA compilation failed: %s", exc)
            self.rules = None

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if not YARA_AVAILABLE or self.rules is None:
            return {
                "detected": False, "confidence": 0.0,
                "details": {"matches": [], "error": "YARA not available"},
                "error": "YARA not available",
            }
        try:
            matches = self.rules.match(file_path)
        except Exception as exc:
            return {
                "detected": False, "confidence": 0.0,
                "details": {"matches": [], "error": str(exc)},
                "error": str(exc),
            }
        if not matches:
            return {
                "detected": False, "confidence": 0.0,
                "details": {"matches": []},
                "error": None,
            }

        max_score = 0
        match_details: List[Dict[str, Any]] = []
        for match in matches:
            meta = dict(match.meta) if match.meta else {}
            score = meta.get("score", 50)
            if isinstance(score, list):
                score = score[0] if score else 50
            try:
                score = int(score)
            except (TypeError, ValueError):
                score = 50
            if score > max_score:
                max_score = score

            strings_data = []
            if match.strings:
                for s in match.strings:
                    if hasattr(s, "identifier"):
                        for instance in s.instances:
                            matched = instance.matched_data or b""
                            strings_data.append({
                                "identifier": s.identifier,
                                "offset": instance.offset,
                                "length": len(matched),
                                "data": matched.hex(),
                            })
                    else:
                        strings_data.append({
                            "identifier": s[1],
                            "offset": s[0],
                            "data": s[2].hex() if s[2] else "",
                        })

            match_details.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags) if match.tags else [],
                "meta": meta,
                "strings": strings_data,
                "score": score,
            })

        confidence = min(max_score / 100.0, 1.0)
        return {
            "detected": True,
            "confidence": round(confidence, 4),
            "details": {"matches": match_details, "total_matches": len(matches)},
            "error": None,
        }

def analyze(target_path: str) -> Dict[str, Any]:
    scanner = YaraScanner()
    return scanner.scan_file(target_path)