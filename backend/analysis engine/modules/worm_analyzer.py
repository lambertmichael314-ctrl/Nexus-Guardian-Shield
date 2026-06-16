import re
from typing import Any, Dict

from backend.analysis_engine.modules.malware_detector_base import (
    MalwareDetectorBase,
    analyze_file_path,
)


class WormAnalyzer(MalwareDetectorBase):
    """Detects worm patterns: network scanning, self-propagation, exploitation, lateral movement."""

    def __init__(self):
        super().__init__("worm_analyzer")

        self.indicators = [
            # Network scanning
            r"socket\.socket",
            r"\.connect\(",
            r"\.connect_ex\(",
            r"for.*in range\(.*\d+.*\d+.*\)",
            r"ipaddress\.",
            r"socket\.gethostbyname",
            # Exploitation / brute force
            r"paramiko\.SSHClient",
            r"paramiko\.Transport",
            r"pxssh",
            r"ftplib\.FTP",
            r"smtplib",
            r"telnetlib",
            # Propagation via shares / removable media
            r"smbclient",
            r"win32wnet",
            r"WNetAddConnection",
            r"GetLogicalDrives",
            r"GetDriveType",
            r"DRIVE_REMOVABLE",
            # Self-copy to remote targets
            r"shutil\.copy",
            r"shutil\.copyfile",
            r"open\(.*, ['\"']w['\"']",
            r"\.write\(__file__",
            r"\.write\(sys\.argv",
            # Lateral movement
            r"psexec",
            r"wmi",
            r"win32com",
            # Network discovery
            r"nmap",
            r"scapy",
            r"arp",
            r"ping",
            # Mass-mailing
            r"email\.mime",
            r"MIMEBase",
            r"attachment",
            r"SMTP\(",
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
                self.add_finding(f"Found worm pattern: {pattern}", 0.75)

        return self.build_result()


def analyze(target_path: str) -> Dict[str, Any]:
    return analyze_file_path(target_path, WormAnalyzer())