import pytest
from analysis_engine.modules.ransomware_analyzer import RansomwareAnalyzer
from analysis_engine.modules.ddos_analyzer import DdosAnalyzer

def test_ransomware_detection():
    analyzer = RansomwareAnalyzer()
    malicious_code = {
        "content": "import cryptography; f = Fernet(key); f.encrypt(data); os.rename(file, file + '.encrypted')"
    }
    result = analyzer.analyze(malicious_code)
    assert result["is_malware"] is True
    assert "Ransomware" in str(result["results"])

def test_ddos_detection():
    analyzer = DdosAnalyzer()
    # Test valid DDoS pattern
    flooder = {"content": "while True: s.sendto(packet, (target_ip, port))"}
    result = analyzer.analyze(flooder)
    assert result["is_malware"] is True

def test_clean_file():
    analyzer = RansomwareAnalyzer()
    clean_code = {"content": "print('Hello World'); x = 1 + 1"}
    result = analyzer.analyze(clean_code)
    assert result["is_malware"] is False
