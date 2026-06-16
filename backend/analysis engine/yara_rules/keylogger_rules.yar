/*
 * CTI Platform — Keylogger Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Keylogger_Basic_Simple
{
    meta:
        description = "Detects basic Python keylogger with simple keystroke capture"
        author      = "CTI Platform"
        severity    = "medium"
        score       = 50
        category    = "keylogger"
        mitre_attack= "T1056.001"
        reference   = "Basic key capture with file or memory logging"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $pyn1 = "import pynput.keyboard" ascii
        $pyn2 = "from pynput import keyboard" ascii
        $pyn3 = "import pynput" ascii
        $key1 = "import keyboard" ascii
        $pyx1 = "import pyxhook" ascii
        $hook1 = "def on_press(key):" ascii
        $hook2 = "on_press=on_press" ascii
        $hook3 = "def on_release(key):" ascii
        $hook4 = "HookManager" ascii
        $hook5 = "key_hook" ascii
        $log1 = "log = \"\"" ascii
        $log2 = "keystrokes =" ascii
        $log3 = "capture_keys" ascii
        $log4 = "key_log" ascii
        $log5 = "log_file" ascii
        $lst1 = "with pynput.keyboard.Listener" ascii
        $lst2 = "keyboard.Listener" ascii
        $lst3 = ".start()" ascii
        $lst4 = ".join()" ascii
    condition:
        (any of ($pyn*, $key1, $pyx1)) and (any of ($hook*)) and (any of ($log*)) and (any of ($lst*))
}

rule Keylogger_Intermediate_Exfil
{
    meta:
        description = "Detects Python keylogger with network exfiltration"
        author      = "CTI Platform"
        severity    = "high"
        score       = 75
        category    = "keylogger"
        mitre_attack= "T1056.001"
        reference   = "Keylogger with network communication"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $pyn1 = "import pynput.keyboard" ascii
        $key1 = "import keyboard" ascii
        $enc1 = "import base64" ascii
        $enc2 = "import cryptography" ascii
        $net1 = "import requests" ascii
        $net2 = "import urllib" ascii
        $net3 = "import socket" ascii
        $net4 = "import smtplib" ascii
        $exf1 = "requests.post(" ascii
        $exf2 = "requests.get(" ascii
        $exf3 = "send_mail(" ascii
        $exf4 = "send_data" ascii
        $exf5 = "upload_log" ascii
        $col1 = "get_pressed_keys" ascii
        $col2 = "collect_keystrokes" ascii
        $col3 = "capture_input" ascii
        $int1 = "interval" ascii
        $int2 = "buffer_size" ascii
        $int3 = "flush_interval" ascii
    condition:
        (any of ($pyn*, $key1)) and (any of ($enc*)) and (any of ($net*)) and
        (any of ($exf*)) and ((any of ($col*)) or (any of ($int*)))
}

rule Keylogger_Advanced_Capture
{
    meta:
        description = "Detects advanced Python keylogger with screenshot and clipboard"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "keylogger"
        mitre_attack= "T1056.001"
        reference   = "Advanced keylogger with screen capture"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $pyn1 = "import pynput.keyboard" ascii
        $key1 = "import keyboard" ascii
        $scr1 = "from PIL import ImageGrab" ascii
        $scr2 = "ImageGrab.grab()" ascii
        $scr3 = "screenshot" ascii
        $clip1 = "import pyperclip" ascii
        $clip2 = "pyperclip.paste()" ascii
        $clip3 = "clipboard" ascii
        $win1 = "import win32clipboard" ascii
        $win2 = "GetClipboardData" ascii
        $snd1 = "requests.post(" ascii
        $snd2 = "smtplib.SMTP(" ascii
        $snd3 = "upload_file(" ascii
    condition:
        (any of ($pyn*, $key1)) and (any of ($scr*)) and
        ((any of ($clip*)) or (any of ($win*))) and (any of ($snd*))
}

rule Keylogger_AIEnhanced_Behavior
{
    meta:
        description = "Detects AI-enhanced Python keylogger with ML behavior"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "keylogger"
        mitre_attack= "T1056.001"
        reference   = "ML-driven keylogger with adaptive capture"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $ml1 = "from sklearn" ascii
        $ml2 = "import sklearn" ascii
        $ml3 = "import numpy" ascii
        $ml4 = "import tensorflow" ascii
        $ml5 = "import keras" ascii
        $fit1 = "model.fit(" ascii
        $fit2 = ".fit(" ascii
        $pred1 = ".predict(" ascii
        $pred2 = "ml_predict" ascii
        $cap1 = "def capture_clipboard(model):" ascii
        $cap2 = "def ai_monitor(" ascii
        $cap3 = "intelligent_capture" ascii
        $pyper1 = "import pyperclip" ascii
        $feat1 = "extract_features" ascii
        $feat2 = "analyze_context" ascii
        $feat3 = "behavioral_analysis" ascii
    condition:
        (any of ($ml*)) and (any of ($fit*)) and (any of ($pred*)) and
        (any of ($cap*)) and $pyper1 and (any of ($feat*))
}

rule Keylogger_Ethical_Monitoring
{
    meta:
        description = "Detects ethical keylogger for authorized incident response"
        author      = "CTI Platform"
        severity    = "low"
        score       = 10
        category    = "keylogger"
        mitre_attack= "T1056.001"
        reference   = "Legitimate security monitoring"
        date        = "2025-10-17"
        version     = "3.0"
        status      = "informational"
    strings:
        $pyn1 = "import pynput.keyboard" ascii
        $cls1 = "class EthicalKeylogger:" ascii
        $cls2 = "class SecurityMonitor:" ascii
        $meth1 = "def on_press(self, key):" ascii
        $meth2 = "def analyze_command(self):" ascii
        $meth3 = "def save_log(self):" ascii
        $meth4 = "def notify_security_team(self, command):" ascii
        $auth1 = "authorized" ascii
        $auth2 = "security_team" ascii
        $auth3 = "incident_response" ascii
    condition:
        $pyn1 and (any of ($cls*)) and ($meth1 and $meth2 and $meth3) and
        $meth4 and (any of ($auth*))
}

rule Keylogger_Alternative_Methods
{
    meta:
        description = "Detects keyloggers using alternative libraries"
        author      = "CTI Platform"
        severity    = "medium"
        score       = 55
        category    = "keylogger"
        mitre_attack= "T1056.001"
        reference   = "Non-standard libraries and platform-specific techniques"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $lib1 = "import keyboard" ascii
        $lib2 = "import pyxhook" ascii
        $lib3 = "import evdev" ascii
        $lib4 = "import win32api" ascii
        $plat1 = "SetWindowsHookEx" ascii
        $plat2 = "/dev/input" ascii
        $plat3 = "XRecord" ascii
        $plat4 = "CGEventTap" ascii
        $cap1 = "capture_keys" ascii
        $cap2 = "record_keys" ascii
        $cap3 = "key_capture" ascii
    condition:
        (any of ($lib*)) and (any of ($plat*)) and (any of ($cap*))
}

rule Keylogger_Obfuscated
{
    meta:
        description = "Detects obfuscated Python keylogger"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "keylogger"
        mitre_attack= "T1027"
        reference   = "Obfuscated keylogger with encoding"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $obf1 = "base64.b64decode" ascii
        $obf2 = "eval(" ascii
        $obf3 = "exec(" ascii
        $b64_1 = "cHlucHV0LmtleWJvYXJk" ascii
        $b64_2 = "a2V5Ym9hcmQ=" ascii
        $b64_3 = "aG9vaw==" ascii
        $vm1 = "vmware" ascii nocase
        $vm2 = "virtualbox" ascii nocase
        $dbg = "debugger" ascii nocase
        $concat1 = "chr(" ascii
        $glb1 = "globals()[" ascii
        $loc1 = "locals()[" ascii
        $get1 = "getattr(" ascii
    condition:
        (any of ($obf*)) and
        ((any of ($b64*)) or (any of ($concat1, $glb1, $loc1, $get1))) and
        (any of ($vm*, $dbg))
}