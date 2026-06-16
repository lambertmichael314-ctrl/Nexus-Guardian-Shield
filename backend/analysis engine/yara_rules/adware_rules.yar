/*
 * CTI Platform — Adware Detection YARA Rules
 * Compatible with yara-python 4.x
 *
 * Scoring: score maps to backend confidence (score/100)
 * MITRE ATT&CK: T1622 (Data Encrypted for Impact), T1647 (Plist File Modification)
 */

// ---------------------------------------------------------------------------
// Basic adware with popup windows
// ---------------------------------------------------------------------------
rule Adware_Basic_Popup
{
    meta:
        description = "Detects Python adware with static GUI popup windows"
        author      = "CTI Platform"
        severity    = "low"
        score       = 30
        category    = "adware"
        mitre_attack= "T1622"
        reference   = "Basic GUI-based adware with static content"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $tk1 = "import tkinter" ascii
        $tk2 = "from tkinter import" ascii
        $tk3 = "import tkinter as tk" ascii
        $tk4 = "from Tkinter import" ascii wide

        $win1 = "tk.Tk()" ascii
        $win2 = "root = Tk()" ascii
        $win3 = "Tkinter.Tk()" ascii wide

        $ad1 = "Advertisement" ascii wide
        $ad2 = "product" ascii wide
        $ad3 = "offer" ascii wide nocase
        $ad4 = "discount" ascii wide
        $ad5 = "free" ascii wide nocase

        $pop1 = ".showinfo(" ascii
        $pop2 = ".showwarning(" ascii
        $pop3 = ".showerror(" ascii

    condition:
        (any of ($tk*)) and
        (any of ($win*) or any of ($pop*)) and
        (any of ($ad*))
}

// ---------------------------------------------------------------------------
// Periodic / scheduled adware
// ---------------------------------------------------------------------------
rule Adware_Intermediate_Periodic
{
    meta:
        description = "Detects Python adware with periodic display and scheduled execution"
        author      = "CTI Platform"
        severity    = "medium"
        score       = 50
        category    = "adware"
        mitre_attack= "T1053"
        reference   = "Scheduled adware with threading or timing mechanisms"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $th1 = "import threading" ascii
        $th2 = "from threading import" ascii
        $ti1 = "import time" ascii
        $sc1 = "import schedule" ascii
        $sc2 = "import sched" ascii

        $tc1 = "threading.Thread(" ascii
        $tc2 = "Thread(target=" ascii
        $tc3b = "threading.Timer(" ascii
        $ts1 = ".start()" ascii

        $sl1 = "time.sleep(" ascii
        $sr1 = "schedule.run_pending()" ascii
        $sr2 = "scheduler.run()" ascii

        $pf1 = "periodic_ad" ascii
        $pf2 = "show_ad_" ascii
        $pf3 = "timer_callback" ascii

    condition:
        (any of ($th*, $sc*)) and
        ($ti1 and (any of ($sl*, $sr*))) and
        (any of ($pf*)) and
        ((any of ($tc*) and $ts1) or any of ($sr*))
}

// ---------------------------------------------------------------------------
// Advanced tracking / data exfiltration adware
// ---------------------------------------------------------------------------
rule Adware_Advanced_Tracking
{
    meta:
        description = "Detects Python adware with user tracking and data exfiltration"
        author      = "CTI Platform"
        severity    = "high"
        score       = 75
        category    = "adware"
        mitre_attack= "T1041"
        reference   = "Adware with network communication and data collection"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $net1 = "import requests" ascii
        $net2 = "import urllib" ascii
        $net3 = "import socket" ascii
        $net4 = "import http.client" ascii

        $enc1 = "import base64" ascii
        $enc2 = "import json" ascii
        $enc3 = "import pickle" ascii

        $exf1 = "requests.post(" ascii
        $exf2 = "requests.get(" ascii
        $exf3 = "urlopen(" ascii
        $exf4 = "send_data" ascii
        $exf5 = "upload_data" ascii
        $exf6 = "transmit" ascii

        $col1 = "user_data" ascii
        $col2 = "user_input" ascii
        $col3 = "keystroke" ascii
        $col4 = "click" ascii wide

        $trk1 = "tracking_id" ascii
        $trk2 = "session_id" ascii
        $trk3 = "user_id" ascii

        $c2a = ".php" ascii
        $c2b = ".asp" ascii
        $c2c = "collect" ascii
        $c2d = "track" ascii

        $enc_fn1 = "encrypt" ascii
        $enc_fn2 = "cipher" ascii
        $enc_fn3 = "encode" ascii

    condition:
        (any of ($net*)) and
        (any of ($exf*) or any of ($c2*)) and
        (any of ($col*) or any of ($trk*)) and
        (any of ($enc*, $enc_fn*))
}

// ---------------------------------------------------------------------------
// AI-enhanced / ML-driven adware
// ---------------------------------------------------------------------------
rule Adware_AI_Enhanced
{
    meta:
        description = "Detects AI-enhanced Python adware with ML capabilities"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "adware"
        mitre_attack= "T1027.010"
        reference   = "ML-based adware with content generation and adaptive targeting"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $ml1 = "from sklearn" ascii
        $ml2 = "import tensorflow" ascii
        $ml3 = "import keras" ascii
        $ml4 = "import torch" ascii
        $ml5 = "import numpy" ascii
        $ml6 = "import pandas" ascii

        $nn1 = "neural" ascii nocase
        $nn2 = "load_model" ascii
        $nn3 = "fit(" ascii
        $nn4 = "predict(" ascii

        $gen1 = "generate_ad" ascii
        $gen2 = "generate_content" ascii
        $gen3 = "create_ad" ascii
        $gen4 = "recommend" ascii

        $adp1 = "adaptive" ascii
        $adp2 = "learn_from" ascii
        $adp3 = "optimize" ascii

        $ad_txt1 = "amazing product" ascii wide
        $ad_txt2 = "off on your" ascii wide
        $ad_txt3 = "limited time offer" ascii wide
        $ad_txt4 = "click here" ascii wide

    condition:
        (any of ($ml*)) and
        (any of ($nn*, $gen*, $adp*)) and
        (any of ($ad_txt*))
}

// ---------------------------------------------------------------------------
// Obfuscated / evasive adware
// ---------------------------------------------------------------------------
rule Adware_Obfuscated
{
    meta:
        description = "Detects obfuscated Python adware using evasion techniques"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "adware"
        mitre_attack= "T1027"
        reference   = "Obfuscated adware with string encoding and anti-analysis"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $obf1 = "base64.b64decode" ascii
        $obf2 = "eval(" ascii
        $obf3 = "exec(" ascii
        $obf4 = "compile(" ascii

        $vm1 = "vmware" ascii nocase
        $vm2 = "virtualbox" ascii nocase
        $dbg = "debugger" ascii nocase
        $slp = "time.sleep(10)" ascii

        $imp1 = "__import__" ascii
        $imp2 = "importlib.import_module" ascii
        $imp3 = "getattr(" ascii

        $chr1 = "chr(" ascii
        $glb1 = "globals()[" ascii
        $loc1 = "locals()[" ascii

    condition:
        (any of ($obf*)) and
        (any of ($imp*, $chr1)) and
        (any of ($vm*, $dbg, $slp, $glb1, $loc1))
}

// ---------------------------------------------------------------------------
// Persistence mechanisms
// ---------------------------------------------------------------------------
rule Adware_Persistence
{
    meta:
        description = "Detects Python adware with startup persistence mechanisms"
        author      = "CTI Platform"
        severity    = "medium"
        score       = 55
        category    = "adware"
        mitre_attack= "T1547"
        reference   = "Adware with startup persistence mechanisms"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $reg1 = "winreg" ascii
        $reg2 = "Registry" ascii

        $persist1 = "persistence" ascii
        $persist2 = "autostart" ascii
        $persist3 = "add_to_startup" ascii
        $persist4 = "startup" ascii nocase

        $fs1 = "open(" ascii
        $fs2 = ".write(" ascii
        $fs3 = "w+" ascii

        $win_path = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu" ascii
        $lin_path1 = "/.config/autostart/" ascii
        $lin_path2 = "crontab" ascii
        $mac_path = "Library/LaunchAgents" ascii

    condition:
        (any of ($persist*) or any of ($reg*)) and
        ($fs1 and ($fs2 or $fs3)) and
        (any of ($win_path, $lin_path*, $mac_path))
}