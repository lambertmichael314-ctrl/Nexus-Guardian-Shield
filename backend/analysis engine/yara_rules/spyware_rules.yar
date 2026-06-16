/*
 * CTI Platform — Spyware Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Spyware_BrowserDataTheft
{
    meta:
        description = "Detects browser credential and cookie theft"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "spyware"
        mitre_attack= "T1555.003"
        reference   = "Browser data exfiltration"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $db1 = "sqlite3.connect(" ascii
        $db2 = "SELECT host_key" ascii
        $db3 = "SELECT name, value FROM cookies" ascii
        $db4 = "Cookies" ascii

        $path1 = "google-chrome" ascii
        $path2 = "Mozilla/Firefox" ascii
        $path3 = "Edge" ascii
        $path4 = "AppData\\Local" ascii

        $exf1 = "requests.post(" ascii
        $exf2 = "requests.get(" ascii
        $exf3 = "urlopen(" ascii

        $fn1 = "steal_cookies" ascii
        $fn2 = "get_passwords" ascii
        $fn3 = "extract_credentials" ascii
    condition:
        (any of ($db*)) and (any of ($path*)) and (any of ($exf*)) and (any of ($fn*))
}

rule Spyware_ScreenCapture
{
    meta:
        description = "Detects screenshot capture spyware"
        author      = "CTI Platform"
        severity    = "high"
        score       = 75
        category    = "spyware"
        mitre_attack= "T1113"
        reference   = "Screen capture and image exfiltration"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $img1 = "ImageGrab.grab()" ascii
        $img2 = "pyscreenshot" ascii
        $img3 = "PIL.ImageGrab" ascii
        $img4 = "screenshot" ascii

        $save1 = ".save(" ascii
        $save2 = "open(" ascii

        $exf1 = "requests.post(" ascii
        $exf2 = "upload_file(" ascii
        $exf3 = "send_file(" ascii

        $fn1 = "take_screenshot" ascii
        $fn2 = "capture_screen" ascii
    condition:
        (any of ($img*)) and (any of ($save*)) and (any of ($exf*)) and (any of ($fn*))
}

rule Spyware_DataExfiltration
{
    meta:
        description = "Detects general data exfiltration spyware"
        author      = "CTI Platform"
        severity    = "high"
        score       = 70
        category    = "spyware"
        mitre_attack= "T1041"
        reference   = "General data theft and exfiltration"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $cred1 = "getpass.getuser()" ascii
        $cred2 = "getpass.getpass(" ascii
        $cred3 = "os.getlogin()" ascii

        $net1 = "requests.post(" ascii
        $net2 = "requests.get(" ascii
        $net3 = "urllib.request" ascii

        $exf1 = "exfil_data" ascii
        $exf2 = "send_data" ascii
        $exf3 = "upload_data" ascii
        $exf4 = "stolen" ascii

    condition:
        (any of ($cred*)) and (any of ($net*)) and (any of ($exf*))
}

rule Spyware_KeystrokeAndClipboard
{
    meta:
        description = "Detects keystroke logging and clipboard monitoring spyware"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 85
        category    = "spyware"
        mitre_attack= "T1056.001"
        reference   = "Keystroke and clipboard capture"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $key1 = "keyboard.on_press(" ascii
        $key2 = "keyboard.hook(" ascii
        $key3 = "pynput.keyboard" ascii

        $clip1 = "pyperclip.paste()" ascii
        $clip2 = "win32clipboard" ascii
        $clip3 = "clipboard" ascii

        $exf1 = "requests.post(" ascii
        $exf2 = "send_mail(" ascii

        $fn1 = "capture_keys" ascii
        $fn2 = "monitor_clipboard" ascii
    condition:
        ((any of ($key*)) or (any of ($clip*))) and (any of ($exf*)) and (any of ($fn*))
}