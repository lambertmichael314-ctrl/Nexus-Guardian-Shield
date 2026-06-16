/*
 * CTI Platform — Logic Bomb Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule LogicBomb_DateTriggered
{
    meta:
        description = "Detects date-triggered logic bombs"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "logic_bomb"
        mitre_attack= "T1499"
        reference   = "Time-based destructive payload trigger"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $dt1 = "import datetime" ascii
        $dt2 = "from datetime import" ascii
        $dt3 = "datetime.datetime.now()" ascii
        $dt4 = "datetime.date.today()" ascii

        $trig1 = "date_to_trigger" ascii
        $trig2 = "trigger_date" ascii
        $trig3 = "activation_date" ascii
        $trig4 = "if datetime" ascii
        $trig5 = ">= date_to_trigger" ascii

        $pay1 = "os.remove(" ascii
        $pay2 = "shutil.rmtree(" ascii
        $pay3 = "os.system(" ascii
        $pay4 = "subprocess.call(" ascii

        $chk1 = "os.path.exists(" ascii
        $chk2 = "os.path.isfile(" ascii
    condition:
        (any of ($dt*)) and (any of ($trig*)) and (any of ($pay*)) and (any of ($chk*))
}

rule LogicBomb_ConditionalTrigger
{
    meta:
        description = "Detects conditionally triggered destructive payloads"
        author      = "CTI Platform"
        severity    = "high"
        score       = 75
        category    = "logic_bomb"
        mitre_attack= "T1499"
        reference   = "Conditional destructive payload execution"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $cond1 = "if len(os.listdir(" ascii
        $cond2 = "if os.geteuid() == 0" ascii
        $cond3 = "if not os.path.exists(" ascii
        $cond4 = "if user_count == 0" ascii
        $cond5 = "secret_file" ascii

        $dest1 = "os.remove(" ascii
        $dest2 = "shutil.rmtree(" ascii
        $dest3 = "os.system(" ascii
        $dest4 = "subprocess.Popen(" ascii

        $tm1 = "import time" ascii
        $tm2 = "time.sleep(" ascii
    condition:
        (any of ($cond*)) and (any of ($dest*)) and (any of ($tm*))
}

rule LogicBomb_RegistryTrigger
{
    meta:
        description = "Detects registry-based logic bomb triggers"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 85
        category    = "logic_bomb"
        mitre_attack= "T1547"
        reference   = "Windows registry triggered destructive payload"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $reg1 = "import winreg" ascii
        $reg2 = "winreg.OpenKey" ascii
        $reg3 = "winreg.QueryValue" ascii

        $trig1 = "registry_check" ascii
        $trig2 = "reg_trigger" ascii

        $pay1 = "os.remove(" ascii
        $pay2 = "os.system(" ascii
        $pay3 = "shutil.rmtree(" ascii
    condition:
        (any of ($reg*)) and (any of ($trig*)) and (any of ($pay*))
}

rule LogicBomb_Obfuscated
{
    meta:
        description = "Detects obfuscated logic bombs"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "logic_bomb"
        mitre_attack= "T1027"
        reference   = "Obfuscated conditional destructive payload"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $obf1 = "base64.b64decode" ascii
        $obf2 = "eval(" ascii
        $obf3 = "exec(" ascii
        $obf4 = "compile(" ascii

        $tm1 = "time.sleep(" ascii
        $dt1 = "datetime" ascii

        $pay1 = "os.remove(" ascii
        $pay2 = "shutil.rmtree(" ascii
    condition:
        (any of ($obf*)) and (any of ($tm*, $dt1)) and (any of ($pay*))
}
