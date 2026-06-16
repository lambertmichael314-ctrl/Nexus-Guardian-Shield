/*
 * CTI Platform — Rootkit Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Rootkit_KernelModule
{
    meta:
        description = "Detects kernel module loading rootkits"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "rootkit"
        mitre_attack= "T1014"
        reference   = "Kernel-level rootkit via module loading"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $ins1 = "insmod" ascii
        $ins2 = "modprobe" ascii
        $ins3 = "rmmod" ascii

        $mod1 = ".ko" ascii
        $mod2 = "kernel module" ascii
        $mod3 = "hidden_module" ascii

        $priv1 = "os.geteuid() == 0" ascii
        $priv2 = "getuid() == 0" ascii
        $priv3 = "sudo " ascii

        $sys1 = "os.system(" ascii
        $sys2 = "subprocess.call(" ascii
    condition:
        (any of ($ins*)) and (any of ($mod*)) and (any of ($priv*, $sys*))
}

rule Rootkit_LibraryPreload
{
    meta:
        description = "Detects LD_PRELOAD rootkit techniques"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "rootkit"
        mitre_attack= "T1574.006"
        reference   = "Library preload hijacking"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $ld1 = "LD_PRELOAD" ascii
        $ld2 = "os.environ" ascii
        $ld3 = "putenv(" ascii

        $so1 = ".so" ascii
        $so2 = "libc.so" ascii

        $hide1 = "hidden" ascii
        $hide2 = ".libhide" ascii
        $hide3 = "/dev/." ascii
    condition:
        (any of ($ld*)) and (any of ($so*)) and (any of ($hide*))
}

rule Rootkit_ProcessHiding
{
    meta:
        description = "Detects process and module hiding techniques"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 85
        category    = "rootkit"
        mitre_attack= "T1014"
        reference   = "Process hiding via module manipulation"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $mod1 = "sys.modules" ascii
        $mod2 = "__import__" ascii
        $mod3 = "importlib" ascii

        $hide1 = "hidden" ascii
        $hide2 = "hide_process" ascii
        $hide3 = "hook_" ascii

        $ptr1 = "ctypes" ascii
        $ptr2 = "CDLL(" ascii
        $ptr3 = "c_void_p" ascii
    condition:
        (any of ($mod*) or any of ($ptr*)) and (any of ($hide*))
}

rule Rootkit_CtypesManipulation
{
    meta:
        description = "Detects ctypes-based low-level manipulation"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "rootkit"
        mitre_attack= "T1055"
        reference   = "Low-level system manipulation via ctypes"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $ct1 = "import ctypes" ascii
        $ct2 = "from ctypes import" ascii
        $ct3 = "ctypes.CDLL" ascii

        $call1 = "libc.so" ascii
        $call2 = "kernel32" ascii
        $call3 = "ntdll" ascii

        $priv1 = "os.geteuid()" ascii
        $priv2 = "IsUserAnAdmin" ascii
    condition:
        (any of ($ct*)) and (any of ($call*)) and (any of ($priv*))
}