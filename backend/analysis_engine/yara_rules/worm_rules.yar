/*
 * CTI Platform — Worm Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Worm_NetworkPropagation
{
    meta:
        description = "Detects network-propagating worm patterns"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "worm"
        mitre_attack= "T1497"
        reference   = "Self-propagation across network"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $net1 = "ipaddress.IPv4Network" ascii
        $net2 = "socket.connect_ex(" ascii
        $net3 = "for ip in" ascii
        $net4 = ".hosts()" ascii

        $scan1 = "socket.socket(" ascii
        $scan2 = "SOCK_STREAM" ascii
        $scan3 = ".settimeout(" ascii

        $copy1 = "shutil.copy(" ascii
        $copy2 = "shutil.copyfile(" ascii
        $copy3 = "open(" ascii
        $copy4 = ".write(" ascii

        $self1 = "__file__" ascii
        $self2 = "sys.argv[0]" ascii
    condition:
        (any of ($net*)) and (any of ($scan*)) and (any of ($copy*)) and (any of ($self*))
}

rule Worm_PortScanning
{
    meta:
        description = "Detects port scanning worm behavior"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "worm"
        mitre_attack= "T1046"
        reference   = "Network port scanning for propagation"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $sock1 = "socket.socket(" ascii
        $sock2 = "socket.AF_INET" ascii

        $scan1 = ".connect_ex(" ascii
        $scan2 = "for port in range(" ascii
        $scan3 = "for ip in" ascii

        $range1 = "range(1, 1024)" ascii
        $range2 = "range(65535)" ascii
        $range3 = "range(22," ascii
        $range4 = "range(445," ascii

        $chk1 = "if result == 0" ascii
        $chk2 = "== 0:" ascii
    condition:
        (any of ($sock*)) and (any of ($scan*)) and (any of ($range*)) and (any of ($chk*))
}

rule Worm_RemovableMedia
{
    meta:
        description = "Detects removable media propagation worm"
        author      = "CTI Platform"
        severity    = "high"
        score       = 85
        category    = "worm"
        mitre_attack= "T1091"
        reference   = "USB/removable drive propagation"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $drive1 = "chr(drive)" ascii
        $drive2 = "range(65, 91)" ascii
        $drive3 = "drive_letter" ascii
        $drive4 = "GetLogicalDrives" ascii
        $drive5 = "GetDriveType" ascii

        $copy1 = "shutil.copy(" ascii
        $copy2 = "shutil.copyfile(" ascii
        $copy3 = ".write(" ascii

        $auto1 = "autorun" ascii
        $auto2 = "autorun.py" ascii
        $auto3 = "autorun.inf" ascii

        $self1 = "__file__" ascii
        $self2 = "sys.argv[0]" ascii
    condition:
        (any of ($drive*)) and (any of ($copy*)) and (any of ($auto*)) and (any of ($self*))
}

rule Worm_SSHPropagation
{
    meta:
        description = "Detects SSH-based worm propagation"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "worm"
        mitre_attack= "T1021.004"
        reference   = "SSH brute force and lateral movement"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $ssh1 = "paramiko.SSHClient" ascii
        $ssh2 = "paramiko.Transport" ascii
        $ssh3 = "pxssh" ascii
        $ssh4 = "ftplib.FTP" ascii

        $conn1 = ".connect(" ascii
        $conn2 = ".connect_ex(" ascii

        $copy1 = "shutil.copy(" ascii
        $copy2 = ".write(" ascii

        $brute1 = "for password in" ascii
        $brute2 = "for user in" ascii
        $brute3 = "wordlist" ascii
    condition:
        (any of ($ssh*)) and (any of ($conn*)) and (any of ($copy*)) and (any of ($brute*))
}
