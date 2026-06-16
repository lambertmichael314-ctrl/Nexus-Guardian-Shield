/*
 * CTI Platform — Trojan Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Trojan_ReverseShell
{
    meta:
        description = "Detects reverse shell trojan patterns"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "trojan"
        mitre_attack= "T1059.004"
        reference   = "Reverse shell backdoor"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $sock1 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" ascii
        $sock2 = "socket.AF_INET" ascii
        $sock3 = "socket.SOCK_STREAM" ascii

        $conn1 = ".connect((" ascii
        $conn2 = "s.connect(" ascii

        $loop1 = "while True:" ascii
        $recv1 = "s.recv(" ascii
        $recv2 = ".recv(1024)" ascii

        $cmd1 = "subprocess.Popen(" ascii
        $cmd2 = "os.system(" ascii
        $cmd3 = "subprocess.call(" ascii
        $cmd4 = "shell=True" ascii

        $send1 = "s.sendall(" ascii
        $send2 = "s.send(" ascii

        $fn1 = "connect_back" ascii
        $fn2 = "reverse_shell" ascii
        $fn3 = "backdoor" ascii
    condition:
        (any of ($sock*)) and (any of ($conn*)) and $loop1 and (any of ($recv*)) and
        (any of ($cmd*)) and (any of ($send*)) and (any of ($fn*))
}

rule Trojan_CommandExecution
{
    meta:
        description = "Detects remote command execution trojan"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "trojan"
        mitre_attack= "T1059"
        reference   = "Remote command execution via network"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $net1 = "import socket" ascii
        $net2 = "socket.socket(" ascii

        $recv1 = ".recv(" ascii
        $recv2 = ".decode()" ascii

        $exec1 = "subprocess.Popen(" ascii
        $exec2 = "os.system(" ascii
        $exec3 = "subprocess.run(" ascii
        $exec4 = "shell=True" ascii

        $send1 = ".sendall(" ascii
        $send2 = ".send(" ascii
        $send3 = ".stdout" ascii
    condition:
        (any of ($net*)) and (any of ($recv*)) and (any of ($exec*)) and (any of ($send*))
}

rule Trojan_NetworkBeacon
{
    meta:
        description = "Detects network beaconing trojan behavior"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "trojan"
        mitre_attack= "T1071"
        reference   = "Periodic C2 beaconing"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $host1 = "HOST =" ascii
        $host2 = "host =" ascii
        $host3 = "C2_SERVER" ascii
        $host4 = "SERVER =" ascii

        $port1 = "PORT =" ascii
        $port2 = "port =" ascii

        $loop1 = "while True:" ascii
        $sleep1 = "time.sleep(" ascii
        $conn1 = "socket.connect(" ascii
        $conn2 = ".connect((" ascii
    condition:
        (any of ($host*)) and (any of ($port*)) and $loop1 and $sleep1 and (any of ($conn*))
}

rule Trojan_DownloadAndExecute
{
    meta:
        description = "Detects download and execute trojan"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "trojan"
        mitre_attack= "T1105"
        reference   = "Payload download and execution"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $dl1 = "requests.get(" ascii
        $dl2 = "urlopen(" ascii
        $dl3 = "urllib.request" ascii

        $exec1 = "exec(" ascii
        $exec2 = "eval(" ascii
        $exec3 = "subprocess.call(" ascii
        $exec4 = "os.system(" ascii

        $write1 = ".write(" ascii
        $open1 = "open(" ascii
    condition:
        (any of ($dl*)) and (any of ($exec*)) and $write1 and $open1
}
