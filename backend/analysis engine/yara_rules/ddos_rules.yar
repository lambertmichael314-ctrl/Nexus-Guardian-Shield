/*
 * CTI Platform — DDoS Detection YARA Rules
 * Compatible with yara-python 4.x
 *
 * Scoring: score maps to backend confidence (score/100)
 * MITRE ATT&CK: T1498 (Network Denial of Service), T1499 (Endpoint Denial of Service)
 */

// ---------------------------------------------------------------------------
// Basic single-threaded flood script
// ---------------------------------------------------------------------------
rule DDoS_Basic_SingleThread
{
    meta:
        description = "Detects basic Python DDoS with single-threaded request loops"
        author      = "CTI Platform"
        severity    = "medium"
        score       = 45
        category    = "ddos"
        mitre_attack= "T1498"
        reference   = "Simple HTTP flood with continuous requests"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $req1 = "import requests" ascii
        $req2 = "from requests import" ascii
        $url1 = "import urllib" ascii
        $http1 = "import http.client" ascii

        $target1 = "target = input(" ascii
        $target2 = "url = input(" ascii
        $target3 = "target_url = input(" ascii
        $target4 = "TARGET =" ascii nocase

        $loop1 = "while True:" ascii
        $loop2 = "while 1:" ascii
        $loop3 = "for _ in range(999999)" ascii
        $loop4 = "for _ in range(1000000)" ascii

        $get1 = "requests.get(target)" ascii
        $get2 = ".get(" ascii
        $post1 = "requests.post(" ascii
        $conn1 = "HTTPConnection(" ascii

        $flood1 = "flood" ascii
        $flood2 = "attack" ascii
        $flood3 = "ddos" ascii nocase

    condition:
        (any of ($req*, $url1, $http1)) and
        (any of ($target*)) and
        (any of ($loop*)) and
        (any of ($get*, $post1, $conn1)) and
        (any of ($flood*))
}

// ---------------------------------------------------------------------------
// Multi-threaded concurrent flood
// ---------------------------------------------------------------------------
rule DDoS_Intermediate_MultiThread
{
    meta:
        description = "Detects Python DDoS with multi-threading for higher volume"
        author      = "CTI Platform"
        severity    = "high"
        score       = 70
        category    = "ddos"
        mitre_attack= "T1498"
        reference   = "Multi-threaded HTTP flood with concurrent requests"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $req1 = "import requests" ascii
        $th1  = "import threading" ascii
        $th2  = "from threading import" ascii
        $conc1 = "from concurrent.futures import" ascii

        $tc1 = "num_threads = int(input(" ascii
        $tc2 = "thread_count =" ascii
        $tc3 = "threads = []" ascii
        $tc4 = "for i in range(num_threads)" ascii

        $ts1 = ".start()" ascii
        $tj1 = ".join()" ascii

        $lp1 = "while True:" ascii
        $lp2 = "for _ in range(" ascii

        $at1 = "def attack(" ascii
        $at2 = "def flood(" ascii
        $at3 = "def http_flood(" ascii
        $at4 = "def send_request(" ascii

        $f1 = "requests.get(" ascii
        $f2 = "requests.post(" ascii
        $f3 = ".sendall(" ascii
        $f4 = ".sendto(" ascii

    condition:
        ($req1 and (any of ($th*, $conc1))) and
        (any of ($tc*)) and
        ($ts1 and $tj1) and
        (any of ($lp*)) and
        (any of ($at*)) and
        (any of ($f*))
}

// ---------------------------------------------------------------------------
// Advanced evasion with header spoofing
// ---------------------------------------------------------------------------
rule DDoS_Advanced_Evasion
{
    meta:
        description = "Detects advanced Python DDoS with random User-Agent rotation"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "ddos"
        mitre_attack= "T1498"
        reference   = "Evasive DDoS with header spoofing and proxy rotation"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $req1 = "import requests" ascii
        $th1  = "import threading" ascii
        $rnd1 = "import random" ascii

        $ua1 = "user_agents = [" ascii
        $ua2 = "user_agents_list = [" ascii
        $ua3 = "ua_list = [" ascii
        $ua4 = "browsers = [" ascii

        $sel1 = "random.choice(user_agents)" ascii
        $sel2 = "choice(user_agents)" ascii
        $sel3 = "random_user_agent" ascii

        $hdr1 = "headers = {'User-Agent':" ascii
        $hdr2 = "headers = {" ascii
        $hdr3 = "'User-Agent':" ascii
        $hdr4 = "\"User-Agent\":" ascii

        $atk1 = "def ddos_attack(target, num_threads, duration):" ascii
        $atk2 = "def http_flood(" ascii
        $atk3 = "def spoof_attack(" ascii

        $sp1 = "spoof_headers" ascii
        $sp2 = "fake_headers" ascii
        $sp3 = "custom_headers" ascii

    condition:
        ($req1 and $th1 and $rnd1) and
        (any of ($ua*)) and
        (any of ($sel*)) and
        (any of ($hdr*)) and
        (any of ($atk*)) and
        (any of ($sp*))
}

// ---------------------------------------------------------------------------
// AI-enhanced adaptive DDoS
// ---------------------------------------------------------------------------
rule DDoS_AIEnhanced_Adaptive
{
    meta:
        description = "Detects AI-enhanced Python DDoS with adaptive behavior"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "ddos"
        mitre_attack= "T1498"
        reference   = "ML-driven DDoS with adaptive timing and evasion"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $ml1 = "from sklearn.ensemble import RandomForestClassifier" ascii
        $ml2 = "from sklearn import" ascii
        $ml3 = "import sklearn" ascii
        $ml4 = "import numpy" ascii
        $ml5 = "import pandas" ascii
        $ml6 = "import tensorflow" ascii
        $ml7 = "import keras" ascii

        $fit1 = "model.fit(X, y)" ascii
        $fit2 = "model.train(" ascii
        $fit3 = "train_model(" ascii
        $fit4 = ".fit(" ascii

        $pred1 = "prediction = model.predict(features)" ascii
        $pred2 = "predict(" ascii
        $pred3 = "ml_predict" ascii
        $pred4 = "adaptive_predict" ascii

        $sleep1 = "time.sleep(random.uniform(0.1, 1.0))" ascii
        $sleep1b = "time.sleep(random.uniform(" ascii
        $sleep2 = "adaptive_sleep" ascii
        $sleep3 = "variable_delay" ascii
        $sleep4 = "dynamic_timing" ascii

        $ai1 = "def attack_thread(target, model):" ascii
        $ai2 = "def ai_attack(" ascii
        $ai3 = "intelligent_flood" ascii
        $ai4 = "ml_ddos" ascii

    condition:
        (any of ($ml*)) and
        (any of ($fit*)) and
        (any of ($pred*)) and
        (any of ($sleep*)) and
        (any of ($ai*))
}

// ---------------------------------------------------------------------------
// Raw socket-level flooding
// ---------------------------------------------------------------------------
rule DDoS_Socket_Level
{
    meta:
        description = "Detects Python DDoS using low-level socket operations"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "ddos"
        mitre_attack= "T1498"
        reference   = "Raw socket flooding with packet manipulation"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $sock1 = "import socket" ascii
        $str1  = "import struct" ascii
        $rnd1  = "import random" ascii

        $sc1 = "socket.socket(" ascii
        $sc2 = "sock = socket.socket" ascii
        $raw = "SOCK_RAW" ascii
        $af  = "AF_INET" ascii

        $con1 = ".connect(" ascii
        $snd1 = ".send(" ascii
        $snd2 = ".sendto(" ascii
        $fs1 = "flood_socket" ascii

        $pack1 = "struct.pack(" ascii
        $pack2 = "struct.unpack(" ascii
        $bp1  = "build_packet" ascii
        $sp1  = "send_packet" ascii

        $fl1 = "syn_flood" ascii
        $fl2 = "udp_flood" ascii
        $fl3 = "icmp_flood" ascii
        $fl4 = "tcp_flood" ascii

        $buf1 = "random._urandom(" ascii
        $buf2 = "os.urandom(" ascii
        $buf3 = "1024*" ascii

    condition:
        ($sock1 or $str1 or $rnd1) and
        (any of ($sc*, $raw, $af)) and
        (any of ($snd*, $con1, $fs1)) and
        (any of ($fl*)) and
        (any of ($pack*, $bp1, $sp1, $buf*))
}

// ---------------------------------------------------------------------------
// Obfuscated DDoS scripts
// ---------------------------------------------------------------------------
rule DDoS_Obfuscated
{
    meta:
        description = "Detects obfuscated Python DDoS using encoding techniques"
        author      = "CTI Platform"
        severity    = "high"
        score       = 75
        category    = "ddos"
        mitre_attack= "T1027"
        reference   = "Obfuscated DDoS with string encoding and evasion"
        date        = "2025-10-17"
        version     = "3.0"

    strings:
        $obf1 = "base64.b64decode" ascii
        $obf2 = "eval(" ascii
        $obf3 = "exec(" ascii
        $obf4 = "compile(" ascii

        // base64("requests")  = "cmVxdWVzdHM="
        // base64("socket")   = "c29ja2V0"
        // base64("threading")= "dGhyZWFkaW5n"
        $b64_req = "cmVxdWVzdHM=" ascii
        $b64_sock = "c29ja2V0" ascii
        $b64_thread = "dGhyZWFkaW5n" ascii

        // base64("attack") = "YXR0YWNr"
        // base64("flood")  = "Zmxvb2Q="
        // base64("ddos")   = "ZGRvcw=="
        $b64_atk = "YXR0YWNr" ascii
        $b64_fld = "Zmxvb2Q=" ascii
        $b64_dd = "ZGRvcw==" ascii

        $slp = "time.sleep(10)" ascii
        $vm1 = "vmware" ascii nocase
        $dbg = "debugger" ascii nocase

        $concat1 = "'r'+'e'+'q'+'u'+'e'+'s'+'t'+'s'" ascii
        $concat2 = "chr(" ascii

    condition:
        (any of ($obf*)) and
        ((any of ($b64*)) or (any of ($concat*))) and
        (any of ($slp, $vm1, $dbg))
}