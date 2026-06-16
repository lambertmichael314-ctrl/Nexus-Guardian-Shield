/*
 * CTI Platform — Ransomware Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Ransomware_FileEncryption
{
    meta:
        description = "Detects file encryption ransomware patterns"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "ransomware"
        mitre_attack= "T1486"
        reference   = "File encryption with ransom note"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $crypt1 = "from Crypto.Cipher import" ascii
        $crypt2 = "import cryptography" ascii
        $crypt3 = "from cryptography" ascii
        $crypt4 = "Cipher(" ascii
        $crypt5 = "AES.new(" ascii

        $walk1 = "os.walk(" ascii
        $walk2 = "os.listdir(" ascii
        $walk3 = "glob.glob(" ascii

        $enc1 = ".encrypt(" ascii
        $enc2 = "cipher.encrypt(" ascii
        $enc3 = "encrypt(data)" ascii

        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crypto" ascii

        $del1 = "os.remove(" ascii
        $del2 = "os.unlink(" ascii

        $note1 = "ransom" ascii
        $note2 = "bitcoin" ascii
        $note3 = "wallet_address" ascii
        $note4 = "pay" ascii
    condition:
        (any of ($crypt*)) and (any of ($walk*)) and (any of ($enc*)) and
        (any of ($ext*) or any of ($del*)) and (any of ($note*))
}

rule Ransomware_Basic
{
    meta:
        description = "Detects basic ransomware with file overwrite"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "ransomware"
        mitre_attack= "T1486"
        reference   = "Basic file locking ransomware"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $walk1 = "os.walk(" ascii
        $open1 = "open(filepath" ascii
        $open2 = "open(file" ascii
        $rb1 = "\"rb\"" ascii
        $wb1 = "\"wb\"" ascii

        $key1 = "key =" ascii
        $key2 = "encryption_key" ascii

        $write1 = "f.write(" ascii
        $remove1 = "os.remove(" ascii

        $ransom1 = "ransom.txt" ascii
        $ransom2 = "README" ascii
        $ransom3 = "PAYMENT" ascii
    condition:
        $walk1 and (any of ($open*)) and (any of ($rb1, $wb1)) and
        (any of ($key*)) and $write1 and $remove1 and (any of ($ransom*))
}

rule Ransomware_Note
{
    meta:
        description = "Detects ransomware note creation"
        author      = "CTI Platform"
        severity    = "high"
        score       = 70
        category    = "ransomware"
        mitre_attack= "T1491"
        reference   = "Ransom note dropped on system"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $note1 = "ransom" ascii wide
        $note2 = "bitcoin" ascii wide
        $note3 = "wallet" ascii wide
        $note4 = "pay" ascii wide
        $note5 = "decrypt" ascii wide
        $note6 = "your files have been" ascii wide
        $note7 = "encrypted" ascii wide

        $write1 = ".write(" ascii
        $open1 = "open(" ascii
    condition:
        (2 of ($note*)) and $write1 and $open1
}
