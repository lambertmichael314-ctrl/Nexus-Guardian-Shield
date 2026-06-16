/*
 * CTI Platform — Virus Detection YARA Rules
 * Compatible with yara-python 4.x
 */

rule Virus_FileInfection
{
    meta:
        description = "Detects file infecting virus patterns"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 95
        category    = "virus"
        mitre_attack= "T1497.001"
        reference   = "File infection via code injection"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $marker1 = "# VIRUS START" ascii
        $marker2 = "# VIRUS END" ascii
        $marker3 = "# INFECTED" ascii
        $marker4 = "infection_marker" ascii
        $marker5 = "infected" ascii
        $marker6 = "infection" ascii

        $glob1 = "glob.glob(" ascii
        $glob2 = "os.listdir(" ascii
        $glob3 = "os.walk(" ascii

        $read1 = "open(target, \"r\")" ascii
        $read2 = ".read()" ascii
        $write1 = "open(target, \"w\")" ascii
        $write2 = ".write(" ascii

        $self1 = "sys.argv[0]" ascii
        $self2 = "__file__" ascii
    condition:
        (any of ($marker*)) and (any of ($glob*)) and (any of ($read*)) and
        (any of ($write*)) and (any of ($self*))
}

rule Virus_SelfReplication
{
    meta:
        description = "Detects self-replicating virus code"
        author      = "CTI Platform"
        severity    = "critical"
        score       = 90
        category    = "virus"
        mitre_attack= "T1497"
        reference   = "Self-replication via file copying"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $copy1 = "shutil.copy(" ascii
        $copy2 = "shutil.copyfile(" ascii
        $copy3 = "shutil.copy2(" ascii

        $self1 = "sys.argv[0]" ascii
        $self2 = "__file__" ascii
        $self3 = "os.path.basename(" ascii

        $loop1 = "for target in" ascii
        $loop2 = "for file in" ascii
        $loop3 = "glob.glob(" ascii

        $exec1 = "os.execv(" ascii
        $exec2 = "subprocess.call(" ascii
    condition:
        (any of ($copy*)) and (any of ($self*)) and (any of ($loop*)) and (any of ($exec*))
}

rule Virus_CodeInjection
{
    meta:
        description = "Detects code injection virus patterns"
        author      = "CTI Platform"
        severity    = "high"
        score       = 85
        category    = "virus"
        mitre_attack= "T1055"
        reference   = "Code injection into host files"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $inject1 = "payload_start" ascii
        $inject2 = "payload_end" ascii
        $inject3 = "virus_code" ascii
        $inject4 = "injected_code" ascii

        $read1 = ".read()" ascii
        $write1 = ".write(" ascii
        $open1 = "open(" ascii

        $exec1 = "exec(" ascii
        $exec2 = "eval(" ascii
        $exec3 = "compile(" ascii
    condition:
        (any of ($inject*)) and $read1 and $write1 and $open1 and (any of ($exec*))
}

rule Virus_PayloadTrigger
{
    meta:
        description = "Detects virus payload trigger conditions"
        author      = "CTI Platform"
        severity    = "high"
        score       = 80
        category    = "virus"
        mitre_attack= "T1497"
        reference   = "Payload execution trigger"
        date        = "2025-10-17"
        version     = "3.0"
    strings:
        $count1 = "infection_count" ascii
        $count2 = "infected_count" ascii
        $count3 = "len(glob.glob(" ascii

        $trigger1 = "if infection_count >" ascii
        $trigger2 = "if count >" ascii
        $trigger3 = "if infected" ascii

        $pay1 = "os.remove(" ascii
        $pay2 = "os.system(" ascii
        $pay3 = "shutil.rmtree(" ascii
    condition:
        (any of ($count*)) and (any of ($trigger*)) and (any of ($pay*))
}
