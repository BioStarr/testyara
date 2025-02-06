rule Dangerous_Amount_of_Coffee
{
    meta:
        description = "Detects programs obsessed with coffee"
        author = "CyberJoker"
        date = "2025-01-27"
    strings:
        $coffee1 = "espresso"
        $coffee2 = "latte"
        $coffee3 = "caffeine"
    condition:
        uint16(0) == 0x4D5A and 2 of ($coffee*)
}

rule Definitely_Not_A_Virus
{
    meta:
        description = "Detects files insisting they're not viruses"
        author = "CyberJoker"
        date = "2025-01-27"
    strings:
        $suspicious1 = "I_am_not_a_virus"
        $suspicious2 = "safe_file"
        $suspicious3 = "trust_me"
    condition:
        any of ($suspicious*)
}
