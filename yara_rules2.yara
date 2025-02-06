rule Detect_Overly_Happy_Executables
{
    meta:
        description = "Detects executables with overly positive vibes"
        author = "CyberJoker"
        date = "2025-01-27"
    strings:
        $happy1 = "happiness"
        $happy2 = "smile"
        $happy3 = "joy"
    condition:
        uint16(0) == 0x5A4D and 3 of ($happy*)
}

rule Cats_All_Over_The_Code
{
    meta:
        description = "Detects files filled with cat references"
        author = "CyberJoker"
        date = "2025-01-27"
    strings:
        $cat1 = "meow"
        $cat2 = "purr"
        $cat3 = "whiskers"
    condition:
        all of ($cat*)
}
