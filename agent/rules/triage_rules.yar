import "math"

rule Triage_High_Entropy_Packed
{
    meta:
        description = "Detects high-entropy files likely packed or obfuscated"
        author = "Roman Oglan - Group 29 Comp 4990"
        stage = "TRIAGE"
        severity = "medium"

    condition:
        filesize > 50KB and
        math.entropy(0, filesize) > 7.2
}
