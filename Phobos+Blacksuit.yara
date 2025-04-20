import "pe"
import "math"
rule high_entropy_suspicious_imports
{
    meta:
        desc = "Detects if the file loads suspicious functions from kernel32.dll and this is inluded in the PE header"
        author = "Alida Oevermo-Mortensen"
        date = "2025-04-07"
    condition:
        pe.imports("kernel32.dll", "Sleep") and pe.imports("kernel32.dll", "WaitForMultipleObjects") and pe.imports("kernel32.dll", "WaitForSingleObject") and not pe.is_dll() and math.entropy(0, filesize) >= 6.8
} 
