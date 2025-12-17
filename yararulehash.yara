import "hash"
rule malicous_hash_match
{meta:
        desc = "Adapt the rule to contain the SHA256 value of the file you have identified as ransomware. Insert the hash after =="
        author = "alovmo"
        date = "2025-04-07"
    condition:
       hash.sha256(0,filesize) == ""
}

