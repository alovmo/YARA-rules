import "hash"
rule yara_rule_hash
{meta:
        desc = "Adapt the rule to contain the SHA256 value of the file you have identified as ransomware. Insert the hash after =="
    condition:
       hash.sha256(0,filesize) == ""
}