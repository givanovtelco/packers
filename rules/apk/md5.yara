import "hash" 

rule md5crap {

    meta:
        description = "md5 rule"
	author = "Georgi Ivanov"

    condition:
        filesize < 1MB and
        hash.md5(0, filesize) == "72d2b67b1b039fee2d153f3a410cbb43"     
}
