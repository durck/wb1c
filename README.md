# wb1c
web bruter for 1c

I reversed javascript from 1c login page. Understood how the algorithm works while generating auth-string before sending on the server.

## What in files?
- 1c_bruter.py - POC written by me, tested and works in the wild
- 1c_bruter_optimized.py - Some changes for optimization written by chatGPT (has not been tested fully)
- 1c_bruter_optimized.go - For those who loves golang. Written by chatGPT (has not been tested fully)

## Algorythm
- key1 = `AES256-CBC(data=rand(32 bytes), key=sha256(base64(sha1(password)))`
- key2 = `AES256-CBC(data=rand(32 bytes), key=sha256(base64(sha1(upper(password))))`
- data1 = `bytes(login)`
- payload = `[1, len(key1), key1, len(key2), key2, packed_little-endian(len(data1)), data1]`
- checksum = `crc32(payload)`
- result = `base64(payload + packed_little-endian(checksum))`
