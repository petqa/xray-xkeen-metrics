package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/hpcloud/tail"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

// Флаги для включения или отключения меток
var (
	enableSourceIP = flag.Bool("enableSourceIP", true, "Enable or disable the source IP label")
	enableProtocol = flag.Bool("enableProtocol", true, "Enable or disable the protocol label")
	enableDestIP   = flag.Bool("enableDestIP", true, "Enable or disable the destination IP label")
	enableDestPort = flag.Bool("enableDestPort", true, "Enable or disable the destination port label")
	enableFrom     = flag.Bool("enableFrom", true, "Enable or disable the 'from' label")
	enableTo       = flag.Bool("enableTo", true, "Enable or disable the 'to' label")

	// Новый флаг для пути логов воркеров
	workerLogPath = flag.String("worker-log", "", "Path to write worker logs. If empty, worker logs are disabled")
)

// Метрики Prometheus
var (
	connectionsVec    *prometheus.CounterVec
	unparsedLogsCount prometheus.Counter
	enabledLabels     []string
)

// Логгер для воркеров
var workerLogger *log.Logger

// Структура конфигурации
type Config struct {
	LogFilePath     string `yaml:"log_file_path"`
	WorkerLogPath   string `yaml:"worker_log_path"`
	PrometheusLabels struct {
		EnableSourceIP bool `yaml:"enable_source_ip"`
		EnableProtocol bool `yaml:"enable_protocol"`
		EnableDestIP   bool `yaml:"enable_dest_ip"`
		EnableDestPort bool `yaml:"enable_dest_port"`
		EnableFrom     bool `yaml:"enable_from"`
		EnableTo       bool `yaml:"enable_to"`
	} `yaml:"prometheus_labels"`
}

// Функция для загрузки конфигурации
func loadConfig() (*Config, error) {
	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	return &config, nil
}

// Инициализация логгера для воркеров
func initWorkerLogger() {
	if *workerLogPath != "" {
		// Открываем файл для записи логов воркеров. Создаём его, если он не существует.
		f, err := os.OpenFile(*workerLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Error opening worker log file: %v", err)
		}

		// Создаём новый логгер для воркеров
		workerLogger = log.New(f, "WORKER: ", log.LstdFlags)
	} else {
		// Если путь не указан, используем логгер, который ничего не пишет
		workerLogger = log.New(io.Discard, "", 0)
	}
}

// Функция для чтения булевого значения из переменной окружения
func getEnvAsBool(envKey string, defaultValue bool) bool {
	value := os.Getenv(envKey)
	if value == "" {
		return defaultValue
	}
	parsedValue, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("Warning: Unable to parse environment variable %s as bool: %v. Using default: %t", envKey, err, defaultValue)
		return defaultValue
	}
	return parsedValue
}

// Инициализация метрик Prometheus
func initMetrics() {
	// Проверяем настройки окружения. Если переменная окружения установлена, она переопределяет значение флага.
	if getEnvAsBool("ENABLE_SOURCE_IP", *enableSourceIP) {
		enabledLabels = append(enabledLabels, "source_ip")
	}
	if getEnvAsBool("ENABLE_PROTOCOL", *enableProtocol) {
		enabledLabels = append(enabledLabels, "protocol")
	}
	if getEnvAsBool("ENABLE_DEST_IP", *enableDestIP) {
		enabledLabels = append(enabledLabels, "dest_ip")
	}
	if getEnvAsBool("ENABLE_DEST_PORT", *enableDestPort) {
		enabledLabels = append(enabledLabels, "dest_port")
	}
	if getEnvAsBool("ENABLE_FROM", *enableFrom) {
		enabledLabels = append(enabledLabels, "from")
	}
	if getEnvAsBool("ENABLE_TO", *enableTo) {
		enabledLabels = append(enabledLabels, "to")
	}

	connectionsVec = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "connections_accepted_total",
			Help: "Total number of accepted connections",
		},
		enabledLabels,
	)

	unparsedLogsCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "unparsed_logs_total",
			Help: "Total number of unparsed log entries",
		},
	)

	prometheus.MustRegister(connectionsVec)
	prometheus.MustRegister(unparsedLogsCount)
}

// Функция для выполнения команд асинхронно с использованием start и отслеживанием завершения
func executeCommandAsync(command string, args ...string) {
	log.Printf("Executing command: %s %s", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	// Опционально: Запуск команды в новом сеансе, чтобы она была полностью отсоединена
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	// Перенаправление вывода в файлы или отключение, если нужно
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Запуск команды
	err := cmd.Start()
	if err != nil {
		log.Printf("Error starting command '%s %s': %v. Please check the command and try again.", command, strings.Join(args, " "), err)
		return
	}
	// Ожидание завершения команды
	err = cmd.Wait()
	if err != nil {
		log.Printf("Error executing command '%s %s': %v. Ensure the command is correct and has the necessary permissions.", command, strings.Join(args, " "), err)
	} else {
		log.Printf("Command '%s %s' executed successfully.", command, strings.Join(args, " "))
	}
}

func checkCookie(r *http.Request) bool {
	cookie, err := r.Cookie("AuthToken")
	if err != nil {
		return false
	}
	expectedToken := os.Getenv("AUTH_TOKEN")
	return cookie.Value == expectedToken
}

func restartHandler(w http.ResponseWriter, r *http.Request) {
	if !checkCookie(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Println("Received /restart request")
	// Отправляем ответ клиенту немедленно
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Restarting application...")
	// Проверяем, поддерживает ли ResponseWriter флашинг
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush() // Отправляем данные клиенту немедленно
	} else {
		log.Println("Warning: http.ResponseWriter does not support flusher")
	}
    // Выполняем команду асинхронно
    go func() {
        cmdStr := "/opt/sbin/xkeen -restart"
        cmd := exec.Command("/bin/sh", "-c", cmdStr)
        cmd.SysProcAttr = &syscall.SysProcAttr{
            Setsid: true,
        }
        if err := cmd.Start(); err != nil {
            log.Printf("Error starting '/bin/sh -c \"%s\"': %v", cmdStr, err)
            return
        }
        log.Printf("Command '/bin/sh -c \"%s\"' started successfully.", cmdStr)
    }()
}

// Обработчик для маршрута /pull
func pullHandler(w http.ResponseWriter, r *http.Request) {
	if !checkCookie(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	log.Println("Received /pull request")
	// Отправляем ответ клиенту немедленно
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Initiating git pull...")
	// Проверяем, поддерживает ли ResponseWriter флашинг
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush() // Отправляем данные клиенту немедленно
	} else {
		log.Println("Warning: http.ResponseWriter does not support flusher")
	}
    // Выполняем git pull синхронно и выводим результат
    cmd := exec.Command("git", "-C", "/opt/etc/xray/configs", "pull")
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Error executing git pull: %v. Output: %s", err, output)
        fmt.Fprintf(w, "Error executing git pull: %v\nOutput: %s", err, output)
        return
    }
    log.Printf("Git pull executed successfully. Output: %s", output)
    fmt.Fprintf(w, "Git pull executed successfully. Output: %s", output)
    if flusher, ok := w.(http.Flusher); ok {
        flusher.Flush()
    }
    // Закрываем соединение после выполнения команды
    w.(http.Flusher).Flush()
    w.(http.CloseNotifier).CloseNotify()
}

// Функция для разбора логов
func parseLog(logEntry string) {
    re := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+) from ([\da-fA-F:.]+):(\d+) accepted (tcp|udp):([\da-fA-F:.]+):(\d+) \[(.*?)\s*[-|>]+\s*(.*?)\]`)
	matches := re.FindStringSubmatch(logEntry)
	if len(matches) != 9 {
		// Лог парсинг не удался, увеличиваем счётчик
		unparsedLogsCount.Inc()
		log.Printf("Failed to parse log: %s", logEntry)
		return
	}
	// Извлекаем поля (дата и время игнорируются в этом примере)
	sourceIP := matches[2]
	protocol := matches[4]
	destIP := matches[5]
	destPort := matches[6]
	from := matches[7]
	to := matches[8]
	// Создаем метки Prometheus на основе разобранного лога
	labels := make(prometheus.Labels)
	if getEnvAsBool("ENABLE_SOURCE_IP", *enableSourceIP) {
		labels["source_ip"] = sourceIP
	}
	if getEnvAsBool("ENABLE_PROTOCOL", *enableProtocol) {
		labels["protocol"] = protocol
	}
	if getEnvAsBool("ENABLE_DEST_IP", *enableDestIP) {
		labels["dest_ip"] = destIP
	}
	if getEnvAsBool("ENABLE_DEST_PORT", *enableDestPort) {
		labels["dest_port"] = destPort
	}
	if getEnvAsBool("ENABLE_FROM", *enableFrom) {
		labels["from"] = from
	}
	if getEnvAsBool("ENABLE_TO", *enableTo) {
		labels["to"] = to
	}
	// Увеличиваем соответствующую метрику с заданными лейблами
	connectionsVec.With(labels).Inc()
}

// Функция для запуска HTTP-сервера с метриками и управляющими роутами
func startMetricsServer() {
	// Маршрут для метрик Prometheus
	http.Handle("/metrics", promhttp.Handler())
	// Добавляем обработчики для /restart и /pull
	http.HandleFunc("/restart", restartHandler)
	http.HandleFunc("/pull", pullHandler)
	// Обработчик для маршрута /status
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received /status request")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		cmd := exec.Command("/bin/sh", "-c", "/opt/sbin/xkeen -status")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Error executing status command: %v. Output: %s", err, output)
			fmt.Fprintf(w, "Error executing status command: %v\nOutput: %s", err, output)
			return
		}
		log.Printf("Status command executed successfully. Output: %s", output)
		fmt.Fprintf(w, "Status: %s", output)
	})

	// Запускаем HTTP-сервер на порту 2112
	serverAddr := ":2112"
	log.Printf("Starting metrics and control server on %s...", serverAddr)
	if err := http.ListenAndServe(serverAddr, nil); err != nil {
		log.Fatalf("Error starting HTTP server: %v", err)
	}
}

func main() {
	// Загружаем конфигурацию
	// Пытаемся загрузить конфигурацию из файла
	config, err := loadConfig()
	if err != nil {
		log.Printf("Warning: Could not load config file: %v. Falling back to environment variables.", err)
	}

	// Используем конфигурацию из файла или переменные окружения
	var logFilePath string
	if config != nil {
		logFilePath = config.LogFilePath
		workerLogPath = &config.WorkerLogPath
	} else {
		logFilePath = os.Getenv("LOG_FILE_PATH")
		workerLogPath = new(string)
		*workerLogPath = os.Getenv("WORKER_LOG_PATH")
	}

	// Инициализируем метрики Prometheus
	initMetrics()

	// Инициализируем логгер для воркеров
	initWorkerLogger()

	// Проверяем существование лог-файла
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		log.Fatalf("Error: log file %s does not exist\n", logFilePath)
	}

	// Открываем лог-файл для tail
	t, err := tail.TailFile(logFilePath, tail.Config{Follow: true, ReOpen: true})
	if err != nil {
		log.Fatalf("Error while trying to open the file: %v\n", err)
	}

	// Запускаем HTTP-сервер в отдельной горутине
	go startMetricsServer()

	// Создаём канал для передачи лог-строк между горутинами
	logLines := make(chan string, 100)
	var wg sync.WaitGroup

	// Запускаем несколько воркеров для параллельной обработки лог-строк
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for line := range logLines {
				workerLogger.Printf("Worker %d: Processing log line: %s", workerID, line)
				parseLog(line)
			}
		}(i)
	}

	// Читаем строки из лог-файла и отправляем в канал
	for line := range t.Lines {
		if line.Err != nil {
			log.Printf("Error reading line: %v", line.Err)
			continue
		}
		logLines <- line.Text
	}

	// Закрываем канал и ждём завершения всех воркеров
	close(logLines)
	wg.Wait()
}
