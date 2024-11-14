package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"

	"github.com/hpcloud/tail"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    enableSourceIP = flag.Bool("enableSourceIP", true, "Enable or disable the source IP label")
    enableProtocol = flag.Bool("enableProtocol", true, "Enable or disable the protocol label")
    enableDestIP   = flag.Bool("enableDestIP", true, "Enable or disable the destination IP label")
    enableDestPort = flag.Bool("enableDestPort", true, "Enable or disable the destination port label")
    enableFrom     = flag.Bool("enableFrom", true, "Enable or disable the 'from' label")
    enableTo       = flag.Bool("enableTo", true, "Enable or disable the 'to' label")
)

var (
    connectionsVec    *prometheus.CounterVec
    unparsedLogsCount prometheus.Counter
    enabledLabels     []string
)

// getEnvAsBool returns the value of an environment variable as a bool.
// If the environment variable is not present or not valid, it returns the default fallback value.
func getEnvAsBool(envKey string, defaultValue bool) bool {
    value := os.Getenv(envKey) // os.Getenv only returns one value
    if value == "" {
        // If the environment variable is missing, return the default value
        return defaultValue
    }

    // Try to parse the string value as a boolean
    parsedValue, err := strconv.ParseBool(value)
    if err != nil {
        log.Printf("Warning: Unable to parse environment variable %s as bool: %v. Using default: %t", envKey, err, defaultValue)
        return defaultValue
    }

    return parsedValue
}

func initMetrics() {
    // Check the environment settings. If an environment variable is set, it overrides the flag value.
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
        enabledLabels, // Array of enabled labels
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

func parseLog(logEntry string) {
    re := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) from ([\da-fA-F:.]+):(\d+) accepted (tcp|udp):([\da-fA-F:.]+):(\d+) \[(.*?) -> (.*?)\]`)
    matches := re.FindStringSubmatch(logEntry)

    if len(matches) != 9 {
        // Log parsing failed, increment the counter
        unparsedLogsCount.Inc()
        log.Printf("Failed to parse log: %s", logEntry)
        return
    }

    // Extract the fields (date and time are ignored in this example)
    sourceIP := matches[2]
    _ = matches[3] // Ignore sourcePort, if not needed
    protocol := matches[4]
    destIP := matches[5]
    destPort := matches[6]
    from := matches[7]
    to := matches[8]

    // Create Prometheus labels based on the parsed log file
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

    // Increment the associated metric with labels
    connectionsVec.With(labels).Inc()
}

func startMetricsServer() {
    http.Handle("/metrics", promhttp.Handler())
    fmt.Println("Starting metrics server on :2112...")
    log.Fatal(http.ListenAndServe(":2112", nil))
}

func main() {
    logFilePath := flag.String("log", "/opt/var/log/xray/access.log", "Path to the log file to read")
    flag.Parse()

    initMetrics()

    if _, err := os.Stat(*logFilePath); os.IsNotExist(err) {
        log.Fatalf("Error: log file %s does not exist\n", *logFilePath)
    }

    t, err := tail.TailFile(*logFilePath, tail.Config{Follow: true, ReOpen: true})
    if err != nil {
        log.Fatalf("Error while trying to open the file: %v\n", err)
    }

    go startMetricsServer()

    logLines := make(chan string, 100)
    var wg sync.WaitGroup

    for i := 0; i < 5; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for line := range logLines {
                parseLog(line)
            }
        }()
    }

    for line := range t.Lines {
        logLines <- line.Text
    }

    close(logLines)
    wg.Wait()
}