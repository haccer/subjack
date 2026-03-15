package subjack

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

//go:embed fingerprints.json
var fingerprintsJSON []byte

const (
	colorGreen = "\033[32;1m"
	colorRed   = "\033[31;1m"
	colorReset = "\033[0m"
)

type Result struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
	Domain     string `json:"nonexist_domain,omitempty"`
}

var outputMu sync.Mutex

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func printResult(service, url string, o *Options) {
	if service != "" {
		colored := colorGreen + service + colorReset
		fmt.Printf("[%s] %s\n", colored, url)

		if o.Output != "" {
			plain := fmt.Sprintf("[%s] %s\n", service, url)
			writeOutput(service, url, plain, o.Output)
		}
		return
	}

	if o.Verbose {
		fmt.Printf("[%sNot Vulnerable%s] %s\n", colorRed, colorReset, url)

		if o.Output != "" {
			plain := fmt.Sprintf("[Not Vulnerable] %s\n", url)
			writeOutput("", url, plain, o.Output)
		}
	}
}

func writeOutput(service, url, plain, output string) {
	outputMu.Lock()
	defer outputMu.Unlock()

	if strings.HasSuffix(output, ".json") {
		appendJSON(service, url, output)
	} else {
		appendText(plain, output)
	}
}

func writeText(text, path string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	appendText(text, path)
}

func appendText(text, path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	if _, err := f.WriteString(text); err != nil {
		log.Fatalln(err)
	}
}

func appendJSON(service, url, path string) {
	var r Result
	if strings.Contains(service, "DOMAIN") {
		r = Result{
			Subdomain:  strings.ToLower(url),
			Vulnerable: true,
			Service:    "unregistered domain",
			Domain:     strings.Split(service, " - ")[1],
		}
	} else if service != "" {
		r = Result{
			Subdomain:  strings.ToLower(url),
			Vulnerable: true,
			Service:    strings.ToLower(service),
		}
	} else {
		r = Result{
			Subdomain:  strings.ToLower(url),
			Vulnerable: false,
		}
	}

	var data []Result
	if existing, err := os.ReadFile(path); err == nil {
		json.Unmarshal(existing, &data)
	}
	data = append(data, r)

	out, _ := json.Marshal(data)
	os.WriteFile(path, out, 0600)
}

func loadFingerprints() []Fingerprint {
	var data []Fingerprint
	if err := json.Unmarshal(fingerprintsJSON, &data); err != nil {
		log.Fatalln(err)
	}
	return data
}
