package subjack

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
)

type Results struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
	Domain     string `json:"nonexist_domain,omitempty"`
}

func chkJSON(output string) (json bool) {
	json = false

	if strings.Contains(output, ".json") {
		if output[len(output)-5:] == ".json" {
			json = true
		}
	}

	return json
}

func write(result, output string) {
	f, err := os.OpenFile(output, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()

	_, err = f.WriteString(result)
	if err != nil {
		log.Fatalln(err)
	}
}

func writeJSON(service, url, output string) {
	var r Results
	if strings.Contains(service, "DOMAIN") {
		r = Results{
			Subdomain:  strings.ToLower(url),
			Vulnerable: true,
			Service:    "unregistered domain",
			Domain:     strings.Split(service, " - ")[1],
		}
	} else {
		if service != "" {
			r = Results{
				Subdomain:  strings.ToLower(url),
				Vulnerable: true,
				Service:    strings.ToLower(service),
			}
		} else {
			r = Results{
				Subdomain:  strings.ToLower(url),
				Vulnerable: false,
			}
		}
	}

	f, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer f.Close()

	file, err := io.ReadAll(f)
	if err != nil {
		log.Fatalln(err)
	}

	var data []Results
	json.Unmarshal(file, &data)
	data = append(data, r)

	results, _ := json.Marshal(data)

	wf, err := os.OpenFile(output, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalln(err)
	}

	defer wf.Close()

	wf.Write(results)
}

func readFile(filename string) (content []byte, Error error) {
	return os.ReadFile(filename)
}

func readFileLines(filename string) (lines []string, Error error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

func fingerprints(config []byte) (data []Fingerprints, Error error) {
	err := json.Unmarshal(config, &data)
	return data, err
}
