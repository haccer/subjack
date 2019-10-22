package subjack

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
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

func open(path string) (lines []string, Error error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
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

	file, err := ioutil.ReadAll(f)
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

	wf.Write(results)
}

func fingerprints(file string, includeEdge bool) (data []Fingerprints) {
	config, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln(err)
	}

	err = json.Unmarshal(config, &data)
	if err != nil {
		log.Fatalln(err)
	}

	if includeEdge {
		return data
	}

	var v []Fingerprints

	for _, s := range data {
		if !s.Edge {
			v = append(v, s)
		}
	}

	return v
}
