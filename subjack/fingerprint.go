package subjack

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/haccer/available"
)

type Fingerprints struct {
	Service     string   `json:"service"`
	Cname       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Nxdomain    bool     `json:"nxdomain"`
}

/*
* Triage step to check whether the CNAME matches
* the fingerprinted CNAME of a vulnerable cloud service.
 */
func VerifyCNAME(subdomain string, config []Fingerprints) (match bool) {
	cname := resolve(subdomain)
	match = false

VERIFY:
	for n := range config {
		for c := range config[n].Cname {
			if strings.Contains(cname, config[n].Cname[c]) {
				match = true
				break VERIFY
			}
		}
	}

	return match
}

func detect(url, output string, nocolor, ssl, verbose, manual bool, timeout int, config []Fingerprints) {
	service := Identify(url, ssl, manual, timeout, config)

	if service != "" {
		result := fmt.Sprintf("[%s] %s\n", service, url)
		if nocolor {
			fmt.Printf(result)
		} else {
			c := fmt.Sprintf("\u001b[32;1m%s\u001b[0m", service)
			out := strings.Replace(result, service, c, -1)
			fmt.Printf(out)
		}

		if output != "" {
			if chkJSON(output) {
				writeJSON(service, url, output)
			} else {
				write(result, output)
			}
		}
	}

	if service == "" && verbose {
		result := fmt.Sprintf("[Not Vulnerable] %s\n", url)
		if nocolor {
			fmt.Printf(result)
		} else {
			c := "\u001b[31;1mNot Vulnerable\u001b[0m"
			out := strings.Replace(result, "Not Vulnerable", c, -1)
			fmt.Printf(out)
		}

		if output != "" {
			if chkJSON(output) {
				writeJSON(service, url, output)
			} else {
				write(result, output)
			}
		}
	}
}

/*
* This function aims to identify whether the subdomain
* is attached to a vulnerable cloud service and able to
* be taken over.
 */
func Identify(subdomain string, forceSSL, manual bool, timeout int, fingerprints []Fingerprints) (service string) {
	body := get(subdomain, forceSSL, timeout)

	cname := resolve(subdomain)

	if len(cname) <= 3 {
		cname = ""
	}

	service = ""
	nx := nxdomain(subdomain)

IDENTIFY:
	for f := range fingerprints {

		// Begin subdomain checks if the subdomain returns NXDOMAIN
		if nx {

			// Check if we can register this domain.
			dead := available.Domain(cname)
			if dead {
				service = "DOMAIN AVAILABLE - " + cname
				break IDENTIFY
			}

			// Check if subdomain matches fingerprinted cname
			if fingerprints[f].Nxdomain {
				for n := range fingerprints[f].Cname {
					if strings.Contains(cname, fingerprints[f].Cname[n]) {
						service = strings.ToUpper(fingerprints[f].Service)
						break IDENTIFY
					}
				}
			}

			// Option to always print the CNAME and not check if it's available to be registered.
			if manual && !dead && cname != "" {
				service = "DEAD DOMAIN - " + cname
				break IDENTIFY
			}
		}

		// Check if body matches fingerprinted response
		for n := range fingerprints[f].Fingerprint {
			if bytes.Contains(body, []byte(fingerprints[f].Fingerprint[n])) {
				service = strings.ToUpper(fingerprints[f].Service)
				break
			}
		}
	}

	return service
}
