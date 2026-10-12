package subjack

import (
	"bytes"
	"strings"
)

type Fingerprint struct {
	Service     string   `json:"service"`
	Cname       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Nxdomain    bool     `json:"nxdomain"`
}

// matchesCNAME reports whether a CNAME target matches any fingerprint's
// CNAME pattern. Empty patterns are body-only services (e.g. worksites.net)
// and never match by CNAME.
func matchesCNAME(cname string, fingerprints []Fingerprint) bool {
	for _, fp := range fingerprints {
		for _, c := range fp.Cname {
			if c == "" {
				continue
			}
			if strings.Contains(cname, c) {
				return true
			}
		}
	}
	return false
}

func verifyCNAME(subdomain string, o *Options) bool {
	return matchesCNAME(resolveCNAME(subdomain, o), o.fingerprints)
}

func detect(url string, o *Options) {
	service := identify(url, o)
	printResult(service, url, o)
}

func identify(subdomain string, o *Options) string {
	cname := strings.TrimSuffix(resolveCNAME(subdomain, o), ".")
	if len(cname) <= 3 {
		cname = ""
	}

	if isNXDOMAIN(subdomain, o) {
		if o.domainAvailable(cname) {
			return "DOMAIN AVAILABLE - " + cname
		}

		for _, fp := range o.fingerprints {
			if fp.Nxdomain {
				for _, c := range fp.Cname {
					if c == "" {
						continue
					}
					if strings.Contains(cname, c) {
						service := strings.ToUpper(fp.Service)
						if strings.HasPrefix(service, "AZURE-") {
							service = verifyAzure(service, cname, o)
							if service == "" {
								return ""
							}
						}
						return service
					}
				}
			}
		}

		if o.Manual && cname != "" {
			return "DEAD DOMAIN - " + cname
		}

		return ""
	}

	body := httpGet(subdomain, o.Ssl, o.Timeout)
	for _, fp := range o.fingerprints {
		for _, pattern := range fp.Fingerprint {
			if bytes.Contains(body, []byte(pattern)) {
				return strings.ToUpper(fp.Service)
			}
		}
	}

	return ""
}
