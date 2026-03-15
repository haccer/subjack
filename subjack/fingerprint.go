package subjack

import (
	"bytes"
	"strings"

	"github.com/haccer/available"
)

type Fingerprint struct {
	Service     string   `json:"service"`
	Cname       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Nxdomain    bool     `json:"nxdomain"`
}

func verifyCNAME(subdomain string, o *Options) bool {
	cname := resolveCNAME(subdomain, o.resolvers)
	for _, fp := range o.fingerprints {
		for _, c := range fp.Cname {
			if strings.Contains(cname, c) {
				return true
			}
		}
	}
	return false
}

func detect(url string, o *Options) {
	service := identify(url, o)
	printResult(service, url, o)
}

func identify(subdomain string, o *Options) string {
	cname := resolveCNAME(subdomain, o.resolvers)
	if len(cname) <= 3 {
		cname = ""
	}

	if isNXDOMAIN(subdomain) {
		if available.Domain(cname) {
			return "DOMAIN AVAILABLE - " + cname
		}

		for _, fp := range o.fingerprints {
			if fp.Nxdomain {
				for _, c := range fp.Cname {
					if strings.Contains(cname, c) {
						return strings.ToUpper(fp.Service)
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
