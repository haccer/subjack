package subjack

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type cloudDNSProvider struct {
	name    string
	pattern *regexp.Regexp
}

var cloudDNSProviders = []cloudDNSProvider{
	{
		name:    "Route53",
		pattern: regexp.MustCompile(`(?i)^ns-\d+\.awsdns-\d+\.(com|net|org|co\.uk)\.?$`),
	},
	{
		name:    "Google Cloud DNS",
		pattern: regexp.MustCompile(`(?i)^ns-cloud-[a-z]\d+\.googledomains\.com\.?$`),
	},
	{
		name:    "Azure DNS",
		pattern: regexp.MustCompile(`(?i)^ns\d+-\d+\.azure-dns\.(com|net|org|info)\.?$`),
	},
	{
		name:    "DigitalOcean DNS",
		pattern: regexp.MustCompile(`(?i)^ns\d+\.digitalocean\.com\.?$`),
	},
	{
		name:    "Vultr DNS",
		pattern: regexp.MustCompile(`(?i)^ns\d+\.vultr\.com\.?$`),
	},
	{
		name:    "Linode DNS",
		pattern: regexp.MustCompile(`(?i)^ns\d+\.linode\.com\.?$`),
	},
}

func identifyDNSProvider(ns string) string {
	ns = strings.TrimSuffix(ns, ".")
	for _, p := range cloudDNSProviders {
		if p.pattern.MatchString(ns) {
			return p.name
		}
	}
	return ""
}

// checkDanglingNS looks for dangling NS delegations to cloud DNS providers.
// If a domain's nameservers belong to a cloud provider but the hosted zone
// has been deleted, direct SOA queries will return SERVFAIL or REFUSED.
func checkDanglingNS(domain string, o *Options) {
	nameservers := lookupNS(domain, o)
	if len(nameservers) == 0 {
		return
	}

	var cloudNSes []string
	var provider string

	for _, ns := range nameservers {
		p := identifyDNSProvider(ns)
		if p != "" {
			cloudNSes = append(cloudNSes, strings.TrimSuffix(ns, ".")+":53")
			provider = p
		}
	}
	if len(cloudNSes) == 0 {
		return
	}

	timeout := time.Duration(o.Timeout) * time.Second
	client := &dns.Client{Timeout: timeout}

	soaMsg := new(dns.Msg)
	soaMsg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	soaMsg.RecursionDesired = false

	failed := 0
	for _, ns := range cloudNSes {
		resp, _, err := client.Exchange(soaMsg, ns)
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			failed++
		}
	}

	// All cloud NS must return failure to confirm
	if failed == 0 || failed != len(cloudNSes) {
		return
	}

	service := "NS DELEGATION TAKEOVER"
	nsList := strings.Join(cloudNSes, ", ")
	detail := fmt.Sprintf("%s - dangling %s delegation (%s)", domain, provider, nsList)

	fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
	if o.Output != "" {
		msg := fmt.Sprintf("[%s] %s\n", service, detail)
		writeOutput(service, domain, msg, o.Output)
	}
}
