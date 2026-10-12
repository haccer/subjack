package subjack

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnsPort is the port used for direct queries to authoritative servers
// (SOA probes and AXFR). It is a variable so tests can point these
// queries at a local fixture.
var dnsPort = "53"

// withDNSPort appends the authoritative-query port to a hostname unless
// it already carries one.
func withDNSPort(host string) string {
	host = strings.TrimSuffix(host, ".")
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, dnsPort)
}

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
			cloudNSes = append(cloudNSes, withDNSPort(ns))
			provider = p
		}
	}
	if len(cloudNSes) == 0 {
		return
	}

	timeout := time.Duration(o.Timeout) * time.Second

	if !allNSFailSOA(domain, cloudNSes, timeout) {
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

// allNSFailSOA reports whether every authoritative server refuses or fails
// a direct SOA query for the zone, which indicates the hosted zone is gone.
func allNSFailSOA(domain string, nsAddrs []string, timeout time.Duration) bool {
	client := &dns.Client{Timeout: timeout}

	soaMsg := new(dns.Msg)
	soaMsg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	soaMsg.RecursionDesired = false

	failed := 0
	for _, ns := range nsAddrs {
		resp, _, err := client.Exchange(soaMsg, ns)
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			failed++
		}
	}

	// All cloud NS must return failure to confirm
	return failed > 0 && failed == len(nsAddrs)
}
