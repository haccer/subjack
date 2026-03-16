package subjack

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Common nameserver hostname prefixes to bruteforce.
var nsPrefixes = []string{
	"ns", "ns0", "ns1", "ns2", "ns3", "ns4", "ns5",
	"dns", "dns0", "dns1", "dns2", "dns3",
	"dns-0", "dns-1", "dns-2", "dns-3",
	"dns-a", "dns-b", "dns-c", "dns-d",
	"ns-a", "ns-b", "ns-c", "ns-d",
	"ns-0", "ns-1", "ns-2", "ns-3",
	"nsa", "nsb", "nsc", "nsd",
	"dnsa", "dnsb", "dnsc", "dnsd",
	"ns-primary", "ns-secondary",
	"ns-backup", "ns-slave", "ns-master",
	"primary", "secondary",
	"auth-ns0", "auth-ns1", "auth-ns2",
	"cdns1", "cdns2", "cdns3",
	"pdns1", "pdns2",
}

// checkAXFR attempts zone transfers against a domain's nameservers
// and bruteforced nameserver hostnames.
func checkAXFR(domain string, o *Options) {
	// Extract the base domain for NS bruteforcing
	baseDomain := getBaseDomain(domain)
	timeout := time.Duration(o.Timeout) * time.Second

	// 1. Try AXFR against actual NS records
	for _, ns := range lookupNS(domain, o) {
		nsHost := strings.TrimSuffix(ns, ".") + ":53"
		if tryAXFR(domain, nsHost, timeout, o) {
			return
		}
	}

	// Also try NS records of the base domain if different
	if baseDomain != domain {
		for _, ns := range lookupNS(baseDomain, o) {
			nsHost := strings.TrimSuffix(ns, ".") + ":53"
			if tryAXFR(domain, nsHost, timeout, o) {
				return
			}
		}
	}

	// 2. Bruteforce common NS hostnames
	for _, prefix := range nsPrefixes {
		candidate := prefix + "." + baseDomain
		ips, err := net.LookupHost(candidate)
		if err != nil || len(ips) == 0 {
			continue
		}
		if tryAXFR(domain, candidate+":53", timeout, o) {
			return
		}
		// Also try AXFR for the base domain on this NS
		if baseDomain != domain {
			if tryAXFR(baseDomain, candidate+":53", timeout, o) {
				return
			}
		}
	}
}

func tryAXFR(domain, nsHost string, timeout time.Duration, o *Options) bool {
	transfer := &dns.Transfer{
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	ch, err := transfer.In(msg, nsHost)
	if err != nil {
		return false
	}

	var records []string
	for envelope := range ch {
		if envelope.Error != nil {
			return false
		}
		for _, rr := range envelope.RR {
			records = append(records, rr.String())
		}
	}

	if len(records) == 0 {
		return false
	}

	service := "ZONE TRANSFER"
	detail := fmt.Sprintf("%s - AXFR successful on %s (%d records)", domain, nsHost, len(records))

	fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
	if o.Output != "" {
		msg := fmt.Sprintf("[%s] %s\n", service, detail)
		writeOutput(service, domain, msg, o.Output)
	}
	return true
}

func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
