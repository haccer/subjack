package subjack

import (
	"fmt"
	"net"
	"strings"

	"github.com/haccer/available"
	"github.com/miekg/dns"
)

const dnsResolver = "8.8.8.8:53"

func check(url string, o *Options) {
	if o.All {
		detect(url, o)
		return
	}

	if verifyCNAME(url, o.fingerprints) {
		detect(url, o)
		return
	}

	if o.Verbose {
		printResult("", url, o)
	}
}

func resolveCNAME(domain string) string {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeCNAME)
	resp, err := dns.Exchange(msg, dnsResolver)
	if err != nil {
		return ""
	}

	for _, a := range resp.Answer {
		if t, ok := a.(*dns.CNAME); ok {
			return t.Target
		}
	}

	return ""
}

func lookupNS(domain string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeNS)
	resp, err := dns.Exchange(msg, dnsResolver)
	if err != nil {
		return nil
	}

	var nameservers []string
	for _, a := range resp.Answer {
		if t, ok := a.(*dns.NS); ok {
			nameservers = append(nameservers, t.Ns)
		}
	}

	return nameservers
}

func isNXDOMAIN(host string) bool {
	_, err := net.LookupHost(host)
	if err != nil {
		return strings.Contains(err.Error(), "no such host")
	}
	return false
}

// CheckNS checks whether any of a domain's nameservers are available for purchase.
func CheckNS(domain, output string, verbose bool) {
	for _, ns := range lookupNS(domain) {
		if verbose {
			msg := fmt.Sprintf("[*] %s: Nameserver is %s\n", domain, ns)
			fmt.Print(msg)
			if output != "" {
				writeText(msg, output)
			}
		}

		if isNXDOMAIN(ns) && available.Domain(ns) {
			msg := fmt.Sprintf("[!] %s's nameserver: %s is available for purchase!\n", domain, ns)
			fmt.Print(msg)
			if output != "" {
				writeText(msg, output)
			}
		}
	}
}
