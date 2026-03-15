package subjack

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"

	"github.com/haccer/available"
	"github.com/miekg/dns"
)

const defaultResolver = "8.8.8.8:53"

func pickResolver(resolvers []string) string {
	if len(resolvers) == 0 {
		return defaultResolver
	}
	return resolvers[rand.IntN(len(resolvers))] + ":53"
}

func dnsExchange(msg *dns.Msg, resolvers []string) (*dns.Msg, error) {
	resolver := pickResolver(resolvers)
	resp, err := dns.Exchange(msg, resolver)
	if err != nil && resolver != defaultResolver {
		resp, err = dns.Exchange(msg, defaultResolver)
	}
	return resp, err
}

func check(url string, o *Options) {
	if o.All {
		detect(url, o)
		return
	}

	if verifyCNAME(url, o) {
		detect(url, o)
		return
	}

	if o.Verbose {
		printResult("", url, o)
	}
}

func resolveCNAME(domain string, resolvers []string) string {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeCNAME)
	resp, err := dnsExchange(msg, resolvers)
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

func lookupNS(domain string, resolvers []string) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeNS)
	resp, err := dnsExchange(msg, resolvers)
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
func CheckNS(domain, output string, verbose bool, resolvers []string) {
	for _, ns := range lookupNS(domain, resolvers) {
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
