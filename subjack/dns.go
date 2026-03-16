package subjack

import (
	"fmt"
	"math/rand/v2"
	"time"

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

func dnsExchange(msg *dns.Msg, resolvers []string, timeout time.Duration) (*dns.Msg, error) {
	client := &dns.Client{Timeout: timeout}
	resolver := pickResolver(resolvers)
	resp, _, err := client.Exchange(msg, resolver)
	if err != nil && resolver != defaultResolver {
		resp, _, err = client.Exchange(msg, defaultResolver)
	}
	return resp, err
}

func check(url string, o *Options) {
	o.sem <- struct{}{}
	defer func() { <-o.sem }()

	if o.CheckNS {
		checkNS(url, o)
		checkDanglingNS(url, o)
	}

	if o.CheckAR {
		checkARecord(url, o)
	}

	if o.CheckAXFR {
		checkAXFR(url, o)
	}

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

func resolveCNAME(domain string, o *Options) string {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeCNAME)
	resp, err := dnsExchange(msg, o.resolvers, time.Duration(o.Timeout)*time.Second)
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

func lookupNS(domain string, o *Options) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(domain+".", dns.TypeNS)
	resp, err := dnsExchange(msg, o.resolvers, time.Duration(o.Timeout)*time.Second)
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

func isNXDOMAIN(host string, o *Options) bool {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	resp, err := dnsExchange(msg, o.resolvers, time.Duration(o.Timeout)*time.Second)
	if err != nil {
		return false
	}
	return resp.Rcode == dns.RcodeNameError
}

func checkNS(domain string, o *Options) {
	for _, ns := range lookupNS(domain, o) {
		if isNXDOMAIN(ns, o) && available.Domain(ns) {
			service := "NS TAKEOVER"
			msg := fmt.Sprintf("[%s] %s - nameserver %s is available for purchase!", service, domain, ns)
			fmt.Printf("[%s%s%s] %s - nameserver %s is available for purchase!\n", colorGreen, service, colorReset, domain, ns)
			if o.Output != "" {
				writeOutput(service, domain, msg+"\n", o.Output)
			}
		}
	}
}
