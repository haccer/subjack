package subjack

import (
	"fmt"
	"strings"
	"time"

	"github.com/haccer/available"
	"github.com/miekg/dns"
)

// checkSPF parses SPF TXT records for include: domains and checks if any
// are expired or available for registration.
func checkSPF(domain string, o *Options) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	resp, err := dnsExchange(msg, o.resolvers, time.Duration(o.Timeout)*time.Second)
	if err != nil {
		return
	}

	for _, a := range resp.Answer {
		txt, ok := a.(*dns.TXT)
		if !ok {
			continue
		}
		record := strings.Join(txt.Txt, "")
		if !strings.HasPrefix(record, "v=spf1") {
			continue
		}

		for _, part := range strings.Fields(record) {
			if !strings.HasPrefix(part, "include:") {
				continue
			}
			includeDomain := strings.TrimPrefix(part, "include:")
			if includeDomain == "" {
				continue
			}

			if isNXDOMAIN(includeDomain, o) && available.Domain(includeDomain) {
				service := "SPF TAKEOVER"
				detail := fmt.Sprintf("%s - SPF include:%s is available for registration", domain, includeDomain)
				fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
				if o.Output != "" {
					msg := fmt.Sprintf("[%s] %s\n", service, detail)
					writeOutput(service, domain, msg, o.Output)
				}
			}
		}
	}
}

// checkMX checks if any MX record targets are expired or available for registration.
func checkMX(domain string, o *Options) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	resp, err := dnsExchange(msg, o.resolvers, time.Duration(o.Timeout)*time.Second)
	if err != nil {
		return
	}

	for _, a := range resp.Answer {
		mx, ok := a.(*dns.MX)
		if !ok {
			continue
		}
		mxHost := strings.TrimSuffix(mx.Mx, ".")
		if mxHost == "" {
			continue
		}

		if isNXDOMAIN(mxHost, o) && available.Domain(mxHost) {
			service := "MX TAKEOVER"
			detail := fmt.Sprintf("%s - mail server %s is available for registration", domain, mxHost)
			fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
			if o.Output != "" {
				msg := fmt.Sprintf("[%s] %s\n", service, detail)
				writeOutput(service, domain, msg, o.Output)
			}
		}
	}
}
