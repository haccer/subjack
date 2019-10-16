package subjack

import (
	"fmt"
	"net"
	"strings"

	"github.com/haccer/available"
	"github.com/miekg/dns"
)

func (s *Subdomain) dns(o *Options) {
	config := fingerprints(o.Config)

	if o.All {
		detect(s.Url, o.Output, o.NoColor, o.Ssl, o.Verbose, o.Manual, o.Timeout, config)
	} else {
		if VerifyCNAME(s.Url, config) {
			detect(s.Url, o.Output, o.NoColor, o.Ssl, o.Verbose, o.Manual, o.Timeout, config)
		}

		if o.Verbose {
			result := fmt.Sprintf("[Not Vulnerable] %s\n", s.Url)
			if o.NoColor {
				fmt.Printf(result)
			} else {
				c := "\u001b[31;1mNot Vulnerable\u001b[0m"
				out := strings.Replace(result, "Not Vulnerable", c, -1)
				fmt.Printf(out)
			}

			if o.Output != "" {
				if chkJSON(o.Output) {
					writeJSON("", s.Url, o.Output)
				} else {
					write(result, o.Output)
				}
			}
		}
	}
}

func resolve(url string) (cname string) {
	cname = ""
	d := new(dns.Msg)
	d.SetQuestion(url+".", dns.TypeCNAME)
	ret, err := dns.Exchange(d, "8.8.8.8:53")
	if err != nil {
		return
	}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.CNAME); ok {
			cname = t.Target
		}
	}

	return cname
}

func nslookup(domain string) (nameservers []string) {
	m := new(dns.Msg)
	m.SetQuestion(dotDomain(domain), dns.TypeNS)
	ret, err := dns.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return
	}

	nameservers = []string{}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.NS); ok {
			nameservers = append(nameservers, t.Ns)
		}
	}

	return nameservers
}

func nxdomain(nameserver string) bool {
	if _, err := net.LookupHost(nameserver); err != nil {
		if strings.Contains(fmt.Sprintln(err), "no such host") {
			return true
		}
	}

	return false
}

func NS(domain, output string, verbose bool) {
	nameservers := nslookup(domain)
	for _, ns := range nameservers {
		if verbose {
			msg := fmt.Sprintf("[*] %s: Nameserver is %s\n", domain, ns)
			fmt.Printf(msg)

			if output != "" {
				write(msg, output)
			}
		}

		if nxdomain(ns) {
			av := available.Domain(ns)

			if av {
				msg := fmt.Sprintf("[!] %s's nameserver: %s is available for purchase!\n", domain, ns)
				fmt.Printf(msg)
				if output != "" {
					write(msg, output)
				}
			}
		}
	}
}
