package subjack

import (
	"fmt"
	"net"
	"strings"
	"math/rand"

	"github.com/haccer/available"
	"github.com/miekg/dns"
)

func (s *Subdomain) dns(o *Options, resolvers []string) {
	config := o.Fingerprints

	if o.All {
		detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Manual, o.Timeout, resolvers, config)
	} else {
		if VerifyCNAME(s.Url, config, resolvers) {
			detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Manual, o.Timeout, resolvers, config)
		}

		if o.Verbose {
			result := fmt.Sprintf("[Not Vulnerable] %s\n", s.Url)
			c := "\u001b[31;1mNot Vulnerable\u001b[0m"
			out := strings.Replace(result, "Not Vulnerable", c, -1)
			fmt.Printf(out)

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

func resolve(url string, resolvers []string) (cname string) {
	cname = ""
	d := new(dns.Msg)
	d.SetQuestion(url+".", dns.TypeCNAME)

	default_resolver := "8.8.8.8:53"
	resolver := default_resolver
	if (len(resolvers) > 0) {
		resolver = fmt.Sprintf("%s:53", resolvers[rand.Intn(len(resolvers))])
	}

	ret, err := dns.Exchange(d, resolver)
	if err != nil && resolver != default_resolver {
		// retry again with the default resolver
		ret, err = dns.Exchange(d, default_resolver)
		if  err != nil {
			return
		}
	}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.CNAME); ok {
			cname = t.Target
		}
	}

	return cname
}

func nslookup(domain string, resolvers []string) (nameservers []string) {
	m := new(dns.Msg)
	m.SetQuestion(dotDomain(domain), dns.TypeNS)

	default_resolver := "8.8.8.8:53"
	resolver := default_resolver
	if (len(resolvers) > 0) {
		resolver = fmt.Sprintf("%s:53", resolvers[rand.Intn(len(resolvers))])
	}

	ret, err := dns.Exchange(m, resolver)
	if err != nil && resolver != default_resolver {
		// retry again with the default resolver
		ret, err = dns.Exchange(m, default_resolver)
		if  err != nil {
			return
		}
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

func NS(domain, output string, verbose bool, resolvers []string) {
	nameservers := nslookup(domain, resolvers)
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
