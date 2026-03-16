package subjack

import (
	"fmt"
	"strings"
	"time"

	"github.com/haccer/available"
	"github.com/miekg/dns"
)

const maxCNAMEDepth = 10

// checkCNAMEChain follows the full CNAME chain and checks if any intermediate
// or terminal target is an NXDOMAIN with a registrable domain.
func checkCNAMEChain(domain string, o *Options) {
	timeout := time.Duration(o.Timeout) * time.Second
	var chain []string
	current := domain

	for i := 0; i < maxCNAMEDepth; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(current), dns.TypeCNAME)
		resp, err := dnsExchange(msg, o.resolvers, timeout)
		if err != nil {
			break
		}

		var target string
		for _, a := range resp.Answer {
			if t, ok := a.(*dns.CNAME); ok {
				target = t.Target
				break
			}
		}
		if target == "" {
			break
		}

		target = strings.TrimSuffix(target, ".")
		chain = append(chain, target)
		current = target
	}

	// Need at least 2 links to be a chain (beyond what normal detection catches)
	if len(chain) < 2 {
		return
	}

	// Check each link in the chain for takeover opportunities
	for i, link := range chain {
		if i == 0 {
			// Skip first link — already caught by normal CNAME detection
			continue
		}

		if isNXDOMAIN(link, o) && available.Domain(link) {
			service := "CNAME CHAIN TAKEOVER"
			chainStr := domain + " -> " + strings.Join(chain[:i+1], " -> ")
			detail := fmt.Sprintf("%s - %s is available for registration (chain: %s)", domain, link, chainStr)
			fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
			if o.Output != "" {
				msg := fmt.Sprintf("[%s] %s\n", service, detail)
				writeOutput(service, domain, msg, o.Output)
			}
			return
		}
	}
}

// checkSRV looks up common SRV records and checks if any targets are
// expired or available for registration.
func checkSRV(domain string, o *Options) {
	srvPrefixes := []string{
		"_sip._tcp.",
		"_sip._udp.",
		"_sips._tcp.",
		"_xmpp-client._tcp.",
		"_xmpp-server._tcp.",
		"_jabber._tcp.",
		"_h323ls._udp.",
		"_h323cs._tcp.",
		"_imap._tcp.",
		"_imaps._tcp.",
		"_submission._tcp.",
		"_pop3._tcp.",
		"_pop3s._tcp.",
		"_caldav._tcp.",
		"_caldavs._tcp.",
		"_carddav._tcp.",
		"_carddavs._tcp.",
		"_ldap._tcp.",
		"_ldaps._tcp.",
		"_kerberos._tcp.",
		"_kerberos._udp.",
		"_kpasswd._tcp.",
		"_kpasswd._udp.",
		"_minecraft._tcp.",
		"_ts3._udp.",
		"_autodiscover._tcp.",
		"_mta-sts._tcp.",
	}

	timeout := time.Duration(o.Timeout) * time.Second

	for _, prefix := range srvPrefixes {
		qname := prefix + domain
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(qname), dns.TypeSRV)
		resp, err := dnsExchange(msg, o.resolvers, timeout)
		if err != nil {
			continue
		}

		for _, a := range resp.Answer {
			srv, ok := a.(*dns.SRV)
			if !ok {
				continue
			}
			target := strings.TrimSuffix(srv.Target, ".")
			if target == "" || target == "." {
				continue
			}

			if isNXDOMAIN(target, o) && available.Domain(target) {
				service := "SRV TAKEOVER"
				detail := fmt.Sprintf("%s - SRV %s points to %s which is available for registration", domain, prefix, target)
				fmt.Printf("[%s%s%s] %s\n", colorGreen, service, colorReset, detail)
				if o.Output != "" {
					msg := fmt.Sprintf("[%s] %s\n", service, detail)
					writeOutput(service, domain, msg, o.Output)
				}
			}
		}
	}
}
