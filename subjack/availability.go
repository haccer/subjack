package subjack

import (
	"strings"
	"time"

	"github.com/haccer/available"
)

// domainAvailable reports whether the registrable domain under name is
// unregistered. Options carries an override used by tests.
func (o *Options) domainAvailable(name string) bool {
	if o.checkAvailable != nil {
		return o.checkAvailable(name)
	}
	return defaultDomainAvailable(name, time.Duration(o.Timeout)*time.Second)
}

// defaultDomainAvailable delegates to the available package, which asks
// the TLD's authoritative whois server.
func defaultDomainAvailable(name string, timeout time.Duration) bool {
	return available.DomainTimeout(name, timeout)
}

// normalizeDomain strips a URL scheme and trailing dot and lowercases.
func normalizeDomain(domain string) string {
	if i := strings.Index(domain, "://"); i != -1 {
		domain = domain[i+3:]
	}
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}
