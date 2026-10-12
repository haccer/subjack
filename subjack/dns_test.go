package subjack

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPickResolver(t *testing.T) {
	tests := []struct {
		resolvers []string
		expected  string
	}{
		{nil, defaultResolver},
		{[]string{}, defaultResolver},
		{[]string{"1.1.1.1"}, "1.1.1.1:53"},
		{[]string{"8.8.8.8", "1.1.1.1"}, "1.1.1.1:53"}, // random pick from 1-element set of both forms
		{[]string{"127.0.0.1:5353"}, "127.0.0.1:5353"},
		{[]string{"[::1]:5353"}, "[::1]:5353"},
		{[]string{"2001:4860:4860::8888"}, "[2001:4860:4860::8888]:53"},
	}

	for _, tt := range tests {
		// A random pick from several resolvers is not deterministic, so
		// only assert on lists where every entry yields the same result.
		if len(tt.resolvers) > 1 {
			continue
		}
		if got := pickResolver(tt.resolvers); got != tt.expected {
			t.Errorf("pickResolver(%v) = %q, want %q", tt.resolvers, got, tt.expected)
		}
	}

	// With several resolvers the pick must be one of them.
	many := []string{"1.1.1.1", "8.8.4.4", "9.9.9.9"}
	for i := 0; i < 20; i++ {
		got := pickResolver(many)
		ok := false
		for _, r := range many {
			if got == r+":53" {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("pickResolver(%v) = %q, not a member", many, got)
		}
	}
}

func TestDNSExchangeFallsBackToDefaultResolver(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		a: map[string][]string{"fallback.test.": {"127.0.0.1"}},
	}).handler())
	overrideVar(t, &defaultResolver, addr)

	// Nothing listens on 127.0.0.1:1, so the first exchange must fail and
	// the fallback to defaultResolver must succeed.
	msg := new(dns.Msg)
	msg.SetQuestion("fallback.test.", dns.TypeA)
	resp, err := dnsExchange(msg, []string{"127.0.0.1:1"}, 2*time.Second)
	if err != nil {
		t.Fatalf("dnsExchange fallback failed: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("fallback response rcode = %v, want NOERROR", resp)
	}
}

func TestResolveCNAME(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{"alias.test.": "target.test"},
	}).handler())
	o := newTestOptions(t, addr)

	if got := resolveCNAME("alias.test", o); got != "target.test." {
		t.Errorf("resolveCNAME(alias.test) = %q, want %q", got, "target.test.")
	}
	if got := resolveCNAME("unknown.test", o); got != "" {
		t.Errorf("resolveCNAME(unknown.test) = %q, want empty", got)
	}
}

func TestLookupNS(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		ns: map[string][]string{"app.test.": {"ns1.example.com", "ns2.example.com"}},
	}).handler())
	o := newTestOptions(t, addr)

	got := lookupNS("app.test", o)
	if len(got) != 2 {
		t.Fatalf("lookupNS returned %v, want 2 nameservers", got)
	}
	if got[0] != "ns1.example.com." || got[1] != "ns2.example.com." {
		t.Errorf("lookupNS = %v, want [ns1.example.com. ns2.example.com.]", got)
	}

	if got := lookupNS("unknown.test", o); got != nil {
		t.Errorf("lookupNS(unknown.test) = %v, want nil", got)
	}
}

func TestIsNXDOMAIN(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		nxdomain: map[string]bool{"dead.test.": true},
	}).handler())
	o := newTestOptions(t, addr)

	if !isNXDOMAIN("dead.test", o) {
		t.Error("isNXDOMAIN(dead.test) = false, want true")
	}
	if isNXDOMAIN("alive.test", o) {
		t.Error("isNXDOMAIN(alive.test) = true, want false")
	}
}

// TestVerifyCNAMEEmptyPattern guards the regression behind issue #102: the
// worksites.net fingerprint has an empty CNAME pattern, and
// strings.Contains(x, "") is always true, so without the empty-pattern skip
// every domain was treated as having an identified CNAME and funneled into
// the slow detect() path.
func TestVerifyCNAMEEmptyPattern(t *testing.T) {
	fingerprints := loadFingerprints()

	if !matchesCNAME("site.github.io", fingerprints) {
		t.Error("matchesCNAME(site.github.io) = false, want true")
	}
	if matchesCNAME("unrelated.example.org", fingerprints) {
		t.Error("matchesCNAME(unrelated) = true, want false")
	}
	if matchesCNAME("", fingerprints) {
		t.Error(`matchesCNAME("") = true, want false (empty pattern regression)`)
	}
}

func TestVerifyCNAME(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{
			"pages.test.":  "site.github.io",
			"plain.test.":  "something.example.org",
			"empty.test.":  "",
			"works1.test.": "customer.worksites.net",
		},
	}).handler())
	o := newTestOptions(t, addr)

	if !verifyCNAME("pages.test", o) {
		t.Error("verifyCNAME(pages.test) = false, want true")
	}
	if verifyCNAME("plain.test", o) {
		t.Error("verifyCNAME(plain.test) = true, want false")
	}
	// A domain with no CNAME at all must not match anything.
	if verifyCNAME("nocname.test", o) {
		t.Error("verifyCNAME(nocname.test) = true, want false")
	}
	// worksites.net has only an empty CNAME pattern: body-only service.
	if verifyCNAME("works1.test", o) {
		t.Error("verifyCNAME(works1.test) = true, want false (body-only service)")
	}
}

// TestCheckSkipsSRVWhenDisabled guards the SRV gating from issue #102:
// checkSRV issues ~28 DNS queries per domain and must only run with -srv.
func TestCheckSkipsSRVWhenDisabled(t *testing.T) {
	var srvQueries atomic.Int32
	fx := &fakeDNS{onQuery: func(q dns.Question) {
		if q.Qtype == dns.TypeSRV {
			srvQueries.Add(1)
		}
	}}
	addr := startTestDNSServer(t, fx.handler())
	o := newTestOptions(t, addr)

	check("plain.test", o)
	if n := srvQueries.Load(); n != 0 {
		t.Errorf("check() sent %d SRV queries with -srv off, want 0", n)
	}

	o.CheckSRV = true
	check("plain.test", o)
	if n := srvQueries.Load(); n == 0 {
		t.Error("check() sent no SRV queries with -srv on")
	}
}

func TestCheckVerbosePrintsNotVulnerable(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	out := captureStdout(t, func() { check("plain.test", o) })
	if !strings.Contains(out, "[Not Vulnerable] plain.test") {
		t.Errorf("verbose output = %q, want it to contain \"[Not Vulnerable] plain.test\"", out)
	}
	if written := readOutput(t, o.Output); !strings.Contains(written, "[Not Vulnerable] plain.test") {
		t.Errorf("output file = %q, want it to contain the not-vulnerable line", written)
	}
}

func TestCheckNS_Takeover(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		ns: map[string][]string{
			"hijacked.test.": {"ns1.dead-nameserver.test"},
			"healthy.test.":  {"ns1.alive-nameserver.test"},
		},
		nxdomain: map[string]bool{
			"ns1.dead-nameserver.test.": true,
		},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "ns1.dead-nameserver.test")

	checkNS("hijacked.test", o)
	written := readOutput(t, o.Output)
	if !strings.Contains(written, "[NS TAKEOVER] hijacked.test - nameserver ns1.dead-nameserver.test is available for purchase!") {
		t.Errorf("output = %q, want NS TAKEOVER line for hijacked.test", written)
	}

	checkNS("healthy.test", o)
	if written := readOutput(t, o.Output); strings.Contains(written, "healthy.test") {
		t.Errorf("output = %q, healthy domain must not be flagged", written)
	}
}

func TestCheckNS_RegisteredNameserverNotFlagged(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		ns:       map[string][]string{"app.test.": {"ns1.dead-but-registered.test"}},
		nxdomain: map[string]bool{"ns1.dead-but-registered.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o) // nothing available

	checkNS("app.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty for NXDOMAIN but registered nameserver", written)
	}
}
