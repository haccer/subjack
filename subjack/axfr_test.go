package subjack

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func TestGetBaseDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"a.b.c.d.example.com", "example.com"},
		{"com", "com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := getBaseDomain(tt.domain)
		if got != tt.expected {
			t.Errorf("getBaseDomain(%q) = %q, want %q", tt.domain, got, tt.expected)
		}
	}
}

func TestTryAXFR_Success(t *testing.T) {
	rrs := []dns.RR{
		mustRR(t, "app.test. 60 IN SOA localhost. hostmaster.app.test. 1 3600 600 86400 60"),
		mustRR(t, "app.test. 60 IN A 127.0.0.1"),
		mustRR(t, "www.app.test. 60 IN A 127.0.0.2"),
	}
	addr := startTestDNSServer(t, (&fakeDNS{axfrRRs: rrs}).handler())
	o := newTestOptions(t, addr)

	if !tryAXFR("app.test", addr, 2*time.Second, o) {
		t.Fatal("tryAXFR = false, want true")
	}

	written := readOutput(t, o.Output)
	if !strings.Contains(written, "ZONE TRANSFER") {
		t.Errorf("output = %q, want ZONE TRANSFER", written)
	}
	if !strings.Contains(written, "(3 records)") {
		t.Errorf("output = %q, want record count 3", written)
	}
}

func TestTryAXFR_NoRecords(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	if tryAXFR("app.test", addr, 2*time.Second, o) {
		t.Error("tryAXFR = true, want false for an empty transfer")
	}
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty", written)
	}
}

func TestTryAXFR_Refused(t *testing.T) {
	addr := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
	}))
	o := newTestOptions(t, addr)

	if tryAXFR("app.test", addr, 2*time.Second, o) {
		t.Error("tryAXFR = true, want false for REFUSED")
	}
}

func TestTryAXFR_Unreachable(t *testing.T) {
	o := newTestOptions(t, "127.0.0.1:1")

	if tryAXFR("app.test", "127.0.0.1:1", 1*time.Second, o) {
		t.Error("tryAXFR = true, want false for an unreachable server")
	}
}

// TestCheckAXFR_ViaNameservers exercises the full checkAXFR flow: NS lookup
// through the test resolver, then an AXFR against that nameserver with the
// authoritative port overridden to the fixture.
func TestCheckAXFR_ViaNameservers(t *testing.T) {
	rrs := []dns.RR{
		mustRR(t, "app.test. 60 IN SOA localhost. hostmaster.app.test. 1 3600 600 86400 60"),
		mustRR(t, "app.test. 60 IN A 127.0.0.1"),
	}
	addr := startTestDNSServer(t, (&fakeDNS{
		ns:      map[string][]string{"app.test.": {"localhost"}},
		axfrRRs: rrs,
	}).handler())

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	overrideVar(t, &dnsPort, port)

	o := newTestOptions(t, addr)
	checkAXFR("app.test", o)

	written := readOutput(t, o.Output)
	if !strings.Contains(written, "ZONE TRANSFER") {
		t.Errorf("output = %q, want ZONE TRANSFER via the domain's nameserver", written)
	}
}
