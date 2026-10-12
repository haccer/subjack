package subjack

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDNSServer runs a DNS server on a loopback ephemeral port serving
// both UDP and TCP with the same handler, and shuts it down on test cleanup.
// It returns the server address ("127.0.0.1:port").
func startTestDNSServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port

	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		l.Close()
		t.Fatalf("udp listen: %v", err)
	}

	tcpReady := make(chan struct{}, 1)
	udpReady := make(chan struct{}, 1)
	tcpServer := &dns.Server{Listener: l, Handler: handler, NotifyStartedFunc: func() { tcpReady <- struct{}{} }}
	udpServer := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { udpReady <- struct{}{} }}

	go tcpServer.ActivateAndServe()
	go udpServer.ActivateAndServe()

	t.Cleanup(func() {
		tcpServer.Shutdown()
		udpServer.Shutdown()
	})

	select {
	case <-tcpReady:
	case <-time.After(5 * time.Second):
		t.Fatal("tcp DNS server did not start")
	}
	select {
	case <-udpReady:
	case <-time.After(5 * time.Second):
		t.Fatal("udp DNS server did not start")
	}

	return pc.LocalAddr().String()
}

// fakeDNS is a map-driven DNS handler fixture.
type fakeDNS struct {
	cname    map[string]string   // qname -> CNAME target
	a        map[string][]string // qname -> A record IPs
	nxdomain map[string]bool     // qname -> NXDOMAIN (applies to A queries)
	ns       map[string][]string // qname -> nameservers
	txt      map[string][]string // qname -> TXT strings
	mx       map[string][]string // qname -> MX targets
	srv      map[string][]string // qname -> SRV targets
	soaRcode map[string]int      // qname -> rcode for direct SOA probes
	axfrRRs  []dns.RR            // records served for AXFR requests
	onQuery  func(q dns.Question)
}

func (f *fakeDNS) handler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if f.onQuery != nil {
			f.onQuery(q)
		}

		if q.Qtype == dns.TypeAXFR {
			ch := make(chan *dns.Envelope)
			tr := new(dns.Transfer)
			go func() {
				ch <- &dns.Envelope{RR: f.axfrRRs}
				close(ch)
			}()
			tr.Out(w, r, ch)
			w.Close()
			return
		}

		// NXDOMAIN is name-scoped to A queries so tests can pair it with a
		// CNAME on the same name, mirroring a dangling CNAME in the wild.
		if q.Qtype == dns.TypeA && f.nxdomain[name] {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}

		m := new(dns.Msg)
		m.SetReply(r)

		switch q.Qtype {
		case dns.TypeCNAME:
			if target, ok := f.cname[name]; ok {
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    rrHdr(name, dns.TypeCNAME),
					Target: dns.Fqdn(target),
				})
			}
		case dns.TypeA:
			for _, ip := range f.a[name] {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: rrHdr(name, dns.TypeA),
					A:   net.ParseIP(ip),
				})
			}
		case dns.TypeNS:
			for _, ns := range f.ns[name] {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: rrHdr(name, dns.TypeNS),
					Ns:  dns.Fqdn(ns),
				})
			}
		case dns.TypeTXT:
			for _, txt := range f.txt[name] {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: rrHdr(name, dns.TypeTXT),
					Txt: []string{txt},
				})
			}
		case dns.TypeMX:
			for i, mx := range f.mx[name] {
				m.Answer = append(m.Answer, &dns.MX{
					Hdr:        rrHdr(name, dns.TypeMX),
					Preference: uint16(10 + i),
					Mx:         dns.Fqdn(mx),
				})
			}
		case dns.TypeSRV:
			for _, target := range f.srv[name] {
				m.Answer = append(m.Answer, &dns.SRV{
					Hdr:      rrHdr(name, dns.TypeSRV),
					Priority: 10,
					Weight:   5,
					Port:     443,
					Target:   dns.Fqdn(target),
				})
			}
		case dns.TypeSOA:
			if rcode, ok := f.soaRcode[name]; ok {
				m.Rcode = rcode
			}
		}

		w.WriteMsg(m)
	}
}

func rrHdr(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: rrtype, Class: dns.ClassINET, Ttl: 60}
}

// newTestOptions returns Options wired for hermetic tests: a fast timeout,
// the embedded fingerprints, and output to a temp file.
func newTestOptions(t *testing.T, dnsAddr string) *Options {
	t.Helper()

	o := &Options{
		Threads:      5,
		Timeout:      2,
		Verbose:      true,
		resolvers:    []string{dnsAddr},
		fingerprints: loadFingerprints(),
		sem:          make(chan struct{}, 5),
	}
	o.Output = filepath.Join(t.TempDir(), "out.txt")
	return o
}

// setAvailable installs a deterministic availability fake keyed on exact
// domain names (case- and dot-insensitive).
func setAvailable(o *Options, names ...string) {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[normalizeDomain(n)] = true
	}
	o.checkAvailable = func(domain string) bool {
		return set[normalizeDomain(domain)]
	}
}

func readOutput(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("reading output file: %v", err)
	}
	return string(data)
}

func readOutputJSON(t *testing.T, path string) []Result {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	var results []Result
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return results
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns
// whatever was printed, with ANSI color escapes stripped.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return ansiRe.ReplaceAllString(string(data), "")
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// overrideVar temporarily sets *ptr to value and restores it on cleanup.
func overrideVar[T any](t *testing.T, ptr *T, value T) {
	t.Helper()

	old := *ptr
	*ptr = value
	t.Cleanup(func() { *ptr = old })
}
