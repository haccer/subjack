package subjack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// e2eFixture returns a DNS fixture with one vulnerable domain (dangling
// CNAME to an unregistered domain) and one healthy domain (CNAME to a live
// service).
func e2eFixture() *fakeDNS {
	return &fakeDNS{
		cname: map[string]string{
			"vuln.app.test.":  "gone.buyable.test",
			"known.app.test.": "site.github.io",
		},
		nxdomain: map[string]bool{"vuln.app.test.": true},
	}
}

func TestProcess_Wordlist_JSONOutput(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	wordlist := filepath.Join(t.TempDir(), "subs.txt")
	if err := os.WriteFile(wordlist, []byte("vuln.app.test\nknown.app.test\n"), 0600); err != nil {
		t.Fatal(err)
	}

	o := newTestOptions(t, addr)
	o.Wordlist = wordlist
	o.All = true // request every URL, as recommended
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	stdout := captureStdout(t, func() { Process(o) })

	if !strings.Contains(stdout, "DOMAIN AVAILABLE") {
		t.Errorf("stdout = %q, want a DOMAIN AVAILABLE line", stdout)
	}

	results := readOutputJSON(t, o.Output)
	if len(results) != 2 {
		t.Fatalf("got %d JSON results, want 2: %+v", len(results), results)
	}

	bySub := make(map[string]Result, len(results))
	for _, r := range results {
		bySub[r.Subdomain] = r
	}

	r := bySub["vuln.app.test"]
	if !r.Vulnerable || r.Service != "unregistered domain" || r.Domain != "gone.buyable.test" {
		t.Errorf("vuln.app.test result = %+v, want vulnerable unregistered domain gone.buyable.test", r)
	}

	r = bySub["known.app.test"]
	if r.Vulnerable {
		t.Errorf("known.app.test result = %+v, want not vulnerable", r)
	}
}

func TestProcess_Stdin(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("vuln.app.test\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	o := newTestOptions(t, addr)
	o.Stdin = true
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	Process(o)

	results := readOutputJSON(t, o.Output)
	if len(results) != 1 {
		t.Fatalf("got %d JSON results, want 1: %+v", len(results), results)
	}
	if !results[0].Vulnerable || results[0].Domain != "gone.buyable.test" {
		t.Errorf("result = %+v, want vulnerable with gone.buyable.test", results[0])
	}
}

func TestProcess_SingleDomain(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	o := newTestOptions(t, addr)
	o.Domain = "vuln.app.test"
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	Process(o)

	results := readOutputJSON(t, o.Output)
	if len(results) != 1 || !results[0].Vulnerable {
		t.Fatalf("results = %+v, want one vulnerable entry", results)
	}
}

func TestProcess_ResolversFile(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	resolvers := filepath.Join(t.TempDir(), "resolvers.txt")
	if err := os.WriteFile(resolvers, []byte(addr+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	o := newTestOptions(t, "127.0.0.1:1") // unused; overridden by -r
	o.ResolverList = resolvers
	o.Domain = "vuln.app.test"
	o.All = true
	o.Output = filepath.Join(t.TempDir(), "results.json")
	setAvailable(o, "gone.buyable.test")

	Process(o)

	results := readOutputJSON(t, o.Output)
	if len(results) != 1 || !results[0].Vulnerable {
		t.Fatalf("results = %+v, want the resolver list to drive detection", results)
	}
}

func TestProcess_DefaultThreadGuard(t *testing.T) {
	addr := startTestDNSServer(t, e2eFixture().handler())

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("known.app.test\n")
	w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	o := newTestOptions(t, addr)
	o.Threads = 0 // must be defaulted, not deadlock
	o.Timeout = 0
	o.Stdin = true

	done := make(chan struct{})
	go func() {
		Process(o)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Process deadlocked with Threads=0")
	}
}
