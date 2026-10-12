package subjack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadFingerprints(t *testing.T) {
	fps := loadFingerprints()
	if len(fps) == 0 {
		t.Fatal("loadFingerprints returned empty slice")
	}

	// Verify structure
	for _, fp := range fps {
		if fp.Service == "" {
			t.Error("fingerprint has empty service name")
		}
	}
}

func TestFingerprintsJSON(t *testing.T) {
	var fps []Fingerprint
	if err := json.Unmarshal(fingerprintsJSON, &fps); err != nil {
		t.Fatalf("fingerprints.json is invalid JSON: %v", err)
	}

	services := make(map[string]bool)
	for _, fp := range fps {
		if fp.Service == "" {
			t.Error("fingerprint has empty service name")
		}
		if services[fp.Service] {
			t.Errorf("duplicate service name: %s", fp.Service)
		}
		services[fp.Service] = true

		if !fp.Nxdomain && len(fp.Fingerprint) == 0 {
			// Non-nxdomain services should have fingerprints (except worksites with empty cname)
			hasCname := false
			for _, c := range fp.Cname {
				if c != "" {
					hasCname = true
					break
				}
			}
			if hasCname {
				t.Errorf("service %s has no fingerprints and nxdomain=false", fp.Service)
			}
		}
	}
}

func TestReadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte("one.test\ntwo.test\n\nthree.test\n"), 0600); err != nil {
		t.Fatal(err)
	}

	lines, err := readLines(path)
	if err != nil {
		t.Fatalf("readLines: %v", err)
	}
	want := []string{"one.test", "two.test", "", "three.test"}
	if len(lines) != len(want) {
		t.Fatalf("readLines returned %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("readLines[%d] = %q, want %q", i, lines[i], want[i])
		}
	}

	if _, err := readLines(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("readLines(missing) succeeded, want error")
	}
}

func TestInitOutput(t *testing.T) {
	jsonPath := filepath.Join(t.TempDir(), "results.json")
	initOutput(jsonPath)
	if got := readOutput(t, jsonPath); got != "[]" {
		t.Errorf("initOutput(json) = %q, want \"[]\"", got)
	}

	txtPath := filepath.Join(t.TempDir(), "results.txt")
	initOutput(txtPath)
	if got := readOutput(t, txtPath); got != "" {
		t.Errorf("initOutput(txt) = %q, want empty", got)
	}
}

func TestWriteOutput_Text(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.txt")
	initOutput(path)

	writeOutput("S3 BUCKET", "cdn.app.test", "[S3 BUCKET] cdn.app.test\n", path)
	writeOutput("", "plain.app.test", "[Not Vulnerable] plain.app.test\n", path)

	want := "[S3 BUCKET] cdn.app.test\n[Not Vulnerable] plain.app.test\n"
	if got := readOutput(t, path); got != want {
		t.Errorf("text output = %q, want %q", got, want)
	}
}

func TestWriteOutput_JSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	initOutput(path)

	writeOutput("DOMAIN AVAILABLE - gone.example.com", "vuln.app.test", "", path)
	writeOutput("DEAD DOMAIN - dead.example.com", "manual.app.test", "", path)
	writeOutput("S3 BUCKET", "cdn.app.test", "", path)
	writeOutput("", "plain.app.test", "", path)

	results := readOutputJSON(t, path)
	if len(results) != 4 {
		t.Fatalf("got %d JSON results, want 4", len(results))
	}

	bySub := make(map[string]Result, len(results))
	for _, r := range results {
		bySub[r.Subdomain] = r
	}

	r := bySub["vuln.app.test"]
	if !r.Vulnerable || r.Service != "unregistered domain" || r.Domain != "gone.example.com" {
		t.Errorf("domain-available result = %+v, want vulnerable unregistered domain gone.example.com", r)
	}

	r = bySub["manual.app.test"]
	if !r.Vulnerable || r.Service != "dead domain - dead.example.com" || r.Domain != "" {
		t.Errorf("dead-domain result = %+v, want flagged with the dead cname in Service", r)
	}

	r = bySub["cdn.app.test"]
	if !r.Vulnerable || r.Service != "s3 bucket" || r.Domain != "" {
		t.Errorf("service result = %+v, want vulnerable s3 bucket", r)
	}

	r = bySub["plain.app.test"]
	if r.Vulnerable || r.Service != "" || r.Domain != "" {
		t.Errorf("not-vulnerable result = %+v, want vulnerable=false with no service", r)
	}
}

func TestWriteOutput_JSONConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	initOutput(path)

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			writeOutput("", fmt.Sprintf("domain-%d.test", i), "", path)
		}(i)
	}
	wg.Wait()

	results := readOutputJSON(t, path)
	if len(results) != n {
		t.Fatalf("got %d JSON results, want %d (lost writes?)", len(results), n)
	}
	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.Subdomain] = true
	}
	for i := 0; i < n; i++ {
		if !seen[fmt.Sprintf("domain-%d.test", i)] {
			t.Errorf("domain-%d.test missing from JSON output", i)
		}
	}
}

func TestPrintResult(t *testing.T) {
	out := captureStdout(t, func() {
		o := &Options{Verbose: true}
		printResult("GITHUB", "pages.app.test", o)
		printResult("", "plain.app.test", o)
	})

	if !strings.Contains(out, "[GITHUB] pages.app.test") {
		t.Errorf("stdout = %q, want a GITHUB result line", out)
	}
	if !strings.Contains(out, "[Not Vulnerable] plain.app.test") {
		t.Errorf("stdout = %q, want a not-vulnerable line in verbose mode", out)
	}

	// Without verbose, not-vulnerable lines are not printed.
	out = captureStdout(t, func() {
		o := &Options{Verbose: false}
		printResult("", "plain.app.test", o)
	})
	if strings.Contains(out, "plain.app.test") {
		t.Errorf("stdout = %q, want no not-vulnerable output without -v", out)
	}
}
