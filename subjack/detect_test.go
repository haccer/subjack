package subjack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentify_DomainAvailable(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{"vuln.test.": "gone.buyable.test"},
		// The subdomain itself resolves to NXDOMAIN via its dangling CNAME.
		nxdomain: map[string]bool{"vuln.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "gone.buyable.test")

	got := identify("vuln.test", o)
	if got != "DOMAIN AVAILABLE - gone.buyable.test" {
		t.Errorf("identify(vuln.test) = %q, want %q", got, "DOMAIN AVAILABLE - gone.buyable.test")
	}
}

func TestIdentify_NXDOMAINButRegistered(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname:    map[string]string{"app.test.": "dead.registered.test"},
		nxdomain: map[string]bool{"app.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o) // dead but registered

	if got := identify("app.test", o); got != "" {
		t.Errorf("identify(app.test) = %q, want empty for registered target", got)
	}
}

func TestIdentify_ManualDeadDomain(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname:    map[string]string{"app.test.": "dead.plainhost.test"},
		nxdomain: map[string]bool{"app.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	o.Manual = true
	setAvailable(o)

	got := identify("app.test", o)
	if got != "DEAD DOMAIN - dead.plainhost.test" {
		t.Errorf("identify(app.test) = %q, want %q", got, "DEAD DOMAIN - dead.plainhost.test")
	}
}

func TestIdentify_NXDOMAINFingerprint(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{
			"app.test.":   "mydb.dead.blob.core.windows.net",
			"live.test.":  "mydb.blob.core.windows.net",
			"taken.test.": "busy.trafficmanager.net",
		},
		nxdomain: map[string]bool{"app.test.": true},
	}).handler())
	o := newTestOptions(t, addr)

	if got := identify("app.test", o); got != "AZURE-BLOB" {
		t.Errorf("identify(app.test) = %q, want AZURE-BLOB", got)
	}

	// Non-NXDOMAIN azure domains are not flagged by the nxdomain rules.
	if got := identify("live.test", o); got != "" {
		t.Errorf("identify(live.test) = %q, want empty (not NXDOMAIN)", got)
	}
}

func TestIdentify_FingerprintBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	t.Cleanup(srv.Close)

	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	// The httptest address is used directly as the scanned "subdomain":
	// DNS says NOERROR with no CNAME, so identify falls through to the
	// HTTP body fingerprint.
	if got := identify(srv.Listener.Addr().String(), o); got != "GITHUB" {
		t.Errorf("identify(http fixture) = %q, want GITHUB", got)
	}
}

func TestIdentify_FingerprintBodyNoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("just a normal page"))
	}))
	t.Cleanup(srv.Close)

	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	if got := identify(srv.Listener.Addr().String(), o); got != "" {
		t.Errorf("identify(http fixture) = %q, want empty", got)
	}
}

func TestIdentify_AzureTrafficManagerVerified(t *testing.T) {
	azure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nameAvailable": true, "reason": ""}`))
	}))
	t.Cleanup(azure.Close)
	overrideVar(t, &azureCheckURL, azure.URL)

	addr := startTestDNSServer(t, (&fakeDNS{
		cname:    map[string]string{"app.test.": "freename.trafficmanager.net"},
		nxdomain: map[string]bool{"app.test.": true},
	}).handler())
	o := newTestOptions(t, addr)

	if got := identify("app.test", o); got != "AZURE-TRAFFICMANAGER" {
		t.Errorf("identify(app.test) = %q, want AZURE-TRAFFICMANAGER", got)
	}
}

func TestIdentify_AzureTrafficManagerFalsePositiveFiltered(t *testing.T) {
	azure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nameAvailable": false, "reason": "AlreadyExists"}`))
	}))
	t.Cleanup(azure.Close)
	overrideVar(t, &azureCheckURL, azure.URL)

	addr := startTestDNSServer(t, (&fakeDNS{
		cname:    map[string]string{"app.test.": "taken.trafficmanager.net"},
		nxdomain: map[string]bool{"app.test.": true},
	}).handler())
	o := newTestOptions(t, addr)

	if got := identify("app.test", o); got != "" {
		t.Errorf("identify(app.test) = %q, want empty (name taken)", got)
	}
}

func TestDetect_WritesResult(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname:    map[string]string{"vuln.test.": "gone.buyable.test"},
		nxdomain: map[string]bool{"vuln.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "gone.buyable.test")

	stdout := captureStdout(t, func() { detect("vuln.test", o) })
	if !strings.Contains(stdout, "[DOMAIN AVAILABLE") {
		t.Errorf("stdout = %q, want DOMAIN AVAILABLE line", stdout)
	}
	if written := readOutput(t, o.Output); !strings.Contains(written, "DOMAIN AVAILABLE") {
		t.Errorf("output file = %q, want DOMAIN AVAILABLE", written)
	}
}
