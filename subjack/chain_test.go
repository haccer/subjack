package subjack

import (
	"strings"
	"testing"
)

func TestCheckCNAMEChain_Takeover(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{
			"app.test.":         "hop1.test",
			"hop1.test.":        "gone.buyable.test",
			"gone.buyable.test": "", // terminal, unregistered
		},
		nxdomain: map[string]bool{"gone.buyable.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "gone.buyable.test")

	checkCNAMEChain("app.test", o)

	written := readOutput(t, o.Output)
	if !strings.Contains(written, "CNAME CHAIN TAKEOVER") {
		t.Fatalf("output = %q, want CNAME CHAIN TAKEOVER", written)
	}
	if !strings.Contains(written, "app.test -> hop1.test -> gone.buyable.test") {
		t.Errorf("output = %q, want it to include the full chain", written)
	}
}

func TestCheckCNAMEChain_SingleLinkIgnored(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{"app.test.": "live.target.test"},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "live.target.test")

	checkCNAMEChain("app.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty for a single-link chain", written)
	}
}

func TestCheckCNAMEChain_UnregisteredButTaken(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		cname: map[string]string{
			"app.test.":  "hop1.test",
			"hop1.test.": "dead.registered.test",
		},
		nxdomain: map[string]bool{"dead.registered.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o) // NXDOMAIN target but not registrable

	checkCNAMEChain("app.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty when the dangling target is registered", written)
	}
}

func TestCheckSRV_Takeover(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		srv: map[string][]string{
			"_submission._tcp.mail.test.": {"dead-srv.buyable.test"},
		},
		nxdomain: map[string]bool{"dead-srv.buyable.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "dead-srv.buyable.test")

	checkSRV("mail.test", o)

	written := readOutput(t, o.Output)
	if !strings.Contains(written, "SRV TAKEOVER") {
		t.Fatalf("output = %q, want SRV TAKEOVER", written)
	}
	if !strings.Contains(written, "_submission._tcp") {
		t.Errorf("output = %q, want it to name the SRV record", written)
	}
}

func TestCheckSRV_LiveTargetNotFlagged(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		srv: map[string][]string{
			"_submission._tcp.mail.test.": {"mail.provider.test"},
		},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o)

	checkSRV("mail.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty for live SRV target", written)
	}
}

func TestCheckSRV_NoRecords(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	checkSRV("mail.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty when there are no SRV records", written)
	}
}
