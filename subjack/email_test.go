package subjack

import (
	"strings"
	"testing"
)

func TestCheckSPF_Takeover(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		txt: map[string][]string{
			"app.test.": {"v=spf1 include:spf.dead-buyable.test include:live.spf.test -all"},
		},
		nxdomain: map[string]bool{"spf.dead-buyable.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "spf.dead-buyable.test")

	checkSPF("app.test", o)

	written := readOutput(t, o.Output)
	if !strings.Contains(written, "SPF TAKEOVER") {
		t.Fatalf("output = %q, want SPF TAKEOVER", written)
	}
	if strings.Count(written, "SPF TAKEOVER") != 1 {
		t.Errorf("output = %q, want exactly one SPF takeover (live include must be skipped)", written)
	}
	if !strings.Contains(written, "include:spf.dead-buyable.test") {
		t.Errorf("output = %q, want it to name the dead include", written)
	}
}

func TestCheckSPF_NonSPFTxtIgnored(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		txt: map[string][]string{
			"app.test.": {"v=spf1 include:spf.dead-buyable.test -all"},
			"other.test.": {
				"include:spf.dead-buyable.test",
				"some verification record",
			},
		},
		nxdomain: map[string]bool{"spf.dead-buyable.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "spf.dead-buyable.test")

	checkSPF("other.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty for non-SPF TXT records", written)
	}
}

func TestCheckSPF_NoRecords(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{}).handler())
	o := newTestOptions(t, addr)

	checkSPF("app.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty when there are no TXT records", written)
	}
}

func TestCheckMX_Takeover(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		mx: map[string][]string{
			"app.test.": {"mail.dead-buyable.test"},
		},
		nxdomain: map[string]bool{"mail.dead-buyable.test.": true},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o, "mail.dead-buyable.test")

	checkMX("app.test", o)

	written := readOutput(t, o.Output)
	if !strings.Contains(written, "MX TAKEOVER") {
		t.Fatalf("output = %q, want MX TAKEOVER", written)
	}
	if !strings.Contains(written, "mail.dead-buyable.test") {
		t.Errorf("output = %q, want it to name the dead mail server", written)
	}
}

func TestCheckMX_LiveTargetNotFlagged(t *testing.T) {
	addr := startTestDNSServer(t, (&fakeDNS{
		mx: map[string][]string{"app.test.": {"mail.provider.test"}},
	}).handler())
	o := newTestOptions(t, addr)
	setAvailable(o)

	checkMX("app.test", o)
	if written := readOutput(t, o.Output); written != "" {
		t.Errorf("output = %q, want empty for live MX target", written)
	}
}
