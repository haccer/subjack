package subjack

import "testing"

func TestIdentifyDNSProvider(t *testing.T) {
	tests := []struct {
		ns       string
		expected string
	}{
		// Route53
		{"ns-123.awsdns-45.com", "Route53"},
		{"ns-2047.awsdns-99.net", "Route53"},
		{"ns-500.awsdns-10.org", "Route53"},
		{"ns-1.awsdns-0.co.uk", "Route53"},
		{"ns-1.awsdns-0.co.uk.", "Route53"},
		// Google Cloud DNS
		{"ns-cloud-a1.googledomains.com", "Google Cloud DNS"},
		{"ns-cloud-d2.googledomains.com.", "Google Cloud DNS"},
		// Azure DNS
		{"ns1-01.azure-dns.com", "Azure DNS"},
		{"ns2-05.azure-dns.net", "Azure DNS"},
		{"ns3-03.azure-dns.org", "Azure DNS"},
		{"ns4-09.azure-dns.info", "Azure DNS"},
		// DigitalOcean DNS
		{"ns1.digitalocean.com", "DigitalOcean DNS"},
		{"ns3.digitalocean.com.", "DigitalOcean DNS"},
		// Vultr DNS
		{"ns1.vultr.com", "Vultr DNS"},
		{"ns2.vultr.com.", "Vultr DNS"},
		// Linode DNS
		{"ns1.linode.com", "Linode DNS"},
		{"ns5.linode.com.", "Linode DNS"},
		// Not a cloud provider
		{"ns1.example.com", ""},
		{"dns.google", ""},
		{"a.iana-servers.net", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := identifyDNSProvider(tt.ns)
		if got != tt.expected {
			t.Errorf("identifyDNSProvider(%q) = %q, want %q", tt.ns, got, tt.expected)
		}
	}
}
