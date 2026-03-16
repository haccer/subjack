package subjack

import (
	"net"
	"testing"
)

func TestIdentifyProvider(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		// AWS
		{"3.5.1.1", "AWS"},
		{"52.10.0.1", "AWS"},
		{"54.144.0.1", "AWS"},
		// GCP
		{"34.10.0.1", "GCP"},
		{"35.190.0.1", "GCP"},
		{"104.196.1.1", "GCP"},
		// Azure
		{"13.64.0.1", "Azure"},
		{"20.1.0.1", "Azure"},
		{"40.64.0.1", "Azure"},
		// DigitalOcean
		{"68.183.1.1", "DigitalOcean"},
		{"159.65.1.1", "DigitalOcean"},
		{"143.198.1.1", "DigitalOcean"},
		// Linode
		{"45.79.1.1", "Linode"},
		{"172.104.1.1", "Linode"},
		{"139.144.1.1", "Linode"},
		// Vultr
		{"45.32.1.1", "Vultr"},
		{"149.28.1.1", "Vultr"},
		{"155.138.1.1", "Vultr"},
		// Oracle
		{"129.80.1.1", "Oracle"},
		{"150.136.1.1", "Oracle"},
		{"152.67.1.1", "Oracle"},
		// Unknown
		{"1.1.1.1", ""},
		{"192.168.1.1", ""},
		{"127.0.0.1", ""},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := identifyProvider(ip)
		if got != tt.expected {
			t.Errorf("identifyProvider(%s) = %q, want %q", tt.ip, got, tt.expected)
		}
	}
}

func TestIcmpChecksum(t *testing.T) {
	// Standard ICMP echo request
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	cs := icmpChecksum(msg)
	if cs == 0 {
		t.Error("icmpChecksum returned 0 for non-zero input")
	}

	// Verify checksum is correct by checking complement
	msg[2] = byte(cs >> 8)
	msg[3] = byte(cs)
	verify := icmpChecksum(msg)
	if verify != 0 {
		t.Errorf("icmpChecksum verification failed, got %d, want 0", verify)
	}
}
