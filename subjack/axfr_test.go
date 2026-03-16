package subjack

import "testing"

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
