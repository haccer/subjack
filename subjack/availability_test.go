package subjack

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		in, expected string
	}{
		{"Example.COM", "example.com"},
		{"foo.example.com.", "foo.example.com"},
		{"https://Foo.Bar.com", "foo.bar.com"},
		{"http://foo.bar.com.", "foo.bar.com"},
		{"", ""},
		{".", ""},
	}

	for _, tt := range tests {
		if got := normalizeDomain(tt.in); got != tt.expected {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.in, got, tt.expected)
		}
	}
}

func TestDomainAvailableOverride(t *testing.T) {
	o := &Options{}
	setAvailable(o, "buyable.example")

	if !o.domainAvailable("buyable.example") {
		t.Error("override not used: buyable.example reported unavailable")
	}
	if o.domainAvailable("other.example") {
		t.Error("override not used: other.example reported available")
	}
}
