package subjack

import "testing"

func TestExtractTMName(t *testing.T) {
	tests := []struct {
		cname    string
		expected string
	}{
		{"myprofile.trafficmanager.net", "myprofile"},
		{"myprofile.trafficmanager.net.", "myprofile"},
		{"test-app.trafficmanager.net", "test-app"},
		{"example.com", ""},
		{"trafficmanager.net", ""},
		{".trafficmanager.net", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractTMName(tt.cname)
		if got != tt.expected {
			t.Errorf("extractTMName(%q) = %q, want %q", tt.cname, got, tt.expected)
		}
	}
}
