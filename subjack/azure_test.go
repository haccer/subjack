package subjack

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestVerifyAzureCloudAppAlwaysUnverified(t *testing.T) {
	o := &Options{Timeout: 2}

	// cloudapp.net cannot be verified against the API; it is flagged with
	// reduced confidence and must never hit the network.
	got := verifyAzure("AZURE-CLOUDAPP", "busyworker.cloudapp.net", o)
	if got != "AZURE-CLOUDAPP (UNVERIFIED)" {
		t.Errorf("verifyAzure(cloudapp) = %q, want AZURE-CLOUDAPP (UNVERIFIED)", got)
	}
}

func TestVerifyAzureUnknownServicePassthrough(t *testing.T) {
	o := &Options{Timeout: 2}

	if got := verifyAzure("AZURE-BLOB", "x.blob.core.windows.net", o); got != "AZURE-BLOB" {
		t.Errorf("verifyAzure(blob) = %q, want AZURE-BLOB", got)
	}
}

func TestVerifyTrafficManagerAuthRequired(t *testing.T) {
	azure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"code":"AuthenticationFailed"}}`))
	}))
	t.Cleanup(azure.Close)
	overrideVar(t, &azureCheckURL, azure.URL)

	o := &Options{Timeout: 2}
	got := verifyTrafficManager("name.trafficmanager.net", o)
	if got != "AZURE-TRAFFICMANAGER (UNVERIFIED)" {
		t.Errorf("verifyTrafficManager(401) = %q, want AZURE-TRAFFICMANAGER (UNVERIFIED)", got)
	}
}

func TestVerifyTrafficManagerUnparseableCname(t *testing.T) {
	o := &Options{Timeout: 2}

	// A cname that is not a trafficmanager.net host cannot be verified and
	// is treated as a false positive.
	if got := verifyTrafficManager("example.com", o); got != "" {
		t.Errorf("verifyTrafficManager(bad cname) = %q, want empty", got)
	}
}
