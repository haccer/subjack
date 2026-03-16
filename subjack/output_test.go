package subjack

import (
	"encoding/json"
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
