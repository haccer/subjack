package subjack

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type tmCheckRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type tmCheckResponse struct {
	NameAvailable bool   `json:"nameAvailable"`
	Reason        string `json:"reason"`
}

// verifyAzure performs secondary verification for Azure services to reduce
// false positives. Returns the service name if confirmed vulnerable, or an
// empty string if it's a false positive.
func verifyAzure(service, cname string, o *Options) string {
	switch service {
	case "AZURE-TRAFFICMANAGER":
		return verifyTrafficManager(cname, o)
	case "AZURE-CLOUDAPP":
		// cloudapp.net has a reservation period after deletion and is being
		// deprecated. Flag with reduced confidence.
		return service + " (UNVERIFIED)"
	default:
		return service
	}
}

// verifyTrafficManager checks the Azure API to see if a Traffic Manager
// profile name is actually available for registration.
func verifyTrafficManager(cname string, o *Options) string {
	name := extractTMName(cname)
	if name == "" {
		return ""
	}

	available, err := checkTrafficManagerAvailable(name, time.Duration(o.Timeout)*time.Second)
	if err != nil {
		// API requires auth or failed — can't verify, flag as unverified
		return "AZURE-TRAFFICMANAGER (UNVERIFIED)"
	}

	if available {
		return "AZURE-TRAFFICMANAGER"
	}

	// Name is taken — this is a false positive
	return ""
}

func extractTMName(cname string) string {
	cname = strings.TrimSuffix(cname, ".")
	suffix := ".trafficmanager.net"
	if !strings.HasSuffix(cname, suffix) {
		return ""
	}
	return strings.TrimSuffix(cname, suffix)
}

func checkTrafficManagerAvailable(name string, timeout time.Duration) (bool, error) {
	reqBody, _ := json.Marshal(tmCheckRequest{
		Name: name,
		Type: "microsoft.network/trafficmanagerprofiles",
	})

	url := "https://management.azure.com/providers/Microsoft.Network/checkTrafficManagerNameAvailability?api-version=2022-04-01"

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false, errAuthRequired
	}

	var result tmCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.NameAvailable, nil
}

var errAuthRequired = &azureError{"azure API requires authentication"}

type azureError struct {
	msg string
}

func (e *azureError) Error() string {
	return e.msg
}
