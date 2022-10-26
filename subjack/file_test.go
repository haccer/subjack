package subjack

import (
	"log"
	"os"
	"testing"
)

func TestReadFileLines(t *testing.T) {
	// Read a file that does not exist.
	_, err := readFileLines("does_not_exist.txt")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	// Read a file that does exist.
	tmpfile, err := os.CreateTemp("", "subjack_test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte("test\nFoobar")); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	lines, err := readFileLines(tmpfile.Name())
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines, got %d", len(lines))
	}
}

func TestReadFile(t *testing.T) {
	// Read a file that does not exist.
	_, err := readFile("does_not_exist.txt")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	// Read a file that does exist.
	tmpfile, err := os.CreateTemp("", "subjack_test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte("test\nFoobar")); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	lines, err := readFile(tmpfile.Name())
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if string(lines) != "test\nFoobar" {
		t.Errorf("Expected 'test\nFoobar', got %v", lines)
	}
}

func TestFingerprints(t *testing.T) {
	invalid_fingerprints := []byte(`[
		{
			"service": ",
			"cname": [,
			"fingerprint": [,
			"nxdomain": [,
		}
		]`)

	_, err := fingerprints(invalid_fingerprints)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}

	valid_fingerprints := []byte(`[
		{
			"service": "fastly",
			"cname": [
				"fastly"
			],
			"fingerprint": [
				"Fastly error: unknown domain"
			],
			"nxdomain": false
		}
		]`)
	fs, err := fingerprints(valid_fingerprints)
	if err != nil {
		t.Errorf("Expected nil, got %v", err)
	}
	if len(fs) != 1 {
		t.Errorf("Expected 1 fingerprint, got %d", len(fs))
	}

}
