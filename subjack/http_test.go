package subjack

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHttpGet_ReturnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello subjack"))
	}))
	t.Cleanup(srv.Close)

	body := httpGet(srv.Listener.Addr().String(), false, 2)
	if string(body) != "hello subjack" {
		t.Errorf("httpGet body = %q, want %q", body, "hello subjack")
	}
}

func TestHttpGet_SSL(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure hello"))
	}))
	t.Cleanup(srv.Close)

	// The client skips certificate verification so the self-signed test
	// certificate must be accepted.
	body := httpGet(srv.Listener.Addr().String(), true, 2)
	if string(body) != "secure hello" {
		t.Errorf("httpGet(ssl) body = %q, want %q", body, "secure hello")
	}
}

func TestHttpGet_DeadHost(t *testing.T) {
	// Nothing listens here; the call must return an empty body, not hang.
	body := httpGet("127.0.0.1:1", false, 1)
	if len(body) != 0 {
		t.Errorf("httpGet(dead host) = %q, want empty", body)
	}
}

func TestHttpGet_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.Write([]byte("too late"))
	}))
	t.Cleanup(srv.Close)

	start := time.Now()
	body := httpGet(srv.Listener.Addr().String(), false, 1)
	elapsed := time.Since(start)
	if len(body) != 0 {
		t.Errorf("httpGet(timeout) = %q, want empty", body)
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("httpGet took %v, want it to respect the 1s timeout", elapsed)
	}
}
