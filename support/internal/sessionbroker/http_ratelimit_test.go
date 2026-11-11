package sessionbroker

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCreateRateLimitReturns429AndRetryAfter(t *testing.T) {
	options := DefaultHTTPOptions()
	options.SessionCreatesPerWindow = 1
	options.GlobalSessionCreatesPerWindow = 100
	options.ClaimAttemptsPerWindow = 100
	options.GlobalClaimAttemptsPerWindow = 100
	options.Window = time.Minute

	server := httptest.NewServer(NewHTTPHandlerWithOptions(NewStore(10*time.Minute), options))
	defer server.Close()

	body := []byte(`{"transport_descriptor":"tc-test"}`)
	resp1 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", body, "")
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first create status=%d", resp1.StatusCode)
	}

	resp2 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", body, "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second create status=%d, want 429", resp2.StatusCode)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

func TestClaimRateLimitUsesTrustedClientIPHeader(t *testing.T) {
	options := DefaultHTTPOptions()
	options.ClientIPHeader = "CF-Connecting-IP"
	options.ClaimAttemptsPerWindow = 1
	options.GlobalClaimAttemptsPerWindow = 100
	options.SessionCreatesPerWindow = 100
	options.GlobalSessionCreatesPerWindow = 100
	options.Window = time.Minute

	server := httptest.NewServer(NewHTTPHandlerWithOptions(NewStore(10*time.Minute), options))
	defer server.Close()
	body := []byte(`{"code":"999 999","supporter_name":"Alice"}`)

	resp1 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", body, "203.0.113.10")
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusNotFound {
		t.Fatalf("first client first attempt status=%d", resp1.StatusCode)
	}

	resp2 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", body, "203.0.113.10")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("same client second attempt status=%d, want 429", resp2.StatusCode)
	}

	resp3 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", body, "203.0.113.11")
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("different client status=%d, want independent allowance", resp3.StatusCode)
	}
}

func TestClaimGlobalRateLimitCapsDistributedAttempts(t *testing.T) {
	options := DefaultHTTPOptions()
	options.ClientIPHeader = "CF-Connecting-IP"
	options.ClaimAttemptsPerWindow = 100
	options.GlobalClaimAttemptsPerWindow = 1
	options.SessionCreatesPerWindow = 100
	options.GlobalSessionCreatesPerWindow = 100
	options.Window = time.Minute

	server := httptest.NewServer(NewHTTPHandlerWithOptions(NewStore(10*time.Minute), options))
	defer server.Close()
	body := []byte(`{"code":"999 999","supporter_name":"Alice"}`)

	resp1 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", body, "203.0.113.20")
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusNotFound {
		t.Fatalf("first distributed attempt status=%d", resp1.StatusCode)
	}
	resp2 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", body, "203.0.113.21")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("global second attempt status=%d, want 429", resp2.StatusCode)
	}
}

func doRawJSON(t *testing.T, client *http.Client, method, url string, body []byte, clientIP string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if clientIP != "" {
		req.Header.Set("CF-Connecting-IP", clientIP)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSessionCapacityReturns503(t *testing.T) {
	store := NewStoreWithOptions(StoreOptions{
		WaitingTTL:        10 * time.Minute,
		MaxLiveSessions:   1,
		TerminalRetention: 15 * time.Minute,
	})
	options := DefaultHTTPOptions()
	options.SessionCreatesPerWindow = 100
	options.GlobalSessionCreatesPerWindow = 100
	server := httptest.NewServer(NewHTTPHandlerWithOptions(store, options))
	defer server.Close()

	body := []byte(`{"transport_descriptor":"tc-capacity"}`)
	resp1 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", body, "")
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first create status=%d", resp1.StatusCode)
	}
	resp2 := doRawJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", body, "")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second create status=%d, want 503", resp2.StatusCode)
	}
}
