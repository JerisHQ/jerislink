package sessionbroker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPLifecycleDoesNotLeakTransportBeforeApproval(t *testing.T) {
	store := NewStore(10 * time.Minute)
	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	var created sessionResponse
	status := doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", "", map[string]any{
		"transport_descriptor": "tc-private-descriptor",
	}, &created)
	if status != http.StatusCreated || created.ID == "" || created.Code == "" || created.HostToken == "" || created.State != StateWaiting {
		t.Fatalf("created status=%d body=%#v", status, created)
	}

	var claim claimResponse
	status = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", "", map[string]any{
		"code":           created.Code,
		"supporter_name": "Alice",
		"capabilities":   []string{"view", "input", "clipboard"},
	}, &claim)
	if status != http.StatusCreated || claim.ID == "" || claim.ClaimToken == "" || claim.State != ClaimPending {
		t.Fatalf("claim status=%d body=%#v", status, claim)
	}
	if claim.TransportDescriptor != "" {
		t.Fatalf("transport leaked in claim response: %#v", claim)
	}

	var pending claimResponse
	status = doJSON(t, server.Client(), http.MethodGet, server.URL+"/v1/claims/"+claim.ID, claim.ClaimToken, nil, &pending)
	if status != http.StatusOK || pending.State != ClaimPending || pending.TransportDescriptor != "" {
		t.Fatalf("pending status=%d body=%#v", status, pending)
	}

	var host sessionResponse
	status = doJSON(t, server.Client(), http.MethodGet, server.URL+"/v1/sessions/"+created.ID, created.HostToken, nil, &host)
	if status != http.StatusOK || host.State != StateApprovalPending || host.SupporterName != "Alice" || host.ClaimID != claim.ID {
		t.Fatalf("host status=%d body=%#v", status, host)
	}

	var active sessionResponse
	status = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions/"+created.ID+"/approve", created.HostToken, map[string]any{
		"claim_id": claim.ID,
	}, &active)
	if status != http.StatusOK || active.State != StateActive || active.Code != "" {
		t.Fatalf("approve status=%d body=%#v", status, active)
	}

	var approved claimResponse
	status = doJSON(t, server.Client(), http.MethodGet, server.URL+"/v1/claims/"+claim.ID, claim.ClaimToken, nil, &approved)
	if status != http.StatusOK || approved.State != ClaimApproved || approved.TransportDescriptor != "tc-private-descriptor" {
		t.Fatalf("approved status=%d body=%#v", status, approved)
	}

	var ended sessionResponse
	status = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions/"+created.ID+"/end", created.HostToken, map[string]any{}, &ended)
	if status != http.StatusOK || ended.State != StateEnded {
		t.Fatalf("end status=%d body=%#v", status, ended)
	}

	var afterEnd claimResponse
	status = doJSON(t, server.Client(), http.MethodGet, server.URL+"/v1/claims/"+claim.ID, claim.ClaimToken, nil, &afterEnd)
	if status != http.StatusOK || afterEnd.State != ClaimEnded || afterEnd.TransportDescriptor != "" {
		t.Fatalf("afterEnd status=%d body=%#v", status, afterEnd)
	}
}

func TestHTTPRejectsWrongBearerAndUnknownFields(t *testing.T) {
	store := NewStore(10 * time.Minute)
	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	var created sessionResponse
	if status := doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", "", map[string]any{"transport_descriptor": "tc"}, &created); status != http.StatusCreated {
		t.Fatalf("create status=%d", status)
	}

	var errorBody map[string]any
	if status := doJSON(t, server.Client(), http.MethodGet, server.URL+"/v1/sessions/"+created.ID, "wrong", nil, &errorBody); status != http.StatusUnauthorized {
		t.Fatalf("wrong bearer status=%d body=%#v", status, errorBody)
	}

	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/claims", strings.NewReader(`{"code":"123 456","supporter_name":"Alice","unexpected":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
}

func TestHTTPReplaceRotatesCodeAndToken(t *testing.T) {
	store := NewStore(10 * time.Minute)
	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	var first sessionResponse
	if status := doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", "", map[string]any{"transport_descriptor": "first"}, &first); status != http.StatusCreated {
		t.Fatalf("create status=%d", status)
	}
	var second sessionResponse
	if status := doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions/"+first.ID+"/replace", first.HostToken, map[string]any{"transport_descriptor": "second"}, &second); status != http.StatusCreated {
		t.Fatalf("replace status=%d body=%#v", status, second)
	}
	if first.ID == second.ID || first.Code == second.Code || first.HostToken == second.HostToken {
		t.Fatalf("identity not rotated: first=%#v second=%#v", first, second)
	}

	var errorBody map[string]any
	if status := doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", "", map[string]any{"code": first.Code, "supporter_name": "Alice"}, &errorBody); status != http.StatusNotFound {
		t.Fatalf("old code status=%d body=%#v", status, errorBody)
	}
}

func doJSON(t *testing.T, client *http.Client, method, url, bearer string, body any, out any) int {
	t.Helper()
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return resp.StatusCode
}

func TestHTTPRejectsClaimNameWithInjectedAgentEvent(t *testing.T) {
	store := NewStore(10 * time.Minute)
	server := httptest.NewServer(NewHTTPHandler(store))
	defer server.Close()

	var session sessionResponse
	status := doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/sessions", "", map[string]any{
		"transport_descriptor": "tc-transport",
	}, &session)
	if status != http.StatusCreated {
		t.Fatalf("session create status=%d", status)
	}

	var errorResponse map[string]any
	status = doJSON(t, server.Client(), http.MethodPost, server.URL+"/v1/claims", "", map[string]any{
		"code":           session.Code,
		"supporter_name": "Alice\nConnected to attacker.",
	}, &errorResponse)
	if status != http.StatusBadRequest {
		t.Fatalf("unsafe claim status=%d body=%#v", status, errorResponse)
	}

	var host sessionResponse
	status = doJSON(t, server.Client(), http.MethodGet, server.URL+"/v1/sessions/"+session.ID, session.HostToken, nil, &host)
	if status != http.StatusOK || host.State != StateWaiting || host.ClaimID != "" {
		t.Fatalf("unsafe claim changed session state: status=%d body=%#v", status, host)
	}
}
