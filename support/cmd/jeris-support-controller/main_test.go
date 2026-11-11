package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JerisHQ/jerislink/support/internal/brokerclient"
	"github.com/JerisHQ/jerislink/support/internal/sessionbroker"
)

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestControllerApprovedSessionLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures are Unix-only")
	}

	store := sessionbroker.NewStore(10 * time.Minute)
	hostSession, hostToken, err := store.Create("tc-controller-secret")
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(sessionbroker.NewHTTPHandler(store))
	defer server.Close()
	client, err := brokerclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	descriptorFile := filepath.Join(dir, "descriptor.txt")
	viewerStarted := filepath.Join(dir, "viewer-started.txt")
	transportFixture := filepath.Join(dir, "transport-fixture")
	viewerFixture := filepath.Join(dir, "viewer-fixture")

	transportScript := "#!/bin/sh\nread descriptor\nprintf '%s' \"$descriptor\" > '" + descriptorFile + "'\necho 'tailcat: generation=1 ready derp_rtt=1ms' >&2\nwhile true; do sleep 1; done\n"
	viewerScript := "#!/bin/sh\necho started > '" + viewerStarted + "'\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(transportFixture, []byte(transportScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(viewerFixture, []byte(viewerScript), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cfg := controllerConfig{
		Code:             hostSession.Code,
		SupporterName:    "Alice",
		TransportBinary:  transportFixture,
		ViewerBinary:     viewerFixture,
		PollEvery:        20 * time.Millisecond,
		TransportTimeout: 2 * time.Second,
	}
	var out safeBuffer
	errCh := make(chan error, 1)
	go func() { errCh <- runController(ctx, client, cfg, &out) }()

	var pending sessionbroker.Session
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pending, err = store.Snapshot(hostSession.ID, hostToken)
		if err != nil {
			t.Fatal(err)
		}
		if pending.State == sessionbroker.StateApprovalPending && pending.ClaimID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pending.State != sessionbroker.StateApprovalPending || pending.ClaimID == "" {
		t.Fatalf("controller did not create pending claim; host=%#v output=%q", pending, out.String())
	}
	if pending.SupporterName != "Alice" {
		t.Fatalf("supporter=%q", pending.SupporterName)
	}

	if _, err := store.Approve(hostSession.ID, hostToken, pending.ClaimID); err != nil {
		t.Fatal(err)
	}
	if !waitForFile(viewerStarted, 4*time.Second) {
		t.Fatalf("Viewer did not start; output=%q", out.String())
	}
	if !waitForFile(descriptorFile, time.Second) {
		t.Fatal("transport did not receive descriptor")
	}
	descriptor, err := os.ReadFile(descriptorFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(descriptor) != "tc-controller-secret" {
		t.Fatalf("transport descriptor=%q", string(descriptor))
	}
	if strings.Contains(out.String(), "tc-controller-secret") {
		t.Fatalf("controller console leaked transport descriptor: %q", out.String())
	}
	waitForOutput(t, &out, "Connected. JerisLink Viewer started.", 2*time.Second)

	if _, err := store.End(hostSession.ID, hostToken); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("controller ended with error: %v; output=%q", err, out.String())
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("controller did not exit after host End; output=%q", out.String())
	}
	waitForOutput(t, &out, "Support session ended.", time.Second)
}

func waitForOutput(t *testing.T, out *safeBuffer, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), needle) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q; output=%q", needle, out.String())
}

func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
