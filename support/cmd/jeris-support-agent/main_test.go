package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JerisHQ/jerislink/support/internal/brokerclient"
	"github.com/JerisHQ/jerislink/support/internal/sessionbroker"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestAgentOneTimeSessionLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell transport fixture is Unix-only")
	}

	store := sessionbroker.NewStore(10 * time.Minute)
	server := httptest.NewServer(sessionbroker.NewHTTPHandler(store))
	defer server.Close()
	client, err := brokerclient.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	transport := filepath.Join(dir, "transport-fixture")
	fixture := "#!/bin/sh\necho \"TAILCAT_ADDR=tc-agent-$$\"\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(transport, []byte(fixture), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	inR, inW := io.Pipe()
	defer inR.Close()
	defer inW.Close()
	var out lockedBuffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- runAgent(ctx, client, transport, 2*time.Second, 20*time.Millisecond, inR, &out)
	}()

	codes := waitForCodes(t, &out, 1, 4*time.Second)
	oldCode := codes[0]

	if _, err := io.WriteString(inW, "new\n"); err != nil {
		t.Fatal(err)
	}
	codes = waitForCodes(t, &out, 2, 5*time.Second)
	newCode := codes[1]
	if newCode == oldCode {
		t.Fatalf("Generate New Code reused visible code %q", newCode)
	}
	if _, _, err := store.Claim(oldCode, "Alice", nil); !errors.Is(err, sessionbroker.ErrCodeNotFound) {
		t.Fatalf("old code should be revoked, got %v", err)
	}

	claim, claimToken, err := store.Claim(newCode, "Alice", []string{"view", "input", "clipboard"})
	if err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, &out, "Incoming support request from Alice", 3*time.Second)
	if strings.Contains(out.String(), "tc-agent-") {
		t.Fatal("agent console leaked transport descriptor before approval")
	}

	if _, err := io.WriteString(inW, "approve\n"); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, &out, "Connected to Alice.", 3*time.Second)
	approved := waitForClaimState(t, store, claim.ID, claimToken, sessionbroker.ClaimApproved, 3*time.Second)
	if !strings.HasPrefix(approved.TransportDescriptor, "tc-agent-") {
		t.Fatalf("approved transport descriptor=%q", approved.TransportDescriptor)
	}
	if strings.Contains(out.String(), approved.TransportDescriptor) {
		t.Fatal("agent console leaked approved transport descriptor")
	}

	if _, err := io.WriteString(inW, "new\n"); err != nil {
		t.Fatal(err)
	}
	waitForOutput(t, &out, "End the active session before generating a new code.", 2*time.Second)

	if _, err := io.WriteString(inW, "end\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("agent ended with error: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("agent did not exit after end")
	}

	ended := waitForClaimState(t, store, claim.ID, claimToken, sessionbroker.ClaimEnded, time.Second)
	if ended.TransportDescriptor != "" {
		t.Fatalf("transport descriptor survived end: %q", ended.TransportDescriptor)
	}
	waitForOutput(t, &out, "Temporary transport credentials destroyed.", time.Second)
}

func waitForCodes(t *testing.T, out *lockedBuffer, want int, timeout time.Duration) []string {
	t.Helper()
	re := regexp.MustCompile(`Support Code: ([0-9]{3} [0-9]{3})`)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		matches := re.FindAllStringSubmatch(out.String(), -1)
		if len(matches) >= want {
			codes := make([]string, 0, len(matches))
			for _, m := range matches {
				codes = append(codes, m[1])
			}
			return codes
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d support codes; output=%q", want, out.String())
	return nil
}

func waitForOutput(t *testing.T, out *lockedBuffer, needle string, timeout time.Duration) {
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

func waitForClaimState(t *testing.T, store *sessionbroker.Store, claimID, token string, want sessionbroker.ClaimState, timeout time.Duration) sessionbroker.Claim {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		claim, err := store.ClaimStatus(claimID, token)
		if err != nil {
			t.Fatal(err)
		}
		if claim.State == want {
			return claim
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for claim state %s", want)
	return sessionbroker.Claim{}
}
