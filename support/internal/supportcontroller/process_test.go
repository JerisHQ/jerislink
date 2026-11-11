package supportcontroller

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTransportDescriptorDeliveredViaStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "descriptor.txt")
	fixture := filepath.Join(dir, "transport-fixture")
	script := "#!/bin/sh\nread descriptor\nprintf '%s' \"$descriptor\" > '" + inputFile + "'\necho 'tailcat: generation=1 ready derp_rtt=1ms' >&2\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(fixture, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	transport, err := StartTransportClient(context.Background(), fixture, "tc-secret-fixture", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "tc-secret-fixture" {
		t.Fatalf("descriptor=%q", string(got))
	}
	if err := transport.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := transport.Stop(); err != nil {
		t.Fatalf("second Stop should be idempotent: %v", err)
	}
	select {
	case <-transport.Done():
	default:
		t.Fatal("transport Done channel should be closed after Stop")
	}
}

func TestTransportDescriptorNotPresentInArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	fixture := filepath.Join(dir, "transport-fixture")
	script := "#!/bin/sh\nprintf '%s' \"$*\" > '" + argsFile + "'\nread descriptor\necho 'tailcat: generation=1 ready derp_rtt=1ms' >&2\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(fixture, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	transport, err := StartTransportClient(context.Background(), fixture, "tc-secret-args-check", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Stop()
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), "tc-secret-args-check") {
		t.Fatalf("descriptor leaked into argv: %q", string(args))
	}
	if !strings.Contains(string(args), "--tailcat-stdin") {
		t.Fatalf("expected --tailcat-stdin in argv: %q", string(args))
	}
}

func waitFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
