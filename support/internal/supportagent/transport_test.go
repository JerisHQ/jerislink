package supportagent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStartTransportReadsAddressAndStops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	dir := t.TempDir()
	fixture := filepath.Join(dir, "transport-fixture")
	content := "#!/bin/sh\necho 'TAILCAT_ADDR=tc-test-descriptor'\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(fixture, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	transport, err := StartTransport(context.Background(), fixture, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Address != "tc-test-descriptor" {
		t.Fatalf("address=%q", transport.Address)
	}
	if err := transport.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestStartTransportTimesOutWithoutAddress(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	dir := t.TempDir()
	fixture := filepath.Join(dir, "transport-fixture")
	content := "#!/bin/sh\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(fixture, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := StartTransport(context.Background(), fixture, 100*time.Millisecond); err == nil {
		t.Fatal("expected startup timeout")
	}
}
