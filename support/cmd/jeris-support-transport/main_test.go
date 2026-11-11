package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitorTailcatTriggersAfterConsecutiveFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var c counters
	var calls atomic.Int32
	err := monitorTailcat(
		ctx,
		time.Millisecond,
		2,
		func(context.Context) error {
			calls.Add(1)
			return errors.New("offline")
		},
		&c,
		7,
	)
	if err == nil || !strings.Contains(err.Error(), "2 consecutive probes") {
		t.Fatalf("expected consecutive-failure error, got %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("probe calls=%d, want 2", got)
	}
	if got := c.healthFail.Load(); got != 2 {
		t.Fatalf("healthFail=%d, want 2", got)
	}
	if got := c.healthOK.Load(); got != 0 {
		t.Fatalf("healthOK=%d, want 0", got)
	}
}

func TestMonitorTailcatRecoveryResetsFailureStreak(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	probeResults := []error{
		errors.New("first failure"),
		nil,
		errors.New("second failure"),
		errors.New("third failure"),
	}
	var c counters
	var index atomic.Int32
	err := monitorTailcat(
		ctx,
		time.Millisecond,
		2,
		func(context.Context) error {
			i := int(index.Add(1)) - 1
			if i >= len(probeResults) {
				return errors.New("unexpected extra probe")
			}
			return probeResults[i]
		},
		&c,
		9,
	)
	if err == nil || !strings.Contains(err.Error(), "2 consecutive probes") {
		t.Fatalf("expected consecutive-failure error, got %v", err)
	}
	if got := index.Load(); got != 4 {
		t.Fatalf("probe calls=%d, want 4", got)
	}
	if got := c.healthFail.Load(); got != 3 {
		t.Fatalf("healthFail=%d, want 3", got)
	}
	if got := c.healthOK.Load(); got != 1 {
		t.Fatalf("healthOK=%d, want 1", got)
	}
}

func TestExponentialBackoffCapsAtMaximum(t *testing.T) {
	base := time.Second
	maximum := 30 * time.Second
	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}
	for i, expected := range want {
		streak := i + 1
		if got := exponentialBackoff(base, maximum, streak); got != expected {
			t.Fatalf("streak=%d backoff=%s, want %s", streak, got, expected)
		}
	}
}

func TestNextRestartDelayResetsAfterReadyGeneration(t *testing.T) {
	base := time.Second
	maximum := 30 * time.Second
	streak := 0

	var delay time.Duration
	for _, expected := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		delay, streak = nextRestartDelay(false, streak, base, maximum)
		if delay != expected {
			t.Fatalf("startup failure streak=%d delay=%s, want %s", streak, delay, expected)
		}
	}
	if streak != 3 {
		t.Fatalf("startup failure streak=%d, want 3", streak)
	}

	delay, streak = nextRestartDelay(true, streak, base, maximum)
	if delay != base {
		t.Fatalf("ready generation delay=%s, want %s", delay, base)
	}
	if streak != 0 {
		t.Fatalf("ready generation streak=%d, want 0", streak)
	}

	delay, streak = nextRestartDelay(false, streak, base, maximum)
	if delay != base || streak != 1 {
		t.Fatalf("post-reset first failure delay=%s streak=%d, want %s/1", delay, streak, base)
	}
}

func TestResolveTailcatAddressFromStdin(t *testing.T) {
	got, err := resolveTailcatAddress("", "", true, strings.NewReader("tc-secret-descriptor\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "tc-secret-descriptor" {
		t.Fatalf("got=%q", got)
	}
}

func TestResolveTailcatAddressRejectsMultipleSources(t *testing.T) {
	if _, err := resolveTailcatAddress("tc-direct", "", true, strings.NewReader("tc-stdin\n")); err == nil {
		t.Fatal("expected multiple-source error")
	}
}

func TestResolveTailcatAddressRequiresSource(t *testing.T) {
	if _, err := resolveTailcatAddress("", "", false, strings.NewReader("")); err == nil {
		t.Fatal("expected missing-source error")
	}
}
