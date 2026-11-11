package sessionbroker

import (
	"testing"
	"time"
)

func TestFixedWindowLimiterBlocksAndResets(t *testing.T) {
	now := time.Date(2026, 10, 8, 4, 0, 0, 0, time.UTC)
	limiter := newFixedWindowLimiter(2, time.Minute, 16, func() time.Time { return now })

	if ok, _ := limiter.allow("client-a"); !ok {
		t.Fatal("first request should pass")
	}
	if ok, _ := limiter.allow("client-a"); !ok {
		t.Fatal("second request should pass")
	}
	if ok, retry := limiter.allow("client-a"); ok || retry <= 0 {
		t.Fatalf("third request ok=%v retry=%s, want blocked", ok, retry)
	}

	now = now.Add(time.Minute)
	if ok, _ := limiter.allow("client-a"); !ok {
		t.Fatal("request after window reset should pass")
	}
}

func TestFixedWindowLimiterBoundsKeyCardinality(t *testing.T) {
	now := time.Date(2026, 10, 8, 4, 0, 0, 0, time.UTC)
	limiter := newFixedWindowLimiter(100, time.Minute, 3, func() time.Time { return now })
	for _, key := range []string{"a", "b", "c", "d", "e", "f"} {
		if ok, _ := limiter.allow(key); !ok {
			t.Fatalf("unexpected block for %q", key)
		}
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if got := len(limiter.entries); got > 3 {
		t.Fatalf("entry count=%d, want <=3", got)
	}
	if _, ok := limiter.entries["__overflow__"]; !ok {
		t.Fatal("expected bounded overflow bucket")
	}
}
