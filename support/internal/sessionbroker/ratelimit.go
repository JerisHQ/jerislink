package sessionbroker

import (
	"sync"
	"time"
)

const defaultLimiterMaxKeys = 16384

type rateWindow struct {
	started time.Time
	count   int
}

type fixedWindowLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	maxKeys   int
	now       func() time.Time
	entries   map[string]rateWindow
	lastSweep time.Time
}

func newFixedWindowLimiter(limit int, window time.Duration, maxKeys int, now func() time.Time) *fixedWindowLimiter {
	if window <= 0 {
		window = time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = defaultLimiterMaxKeys
	}
	if now == nil {
		now = time.Now
	}
	return &fixedWindowLimiter{
		limit:   limit,
		window:  window,
		maxKeys: maxKeys,
		now:     now,
		entries: make(map[string]rateWindow),
	}
}

func (l *fixedWindowLimiter) allow(key string) (bool, time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	if key == "" {
		key = "unknown"
	}

	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= l.window || len(l.entries) >= l.maxKeys {
		for k, entry := range l.entries {
			if now.Sub(entry.started) >= l.window {
				delete(l.entries, k)
			}
		}
		l.lastSweep = now
	}

	if _, exists := l.entries[key]; !exists {
		threshold := l.maxKeys
		if _, overflowExists := l.entries["__overflow__"]; !overflowExists {
			threshold--
		}
		if threshold < 0 {
			threshold = 0
		}
		if len(l.entries) >= threshold {
			key = "__overflow__"
		}
	}

	entry, exists := l.entries[key]
	if !exists || now.Sub(entry.started) >= l.window {
		l.entries[key] = rateWindow{started: now, count: 1}
		return true, 0
	}
	if entry.count >= l.limit {
		retry := entry.started.Add(l.window).Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	entry.count++
	l.entries[key] = entry
	return true, 0
}
