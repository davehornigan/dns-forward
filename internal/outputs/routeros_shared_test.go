package outputs

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRouterOSDuration(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"", 0, true},
		{"none", 0, true},
		{"1h23m45s", time.Hour + 23*time.Minute + 45*time.Second, true},
		{"30m", 30 * time.Minute, true},
		{"00:05:00", 5 * time.Minute, true},
		{"23:59:59", 23*time.Hour + 59*time.Minute + 59*time.Second, true},
		{"05:00", 5 * time.Minute, true},
		{"1d00:05:00", 24*time.Hour + 5*time.Minute, true},
		{"4w2d", 30 * 24 * time.Hour, true},
		{"6w6d23:59:59", 48*24*time.Hour + 23*time.Hour + 59*time.Minute + 59*time.Second, true},
		{"90", 90 * time.Second, true},
		{"1H23M", time.Hour + 23*time.Minute, true},
		{"garbage", 0, false},
		{"12x", 0, false},
		{"1:2:3:4", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseRouterOSDuration(tt.value)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("parseRouterOSDuration(%q) = (%v, %v), want (%v, %v)", tt.value, got, ok, tt.want, tt.ok)
		}
	}
}

func TestNeedsTTLRefresh(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		entry  cachedEntry
		wanted string
		want   bool
	}{
		{
			name:   "plenty of time left",
			entry:  cachedEntry{id: "*1", timeout: time.Hour, hasTimeout: true, observedAt: now},
			wanted: "1h",
			want:   false,
		},
		{
			name:   "past the halfway point",
			entry:  cachedEntry{id: "*1", timeout: 20 * time.Minute, hasTimeout: true, observedAt: now},
			wanted: "1h",
			want:   true,
		},
		{
			name:   "observed long ago",
			entry:  cachedEntry{id: "*1", timeout: time.Hour, hasTimeout: true, observedAt: now.Add(-55 * time.Minute)},
			wanted: "1h",
			want:   true,
		},
		{
			name:   "permanent entry",
			entry:  cachedEntry{id: "*1"},
			wanted: "1h",
			want:   true,
		},
		{
			name:   "unparseable wanted ttl",
			entry:  cachedEntry{id: "*1", timeout: time.Hour, hasTimeout: true, observedAt: now},
			wanted: "garbage",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsTTLRefresh(tt.entry, tt.wanted); got != tt.want {
				t.Errorf("needsTTLRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplySnapshotCachesEntries(t *testing.T) {
	cache := newAddressCache()
	restore := cache.applySnapshot("blocked", []listEntry{
		{id: "*1", address: "1.2.3.4", comment: "example.com", timeout: "1h"},
		{id: "*2", address: "10.0.0.0/8", comment: "lan"},
	})
	if restore != nil {
		t.Fatalf("did not expect a restore on the first snapshot, got %v", restore)
	}

	entry, ok := cache.lookup(cacheKey("blocked", "1.2.3.4"))
	if !ok {
		t.Fatal("expected the address to be cached")
	}
	if entry.id != "*1" || entry.comment != "example.com" {
		t.Errorf("unexpected entry %+v", entry)
	}
	if left, known := entry.remaining(); !known || left > time.Hour || left < 59*time.Minute {
		t.Errorf("unexpected remaining %v (known=%v)", left, known)
	}
	if !cache.coveredBySubnet("blocked", "10.1.2.3") {
		t.Error("expected 10.1.2.3 to be covered by the 10.0.0.0/8 entry")
	}
	if cache.coveredBySubnet("blocked", "1.2.3.4") {
		t.Error("did not expect a /32-style address to count as subnet coverage")
	}
}

func TestApplySnapshotDetectsClearedList(t *testing.T) {
	cache := newAddressCache()
	cache.applySnapshot("blocked", []listEntry{
		{id: "*1", address: "1.2.3.4", comment: "example.com", timeout: "1h"},
		{id: "*2", address: "5.6.7.8", comment: "example.org"},
	})

	restore := cache.applySnapshot("blocked", nil)
	if len(restore) != 2 {
		t.Fatalf("expected both entries back for a restore, got %v", restore)
	}
	if restore[0].address != "1.2.3.4" || restore[0].comment != "example.com" {
		t.Errorf("restore lost entry details: %+v", restore[0])
	}
	// The entry keeps the time it had left rather than a fresh full timeout.
	if left, ok := parseRouterOSDuration(restore[0].timeout); !ok || left > time.Hour || left < 59*time.Minute {
		t.Errorf("unexpected restore timeout %q", restore[0].timeout)
	}
	if restore[1].timeout != "" {
		t.Errorf("a permanent entry should stay permanent, got %q", restore[1].timeout)
	}
	if _, ok := cache.lookup(cacheKey("blocked", "1.2.3.4")); ok {
		t.Error("a vanished entry must lose its id so live traffic re-adds it")
	}

	// A failed restore is retried on the next snapshot.
	if again := cache.applySnapshot("blocked", nil); len(again) != 2 {
		t.Errorf("expected the restore to be retried, got %v", again)
	}
}

// The forwarder may write fresh addresses between the clear and the check, so
// the list is not empty by the time we look at it.
func TestApplySnapshotDetectsClearWithNewWrites(t *testing.T) {
	cache := newAddressCache()
	var populated []listEntry
	for i := 1; i <= 30; i++ {
		populated = append(populated, listEntry{
			id:      fmt.Sprintf("*%d", i),
			address: fmt.Sprintf("10.0.0.%d", i),
			comment: "example.com",
		})
	}
	cache.applySnapshot("blocked", populated)

	// Router wiped; three new addresses landed before the check.
	restore := cache.applySnapshot("blocked", []listEntry{
		{id: "*101", address: "192.0.2.1", comment: "fresh.example.com"},
		{id: "*102", address: "192.0.2.2", comment: "fresh.example.com"},
		{id: "*103", address: "192.0.2.3", comment: "fresh.example.com"},
	})
	if len(restore) != 30 {
		t.Fatalf("expected all 30 wiped entries back, got %d", len(restore))
	}
	for _, entry := range restore {
		if strings.HasPrefix(entry.address, "192.0.2.") {
			t.Errorf("a freshly written address must not be restored: %s", entry.address)
		}
	}
	if _, ok := cache.lookup(cacheKey("blocked", "192.0.2.1")); !ok {
		t.Error("expected the fresh addresses to stay cached")
	}
}

// Losing less than a third of a list is churn, not a clear.
func TestApplySnapshotIgnoresSmallShrink(t *testing.T) {
	cache := newAddressCache()
	var populated []listEntry
	for i := 1; i <= 10; i++ {
		populated = append(populated, listEntry{
			id:      fmt.Sprintf("*%d", i),
			address: fmt.Sprintf("10.0.0.%d", i),
		})
	}
	cache.applySnapshot("blocked", populated)

	// Two of ten gone: below the one-third threshold.
	restore := cache.applySnapshot("blocked", populated[2:])
	if len(restore) != 0 {
		t.Errorf("expected no restore for ordinary churn, got %v", restore)
	}
	// They are forgotten, so a later query re-adds them.
	if _, ok := cache.lookup(cacheKey("blocked", "10.0.0.1")); ok {
		t.Error("expected a missing entry to be forgotten when no restore runs")
	}

	// Four of the remaining eight gone: that is a clear.
	restore = cache.applySnapshot("blocked", populated[6:])
	if len(restore) != 4 {
		t.Errorf("expected 4 entries back once a third is gone, got %d", len(restore))
	}
}

// Entries that reached their timeout are the router doing its job.
func TestApplySnapshotIgnoresExpiredEntries(t *testing.T) {
	cache := newAddressCache()
	cache.applySnapshot("blocked", []listEntry{
		{id: "*1", address: "1.1.1.1", timeout: "30s"},
		{id: "*2", address: "2.2.2.2", timeout: "30s"},
		{id: "*3", address: "3.3.3.3", timeout: "2h"},
	})

	// Pretend enough time passed for the 30s entries to expire.
	cache.mu.Lock()
	for _, address := range []string{"1.1.1.1", "2.2.2.2"} {
		entry := cache.entries[cacheKey("blocked", address)]
		entry.observedAt = time.Now().Add(-time.Minute)
		cache.entries[cacheKey("blocked", address)] = entry
	}
	cache.mu.Unlock()

	restore := cache.applySnapshot("blocked", nil)
	if len(restore) != 1 || restore[0].address != "3.3.3.3" {
		t.Fatalf("expected only the unexpired entry back, got %v", restore)
	}
	for _, address := range []string{"1.1.1.1", "2.2.2.2"} {
		cache.mu.Lock()
		_, still := cache.entries[cacheKey("blocked", address)]
		cache.mu.Unlock()
		if still {
			t.Errorf("expected the expired entry %s to be forgotten", address)
		}
	}
}

func TestApplySnapshotEmptyFromTheStart(t *testing.T) {
	cache := newAddressCache()
	if restore := cache.applySnapshot("blocked", nil); restore != nil {
		t.Errorf("an always-empty list has nothing to restore, got %v", restore)
	}
}

func TestExpiredBy(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name  string
		entry cachedEntry
		want  bool
	}{
		{"permanent never expires", cachedEntry{id: "*1"}, false},
		{"fresh", cachedEntry{timeout: time.Hour, hasTimeout: true, observedAt: now}, false},
		{"past due", cachedEntry{timeout: time.Hour, hasTimeout: true, observedAt: now.Add(-2 * time.Hour)}, true},
		{"within grace", cachedEntry{timeout: time.Hour, hasTimeout: true, observedAt: now.Add(-59*time.Minute - 30*time.Second)}, true},
		{"short ttl uses a small grace", cachedEntry{timeout: 30 * time.Second, hasTimeout: true, observedAt: now.Add(-20 * time.Second)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.expiredBy(now); got != tt.want {
				t.Errorf("expiredBy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatRouterOSDuration(t *testing.T) {
	tests := map[time.Duration]string{
		0:                            "0s",
		-time.Second:                 "0s",
		45 * time.Second:             "45s",
		90 * time.Second:             "1m30s",
		time.Hour:                    "1h",
		time.Hour + 23*time.Minute:   "1h23m",
		25*time.Hour + 5*time.Minute: "1d1h5m",
		time.Hour + 23*time.Minute + 45*time.Second: "1h23m45s",
	}
	for input, want := range tests {
		if got := formatRouterOSDuration(input); got != want {
			t.Errorf("formatRouterOSDuration(%v) = %q, want %q", input, got, want)
		}
	}
	// Whatever we emit must parse back to the same duration.
	for _, d := range []time.Duration{time.Second, 90 * time.Second, 3*time.Hour + 17*time.Minute + 4*time.Second} {
		text := formatRouterOSDuration(d)
		back, ok := parseRouterOSDuration(text)
		if !ok || back != d {
			t.Errorf("round trip of %v via %q gave (%v, %v)", d, text, back, ok)
		}
	}
}

func TestApplySnapshotKeepsPendingWrites(t *testing.T) {
	cache := newAddressCache()
	key := cacheKey("blocked", "1.2.3.4")
	cache.applySnapshot("blocked", []listEntry{{id: "*1", address: "1.2.3.4"}})

	if !cache.claim(key) {
		t.Fatal("expected to claim the key")
	}
	cache.applySnapshot("blocked", nil)
	if _, ok := cache.lookup(key); !ok {
		t.Error("expected an in-flight write to keep its cache entry")
	}
	cache.release(key)
}

func TestClaimSnapshotIsExclusive(t *testing.T) {
	cache := newAddressCache()
	if !cache.claimSnapshot("blocked", true) {
		t.Fatal("expected the first claim to win")
	}
	if cache.claimSnapshot("blocked", true) {
		t.Error("expected a concurrent claim to be rejected")
	}
	cache.releaseSnapshot("blocked")

	// onlyIfMissing skips lists that have been snapshotted already.
	cache.applySnapshot("blocked", []listEntry{{id: "*1", address: "1.2.3.4"}})
	if cache.claimSnapshot("blocked", true) {
		t.Error("expected onlyIfMissing to skip an already snapshotted list")
	}
	if !cache.claimSnapshot("blocked", false) {
		t.Error("expected an unconditional claim to succeed")
	}
	cache.releaseSnapshot("blocked")

	if cache.claimSnapshot("  ", false) {
		t.Error("expected an empty list name to be rejected")
	}
}

func TestRouterLimiterCapsConcurrency(t *testing.T) {
	const maxConcurrent = 2
	limiter := newRouterLimiter(maxConcurrent, 0)

	var inFlight, peak int64
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.acquire()
			defer limiter.release()
			current := atomic.AddInt64(&inFlight, 1)
			for {
				observed := atomic.LoadInt64(&peak)
				if current <= observed || atomic.CompareAndSwapInt64(&peak, observed, current) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt64(&inFlight, -1)
		}()
	}
	wg.Wait()

	if peak > maxConcurrent {
		t.Errorf("peak concurrency %d exceeded the limit of %d", peak, maxConcurrent)
	}
	if peak < maxConcurrent {
		t.Errorf("peak concurrency %d never reached the limit of %d", peak, maxConcurrent)
	}
}

func TestRouterLimiterPacesRequests(t *testing.T) {
	const interval = 10 * time.Millisecond
	limiter := newRouterLimiter(4, interval)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limiter.acquire()
			limiter.release()
		}()
	}
	wg.Wait()

	// Five requests at one per interval cannot finish before four intervals.
	if elapsed := time.Since(start); elapsed < 4*interval {
		t.Errorf("5 paced requests took %v, expected at least %v", elapsed, 4*interval)
	}
}

func TestNormalizeListNames(t *testing.T) {
	got := normalizeListNames([]string{" blocked ", "", "blocked", "other", "   "})
	if len(got) != 2 || got[0] != "blocked" || got[1] != "other" {
		t.Errorf("unexpected result %v", got)
	}
}

func TestAddressFamily(t *testing.T) {
	tests := map[string]string{
		"1.2.3.4":              familyIPv4,
		"10.0.0.0/8":           familyIPv4,
		"1.2.3.4/32":           familyIPv4,
		"example.com":          familyIPv4, // recordType: host writes a DNS name
		"":                     familyIPv4,
		"2606:4700:4700::1111": familyIPv6,
		"2606:4700::/32":       familyIPv6,
		"fe80::1/128":          familyIPv6,
		"::1":                  familyIPv6,
	}
	for address, want := range tests {
		if got := addressFamily(address); got != want {
			t.Errorf("addressFamily(%q) = %q, want %q", address, got, want)
		}
	}
}

func TestIsDuplicateEntryErr(t *testing.T) {
	if !isDuplicateEntryErr(errors.New("routeros rest status 400 Bad Request: failure: already have such entry")) {
		t.Error("expected the REST duplicate error to be recognised")
	}
	if !isDuplicateEntryErr(errors.New("from RouterOS device: already have such entry")) {
		t.Error("expected the API duplicate error to be recognised")
	}
	if isDuplicateEntryErr(errors.New("connection refused")) {
		t.Error("an unrelated error is not a duplicate")
	}
	if isDuplicateEntryErr(nil) {
		t.Error("nil is not a duplicate")
	}
}
