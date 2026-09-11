package outputs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRouter is a minimal stand-in for the RouterOS REST address-list endpoint.
// It counts requests so tests can assert how much traffic a deploy produces.
type fakeRouter struct {
	mu      sync.Mutex
	entries []map[string]any
	nextID  int

	gets    int64
	puts    int64
	patches int64

	inFlight int64
	peak     int64
}

func newFakeRouter(entries ...map[string]any) *fakeRouter {
	return &fakeRouter{entries: entries, nextID: len(entries) + 1}
}

func (f *fakeRouter) counts() (gets, puts, patches int64) {
	return atomic.LoadInt64(&f.gets), atomic.LoadInt64(&f.puts), atomic.LoadInt64(&f.patches)
}

func (f *fakeRouter) clear() {
	f.mu.Lock()
	f.entries = nil
	f.mu.Unlock()
}

func (f *fakeRouter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	current := atomic.AddInt64(&f.inFlight, 1)
	for {
		observed := atomic.LoadInt64(&f.peak)
		if current <= observed || atomic.CompareAndSwapInt64(&f.peak, observed, current) {
			break
		}
	}
	defer atomic.AddInt64(&f.inFlight, -1)
	time.Sleep(time.Millisecond)

	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		atomic.AddInt64(&f.gets, 1)
		f.handleGet(w, r)
	case http.MethodPut:
		atomic.AddInt64(&f.puts, 1)
		f.handlePut(w, r)
	case http.MethodPatch:
		atomic.AddInt64(&f.patches, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeRouter) handleGet(w http.ResponseWriter, r *http.Request) {
	list := r.URL.Query().Get("list")
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, 0, len(f.entries))
	for _, entry := range f.entries {
		if list == "" || entry["list"] == list {
			out = append(out, entry)
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (f *fakeRouter) handlePut(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	id := fmt.Sprintf("*%d", f.nextID)
	f.nextID++
	entry := map[string]any{".id": id}
	for key, value := range payload {
		entry[key] = value
	}
	f.entries = append(f.entries, entry)
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(entry)
}

func routerEntry(id, list, address, comment, timeout string) map[string]any {
	entry := map[string]any{".id": id, "list": list, "address": address, "comment": comment}
	if timeout != "" {
		entry["timeout"] = timeout
	}
	return entry
}

func newTestRestClient(t *testing.T, router *fakeRouter, tune func(*RosRestApiAddressListConfig)) *RouterOSRestClient {
	t.Helper()
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port := 0
	if _, err := fmt.Sscanf(parsed.Port(), "%d", &port); err != nil {
		t.Fatalf("parse server port: %v", err)
	}

	cfg := RosRestApiAddressListConfig{
		ID:       "test",
		ListName: "blocked",
		Access: RosApiAccessConfig{
			Host:     parsed.Hostname(),
			Port:     port,
			Username: "admin",
			Password: "password",
		},
		RecordType: "ip",
		// No refresh ticker in tests; refreshAllLists is called explicitly.
		RefreshInterval: -1,
	}
	if tune != nil {
		tune(&cfg)
	}
	client, err := NewRouterOSRestClient(cfg, 5*time.Second)
	if err != nil {
		t.Fatalf("new rest client: %v", err)
	}
	return client
}

// A deploy over an already-populated list should cost one request per list, not
// one per address.
func TestRestWarmupAvoidsPerAddressLookups(t *testing.T) {
	router := newFakeRouter(
		routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", ""),
		routerEntry("*2", "blocked", "2.2.2.2", "b.example.com", ""),
		routerEntry("*3", "blocked", "3.3.3.3", "c.example.com", ""),
	)
	client := newTestRestClient(t, router, nil)

	gets, _, _ := router.counts()
	if gets != 1 {
		t.Fatalf("expected a single connectivity check, got %d GETs", gets)
	}

	client.WarmupLists([]string{"blocked"})
	gets, _, _ = router.counts()
	if gets != 2 {
		t.Fatalf("expected warmup to cost one request, got %d GETs total", gets)
	}

	for _, address := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if err := client.EnsureAddress("blocked", "x.example.com", address, nil, nil); err != nil {
			t.Fatalf("ensure %s: %v", address, err)
		}
	}

	gets, puts, patches := router.counts()
	if gets != 2 || puts != 0 || patches != 0 {
		t.Errorf("known addresses should be free: got %d GETs, %d PUTs, %d PATCHes", gets, puts, patches)
	}
}

// A new address costs exactly one write, with no follow-up lookup for its id.
func TestRestNewAddressCostsOneWrite(t *testing.T) {
	router := newFakeRouter(routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", ""))
	client := newTestRestClient(t, router, nil)
	client.WarmupLists([]string{"blocked"})

	before, _, _ := router.counts()
	if err := client.EnsureAddress("blocked", "new.example.com", "9.9.9.9", nil, nil); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	gets, puts, _ := router.counts()
	if puts != 1 {
		t.Errorf("expected exactly one write, got %d", puts)
	}
	if gets != before {
		t.Errorf("expected no extra lookups, got %d additional GETs", gets-before)
	}

	// The id from the create response is cached, so a repeat is free.
	if err := client.EnsureAddress("blocked", "new.example.com", "9.9.9.9", nil, nil); err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	if _, puts, _ = router.counts(); puts != 1 {
		t.Errorf("expected the second ensure to be served from cache, got %d writes", puts)
	}
}

func TestRestRestoresClearedList(t *testing.T) {
	router := newFakeRouter(
		routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", "1h"),
		routerEntry("*2", "blocked", "2.2.2.2", "b.example.com", ""),
	)
	client := newTestRestClient(t, router, nil)
	client.WarmupLists([]string{"blocked"})

	// The router loses the list: reboot, config restore, manual flush.
	router.clear()
	client.refreshAllLists()

	if got := router.size(); got != 2 {
		t.Fatalf("expected the list to be restored to 2 entries, got %d", got)
	}
	router.mu.Lock()
	restored := make(map[string]map[string]any, len(router.entries))
	for _, entry := range router.entries {
		restored[fmt.Sprint(entry["address"])] = entry
	}
	router.mu.Unlock()

	first, ok := restored["1.1.1.1"]
	if !ok {
		t.Fatal("expected 1.1.1.1 to be restored")
	}
	if first["comment"] != "a.example.com" {
		t.Errorf("restore lost the comment: %v", first["comment"])
	}
	if first["timeout"] != "1h" {
		t.Errorf("restore lost the timeout: %v", first["timeout"])
	}
	if _, ok := restored["2.2.2.2"]; !ok {
		t.Error("expected 2.2.2.2 to be restored")
	}

	// Restored ids are cached, so serving those addresses stays free.
	_, putsBefore, _ := router.counts()
	if err := client.EnsureAddress("blocked", "a.example.com", "1.1.1.1", nil, nil); err != nil {
		t.Fatalf("ensure after restore: %v", err)
	}
	if _, puts, _ := router.counts(); puts != putsBefore {
		t.Errorf("expected no write after a restore, got %d extra", puts-putsBefore)
	}
}

// The router is wiped, then the forwarder writes a few fresh addresses before
// the periodic check runs, so the list is no longer empty when it is examined.
func TestRestRestoresAfterClearWithFreshWrites(t *testing.T) {
	var seed []map[string]any
	for i := 1; i <= 12; i++ {
		seed = append(seed, routerEntry(fmt.Sprintf("*%d", i), "blocked", fmt.Sprintf("10.0.0.%d", i), "old.example.com", ""))
	}
	router := newFakeRouter(seed...)
	client := newTestRestClient(t, router, nil)
	client.WarmupLists([]string{"blocked"})

	router.clear()

	// Live traffic resolves new domains and writes them into the wiped list.
	for i := 1; i <= 3; i++ {
		address := fmt.Sprintf("192.0.2.%d", i)
		if err := client.EnsureAddress("blocked", "fresh.example.com", address, nil, nil); err != nil {
			t.Fatalf("ensure %s: %v", address, err)
		}
	}
	if got := router.size(); got != 3 {
		t.Fatalf("expected the 3 fresh addresses on the router, got %d", got)
	}

	client.refreshAllLists()

	if got := router.size(); got != 15 {
		t.Fatalf("expected 12 restored + 3 fresh = 15 entries, got %d", got)
	}
	router.mu.Lock()
	byAddress := make(map[string]string, len(router.entries))
	for _, entry := range router.entries {
		byAddress[fmt.Sprint(entry["address"])] = fmt.Sprint(entry["comment"])
	}
	router.mu.Unlock()

	for i := 1; i <= 12; i++ {
		address := fmt.Sprintf("10.0.0.%d", i)
		if comment, ok := byAddress[address]; !ok {
			t.Errorf("expected %s to be restored", address)
		} else if comment != "old.example.com" {
			t.Errorf("restore lost the comment for %s: %q", address, comment)
		}
	}
	if len(byAddress) != 15 {
		t.Errorf("expected no duplicates, got %d distinct addresses", len(byAddress))
	}
}

// Losing a couple of addresses is churn: no bulk restore.
func TestRestIgnoresSmallShrink(t *testing.T) {
	var seed []map[string]any
	for i := 1; i <= 12; i++ {
		seed = append(seed, routerEntry(fmt.Sprintf("*%d", i), "blocked", fmt.Sprintf("10.0.0.%d", i), "old.example.com", ""))
	}
	router := newFakeRouter(seed...)
	client := newTestRestClient(t, router, nil)
	client.WarmupLists([]string{"blocked"})

	// Two of twelve removed by hand.
	router.mu.Lock()
	router.entries = router.entries[2:]
	router.mu.Unlock()

	_, putsBefore, _ := router.counts()
	client.refreshAllLists()
	if _, puts, _ := router.counts(); puts != putsBefore {
		t.Errorf("expected no restore writes for ordinary churn, got %d", puts-putsBefore)
	}
	if got := router.size(); got != 10 {
		t.Errorf("expected the list left alone at 10 entries, got %d", got)
	}
}

func TestRestDoesNotRestoreWhenDisabled(t *testing.T) {
	router := newFakeRouter(routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", ""))
	disabled := false
	client := newTestRestClient(t, router, func(cfg *RosRestApiAddressListConfig) {
		cfg.RestoreClearedList = &disabled
	})
	client.WarmupLists([]string{"blocked"})

	router.clear()
	client.refreshAllLists()

	if got := router.size(); got != 0 {
		t.Errorf("expected no restore when disabled, got %d entries", got)
	}
}

// An entry with plenty of timeout left should not be rewritten on every query.
func TestRestSkipsRedundantTTLWrites(t *testing.T) {
	router := newFakeRouter(routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", "1h"))
	ttl := "1h"
	updateTTL := true
	client := newTestRestClient(t, router, func(cfg *RosRestApiAddressListConfig) {
		cfg.TTL = &ttl
		cfg.UpdateTTL = &updateTTL
	})
	client.WarmupLists([]string{"blocked"})

	for i := 0; i < 5; i++ {
		if err := client.EnsureAddress("blocked", "a.example.com", "1.1.1.1", nil, nil); err != nil {
			t.Fatalf("ensure: %v", err)
		}
	}
	if _, _, patches := router.counts(); patches != 0 {
		t.Errorf("expected no TTL rewrites while the entry is fresh, got %d", patches)
	}

	// An entry close to expiry is refreshed.
	router.clear()
	router.mu.Lock()
	router.entries = []map[string]any{routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", "00:10:00")}
	router.mu.Unlock()
	client.refreshAllLists()

	if err := client.EnsureAddress("blocked", "a.example.com", "1.1.1.1", nil, nil); err != nil {
		t.Fatalf("ensure near expiry: %v", err)
	}
	if _, _, patches := router.counts(); patches != 1 {
		t.Errorf("expected one TTL rewrite near expiry, got %d", patches)
	}
}

func TestRestCapsConcurrentRequests(t *testing.T) {
	router := newFakeRouter()
	client := newTestRestClient(t, router, func(cfg *RosRestApiAddressListConfig) {
		cfg.MaxConcurrentRequests = 2
	})
	client.WarmupLists([]string{"blocked"})

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			address := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			if err := client.EnsureAddress("blocked", "x.example.com", address, nil, nil); err != nil {
				t.Errorf("ensure %s: %v", address, err)
			}
		}(i)
	}
	wg.Wait()

	if peak := atomic.LoadInt64(&router.peak); peak > 2 {
		t.Errorf("router saw %d concurrent requests, expected at most 2", peak)
	}
	if got := router.size(); got != 40 {
		t.Errorf("expected all 40 addresses to be written, got %d", got)
	}
}

func TestRestSubnetCoverageSkipsWrites(t *testing.T) {
	router := newFakeRouter(routerEntry("*1", "blocked", "10.0.0.0/8", "lan", ""))
	client := newTestRestClient(t, router, nil)
	client.WarmupLists([]string{"blocked"})

	if err := client.EnsureAddress("blocked", "host.example.com", "10.1.2.3", nil, nil); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, puts, _ := router.counts(); puts != 0 {
		t.Errorf("expected an address covered by 10.0.0.0/8 to be skipped, got %d writes", puts)
	}

	if err := client.EnsureAddress("blocked", "other.example.com", "11.1.2.3", nil, nil); err != nil {
		t.Fatalf("ensure outside the subnet: %v", err)
	}
	if _, puts, _ := router.counts(); puts != 1 {
		t.Errorf("expected an uncovered address to be written, got %d writes", puts)
	}
}

func TestRestWarmupIsIdempotent(t *testing.T) {
	router := newFakeRouter(routerEntry("*1", "blocked", "1.1.1.1", "a.example.com", ""))
	client := newTestRestClient(t, router, nil)

	client.WarmupLists([]string{"blocked", " blocked ", "", "blocked"})
	gets, _, _ := router.counts()
	if gets != 2 {
		t.Errorf("expected the duplicate list names to collapse into one request, got %d GETs", gets)
	}
	if !strings.HasSuffix(client.baseURL, "/rest/ip/firewall/address-list") {
		t.Errorf("unexpected base url %q", client.baseURL)
	}
}
