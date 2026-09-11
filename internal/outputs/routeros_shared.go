package outputs

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// A router serves real clients on the same service we write address lists
	// through, so keep our own footprint small by default.
	defaultRouterOSMaxConcurrency     = 2
	defaultRouterOSRestMaxIdleConns   = 2
	defaultRouterOSRestIdleConnExpiry = 90 * time.Second
)

// ListWarmer is implemented by writers that can preload whole address lists in
// one request each. Warming up before the first resolutions turns a deploy from
// one lookup per address into one request per list.
type ListWarmer interface {
	WarmupLists(names []string)
}

// routerLimiter caps how hard a router gets hit: at most maxConcurrent requests
// in flight, and at least minInterval between two request starts. Without it a
// deploy fans out one request per resolved address and can occupy every
// connection slot the router has for its own clients.
type routerLimiter struct {
	sem      chan struct{}
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newRouterLimiter(maxConcurrent int, minInterval time.Duration) *routerLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultRouterOSMaxConcurrency
	}
	if minInterval < 0 {
		minInterval = 0
	}
	return &routerLimiter{
		sem:      make(chan struct{}, maxConcurrent),
		interval: minInterval,
	}
}

// acquire blocks until the caller may issue a request. Callers run on detached
// output goroutines, so blocking here never delays a DNS reply.
func (l *routerLimiter) acquire() {
	if l == nil {
		return
	}
	l.pace()
	l.sem <- struct{}{}
}

func (l *routerLimiter) release() {
	if l == nil {
		return
	}
	<-l.sem
}

// pace reserves the next slot in the request schedule and sleeps until it is
// due, so bursts are spread out instead of landing all at once.
func (l *routerLimiter) pace() {
	if l.interval <= 0 {
		return
	}
	now := time.Now()
	l.mu.Lock()
	wait := time.Duration(0)
	if l.next.After(now) {
		wait = l.next.Sub(now)
	}
	l.next = now.Add(wait + l.interval)
	l.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// listEntry is one address-list row as the router reports it.
type listEntry struct {
	id      string
	address string
	comment string
	timeout string // RouterOS timeout string; empty means the entry is permanent
}

// cachedEntry is what we remember about a row between requests.
type cachedEntry struct {
	id         string
	comment    string
	timeout    time.Duration // remaining timeout when observed; 0 means permanent
	hasTimeout bool
	observedAt time.Time
}

// remaining estimates how much of the entry's timeout is left, accounting for
// the time passed since the router reported it.
func (e cachedEntry) remaining() (time.Duration, bool) {
	if !e.hasTimeout {
		return 0, false
	}
	left := e.timeout - time.Since(e.observedAt)
	if left < 0 {
		left = 0
	}
	return left, true
}

const (
	minExpiryGrace = 5 * time.Second
	maxExpiryGrace = time.Minute
)

// expiredBy reports whether the entry had reached its timeout by now. A small
// grace absorbs the second-level rounding RouterOS applies to the timeouts it
// reports and the delay between reading a list and acting on it, so an entry
// that was about to expire is never mistaken for one that vanished early.
// Entries without a timeout are permanent and never expire on their own.
func (e cachedEntry) expiredBy(now time.Time) bool {
	if !e.hasTimeout {
		return false
	}
	grace := e.timeout / 10
	if grace < minExpiryGrace {
		grace = minExpiryGrace
	}
	if grace > maxExpiryGrace {
		grace = maxExpiryGrace
	}
	return !now.Before(e.observedAt.Add(e.timeout - grace))
}

// restoreTimeout renders the timeout to re-create a vanished entry with: the
// time it had left, so a restore does not extend its lifetime.
func (e cachedEntry) restoreTimeout(now time.Time) string {
	if !e.hasTimeout {
		return ""
	}
	left := e.observedAt.Add(e.timeout).Sub(now)
	if left < time.Second {
		left = time.Second
	}
	return formatRouterOSDuration(left)
}

// addressCache mirrors the router's address lists so repeated resolutions cost
// no router traffic. Both the API and the REST client keep their state here.
type addressCache struct {
	mu           sync.Mutex
	entries      map[string]cachedEntry  // "list|address" -> last known row
	subnets      map[string][]*net.IPNet // list -> CIDR entries that cover single IPs
	pending      map[string]bool         // "list|address" writes in flight
	snapshotting map[string]bool         // lists whose snapshot is in flight
	lists        map[string]bool         // every list this writer has touched
	lastSize     map[string]int          // list -> size it should have, to spot a clear
}

func newAddressCache() *addressCache {
	return &addressCache{
		entries:      make(map[string]cachedEntry),
		subnets:      make(map[string][]*net.IPNet),
		pending:      make(map[string]bool),
		snapshotting: make(map[string]bool),
		lists:        make(map[string]bool),
		lastSize:     make(map[string]int),
	}
}

func cacheKey(listName, address string) string {
	return listName + "|" + address
}

func (a *addressCache) trackList(listName string) {
	if listName == "" {
		return
	}
	a.mu.Lock()
	a.lists[listName] = true
	a.mu.Unlock()
}

// claimSnapshot marks a snapshot of listName as in flight. It returns false
// when another goroutine is already snapshotting the list, or when onlyIfMissing
// is set and the list has been snapshotted before.
func (a *addressCache) claimSnapshot(listName string, onlyIfMissing bool) bool {
	if strings.TrimSpace(listName) == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.snapshotting[listName] {
		return false
	}
	if onlyIfMissing {
		if _, ok := a.subnets[listName]; ok {
			return false
		}
	}
	a.snapshotting[listName] = true
	a.lists[listName] = true
	return true
}

func (a *addressCache) releaseSnapshot(listName string) {
	a.mu.Lock()
	delete(a.snapshotting, listName)
	a.mu.Unlock()
}

// restoreShrinkRatio is the share of a list that has to disappear between two
// snapshots before we treat it as cleared rather than as ordinary churn.
const restoreShrinkRatio = 3 // one third

// applySnapshot reconciles what we know about listName with what the router
// just reported and returns the entries worth putting back.
//
// A restore is considered only when the list lost at least a third of the
// entries it had at the previous snapshot: that is a reboot, a restored config
// or a manual flush, not entries timing out one by one. Comparing sizes rather
// than looking for an empty list matters because the forwarder may have written
// fresh addresses into the list between the clear and this check.
//
// Of the missing entries, only those whose timeout was not yet due are put
// back, so a restore never resurrects an address the router was right to drop.
// Entries queued for a restore stay in the cache with their id cleared, so live
// traffic re-adds them too and a failed restore is retried on the next
// snapshot. Anything else that went missing is simply forgotten and gets
// re-added the next time its domain is resolved.
func (a *addressCache) applySnapshot(listName string, entries []listEntry) []listEntry {
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	reported := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.address != "" {
			reported[entry.address] = true
		}
	}

	type missingEntry struct {
		key   string
		entry listEntry
	}
	var missing []missingEntry
	for key, cached := range a.entries {
		keyList, address, ok := splitCacheKey(key)
		if !ok || keyList != listName || reported[address] {
			continue
		}
		// A write in flight has not reached the router yet; not a disappearance.
		if a.pending[key] {
			continue
		}
		if cached.expiredBy(now) {
			delete(a.entries, key)
			continue
		}
		missing = append(missing, missingEntry{
			key: key,
			entry: listEntry{
				address: address,
				comment: cached.comment,
				timeout: cached.restoreTimeout(now),
			},
		})
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].entry.address < missing[j].entry.address })

	previous := a.lastSize[listName]
	current := len(entries)
	cleared := previous > 0 && (previous-current)*restoreShrinkRatio >= previous

	var restore []listEntry
	for _, item := range missing {
		if !cleared {
			delete(a.entries, item.key)
			continue
		}
		cached := a.entries[item.key]
		cached.id = ""
		a.entries[item.key] = cached
		restore = append(restore, item.entry)
	}

	// Remember the size the list should have once the restore lands, so a
	// restore that fails is still seen as a shrink next time and retried.
	a.lastSize[listName] = current + len(restore)

	subnets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if entry.address == "" {
			continue
		}
		if entry.id != "" {
			timeout, known := parseRouterOSDuration(entry.timeout)
			a.entries[cacheKey(listName, entry.address)] = cachedEntry{
				id:         entry.id,
				comment:    entry.comment,
				timeout:    timeout,
				hasTimeout: known && timeout > 0,
				observedAt: now,
			}
		}
		if ipNet := parseAddressCIDR(entry.address); ipNet != nil {
			subnets = append(subnets, ipNet)
		}
	}
	a.subnets[listName] = subnets
	a.lists[listName] = true

	return restore
}

func (a *addressCache) lookup(key string) (cachedEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.entries[key]
	return entry, ok && entry.id != ""
}

func (a *addressCache) store(key string, entry cachedEntry) {
	if entry.id == "" {
		return
	}
	if entry.observedAt.IsZero() {
		entry.observedAt = time.Now()
	}
	a.mu.Lock()
	a.entries[key] = entry
	a.mu.Unlock()
}

// claim marks key as being written. It returns false when another goroutine is
// already writing the same address.
func (a *addressCache) claim(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending[key] {
		return false
	}
	a.pending[key] = true
	return true
}

func (a *addressCache) release(key string) {
	a.mu.Lock()
	delete(a.pending, key)
	a.mu.Unlock()
}

// coveredBySubnet reports whether the list already holds a CIDR entry covering
// address, in which case adding the single IP would be redundant.
func (a *addressCache) coveredBySubnet(listName, address string) bool {
	ip := parseAddressIP(address)
	if ip == nil {
		return false
	}
	a.mu.Lock()
	subnets := a.subnets[listName]
	a.mu.Unlock()
	for _, subnet := range subnets {
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *addressCache) listNames() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.lists))
	for listName := range a.lists {
		out = append(out, listName)
	}
	return out
}

// needsTTLRefresh reports whether an entry's timeout is close enough to expiry
// to be worth rewriting. Entries with plenty of time left are skipped, which
// removes most of the periodic write traffic to the router.
func needsTTLRefresh(entry cachedEntry, wanted string) bool {
	left, known := entry.remaining()
	if !known {
		return true
	}
	want, ok := parseRouterOSDuration(wanted)
	if !ok || want <= 0 {
		return true
	}
	return left <= want/2
}

// normalizeListNames trims, dedupes and drops empties, keeping input order.
func normalizeListNames(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// parseRouterOSDuration understands the timeout formats RouterOS reports and
// accepts: "1h23m45s", "00:05:00", "1d00:05:00", "4w2d", a bare number of
// seconds, and "" / "none" for a permanent entry. The bool is false when the
// value cannot be understood, so callers can fall back to writing the timeout
// unconditionally.
func parseRouterOSDuration(value string) (time.Duration, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "none" {
		return 0, true
	}

	// A trailing "HH:MM:SS" may follow a "1w2d" prefix.
	clock := ""
	if idx := strings.IndexByte(value, ':'); idx >= 0 {
		start := idx
		for start > 0 && isDigit(value[start-1]) {
			start--
		}
		clock = value[start:]
		value = strings.TrimSpace(value[:start])
	}

	var total time.Duration
	if value != "" {
		parsed, ok := parseUnitDuration(value)
		if !ok {
			return 0, false
		}
		total += parsed
	}
	if clock != "" {
		parsed, ok := parseClockDuration(clock)
		if !ok {
			return 0, false
		}
		total += parsed
	}
	return total, true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// formatRouterOSDuration renders a duration in the "1h23m45s" form RouterOS
// accepts for timeout values.
func formatRouterOSDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++ // never round an entry's remaining life down to nothing
	}
	var out strings.Builder
	for _, unit := range []struct {
		suffix  string
		seconds int64
	}{
		{"d", 24 * 60 * 60},
		{"h", 60 * 60},
		{"m", 60},
	} {
		if amount := seconds / unit.seconds; amount > 0 {
			fmt.Fprintf(&out, "%d%s", amount, unit.suffix)
			seconds -= amount * unit.seconds
		}
	}
	if seconds > 0 || out.Len() == 0 {
		fmt.Fprintf(&out, "%ds", seconds)
	}
	return out.String()
}

// parseUnitDuration reads "1w2d3h4m5s" style values. A bare number is seconds.
func parseUnitDuration(value string) (time.Duration, bool) {
	units := map[byte]time.Duration{
		'w': 7 * 24 * time.Hour,
		'd': 24 * time.Hour,
		'h': time.Hour,
		'm': time.Minute,
		's': time.Second,
	}
	var total time.Duration
	for i := 0; i < len(value); {
		start := i
		for i < len(value) && isDigit(value[i]) {
			i++
		}
		if start == i {
			return 0, false
		}
		amount, err := strconv.Atoi(value[start:i])
		if err != nil {
			return 0, false
		}
		if i == len(value) {
			total += time.Duration(amount) * time.Second
			return total, true
		}
		unit, ok := units[value[i]]
		if !ok {
			return 0, false
		}
		total += time.Duration(amount) * unit
		i++
	}
	return total, true
}

// parseClockDuration reads "HH:MM:SS" and "MM:SS".
func parseClockDuration(value string) (time.Duration, bool) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	scale := []time.Duration{time.Hour, time.Minute, time.Second}
	if len(parts) == 2 {
		scale = []time.Duration{time.Minute, time.Second}
	}
	var total time.Duration
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return 0, false
		}
		amount, err := strconv.Atoi(part)
		if err != nil || amount < 0 {
			return 0, false
		}
		total += time.Duration(amount) * scale[i]
	}
	return total, true
}
