package resolver

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// DefaultCacheSize is the number of responses kept when the config does not
	// say otherwise. Entries are small, and the cache is what keeps a repeated
	// query from costing an upstream round trip.
	DefaultCacheSize = 10000
	// DefaultNegativeTTL caps how long NXDOMAIN and empty answers are kept.
	DefaultNegativeTTL = 30 * time.Second
)

type cacheEntry struct {
	key       string
	resp      *dns.Msg
	expiresAt time.Time
}

// responseCache keeps upstream answers until their TTL runs out, with an LRU
// bound so it cannot grow without limit.
type responseCache struct {
	mu          sync.Mutex
	entries     map[string]*list.Element
	order       *list.List // front is most recently used
	maxEntries  int
	negativeTTL time.Duration
}

// newResponseCache returns nil when caching is disabled, so callers can treat a
// nil cache as a permanent miss.
func newResponseCache(maxEntries int, negativeTTL time.Duration) *responseCache {
	if maxEntries < 0 {
		return nil
	}
	if maxEntries == 0 {
		maxEntries = DefaultCacheSize
	}
	if negativeTTL < 0 {
		negativeTTL = 0
	} else if negativeTTL == 0 {
		negativeTTL = DefaultNegativeTTL
	}
	return &responseCache{
		entries:     make(map[string]*list.Element, maxEntries),
		order:       list.New(),
		maxEntries:  maxEntries,
		negativeTTL: negativeTTL,
	}
}

func cacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

// get returns a copy of the cached answer with its TTLs counted down, or false
// when nothing usable is cached.
func (c *responseCache) get(req *dns.Msg) (*dns.Msg, bool) {
	if c == nil || len(req.Question) == 0 {
		return nil, false
	}
	key := cacheKey(req.Question[0])

	c.mu.Lock()
	element, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	entry := element.Value.(*cacheEntry)
	remaining := time.Until(entry.expiresAt)
	if remaining <= 0 {
		c.removeLocked(element)
		c.mu.Unlock()
		return nil, false
	}
	c.order.MoveToFront(element)
	resp := entry.resp.Copy()
	c.mu.Unlock()

	resp.Id = req.Id
	resp.Compress = req.Compress
	resp.Question = req.Question
	countDownTTLs(resp, uint32(remaining/time.Second))
	return resp, true
}

// put stores a response if it is worth caching. Failures are not cached: a
// SERVFAIL now says nothing about the next second.
func (c *responseCache) put(req *dns.Msg, resp *dns.Msg) {
	if c == nil || resp == nil || len(req.Question) == 0 {
		return
	}
	ttl := c.ttlFor(resp)
	if ttl <= 0 {
		return
	}
	key := cacheKey(req.Question[0])
	stored := resp.Copy()

	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*cacheEntry)
		entry.resp = stored
		entry.expiresAt = time.Now().Add(ttl)
		c.order.MoveToFront(element)
		return
	}
	element := c.order.PushFront(&cacheEntry{key: key, resp: stored, expiresAt: time.Now().Add(ttl)})
	c.entries[key] = element
	for c.order.Len() > c.maxEntries {
		c.removeLocked(c.order.Back())
	}
}

func (c *responseCache) removeLocked(element *list.Element) {
	if element == nil {
		return
	}
	c.order.Remove(element)
	delete(c.entries, element.Value.(*cacheEntry).key)
}

func (c *responseCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// ttlFor decides how long a response may be reused. Answers carry their own
// TTL; a negative answer borrows the SOA's, bounded by negativeTTL.
func (c *responseCache) ttlFor(resp *dns.Msg) time.Duration {
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return 0
	}
	if len(resp.Answer) > 0 {
		ttl := minAnswerTTL(resp)
		if ttl == 0 {
			return 0 // a zero TTL means "do not cache this"
		}
		return time.Duration(ttl) * time.Second
	}
	negative := c.negativeTTL
	if soa := soaNegativeTTL(resp); soa > 0 && soa < negative {
		negative = soa
	}
	return negative
}

// soaNegativeTTL reads the negative caching TTL from the authority section, as
// the smaller of the SOA's own TTL and its minimum field (RFC 2308).
func soaNegativeTTL(resp *dns.Msg) time.Duration {
	for _, rr := range resp.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return time.Duration(ttl) * time.Second
	}
	return 0
}

// countDownTTLs lowers every TTL in the message to what is actually left, so a
// client never caches an answer for longer than the origin allowed.
func countDownTTLs(resp *dns.Msg, remaining uint32) {
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OPT carries flags in the TTL field, not a lifetime
			}
			if rr.Header().Ttl > remaining {
				rr.Header().Ttl = remaining
			}
		}
	}
}

func minAnswerTTL(resp *dns.Msg) uint32 {
	if resp == nil || len(resp.Answer) == 0 {
		return 0
	}
	minTTL := resp.Answer[0].Header().Ttl
	for _, rr := range resp.Answer[1:] {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}
	return minTTL
}
