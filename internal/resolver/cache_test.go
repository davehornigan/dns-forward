package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func answer(qname string, ttl uint32, ip string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, err := dns.NewRR(dns.Fqdn(qname) + " " + string(rune('0'+ttl/100)) + "00 IN A " + ip)
	if err != nil {
		panic(err)
	}
	rr.Header().Ttl = ttl
	resp.Answer = []dns.RR{rr}
	return resp
}

func query(qname string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	return req
}

func TestCacheRoundTrip(t *testing.T) {
	c := newResponseCache(10, 0)
	req := query("example.com", dns.TypeA)

	if _, ok := c.get(req); ok {
		t.Fatal("expected a miss on an empty cache")
	}
	c.put(req, answer("example.com", 300, "1.2.3.4"))

	got, ok := c.get(req)
	if !ok {
		t.Fatal("expected a hit")
	}
	if len(got.Answer) != 1 || got.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Errorf("unexpected answer %v", got.Answer)
	}
	if got.Id != req.Id {
		t.Errorf("the reply must carry the request id, got %d want %d", got.Id, req.Id)
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 300 {
		t.Errorf("TTL must not grow, got %d", ttl)
	}
}

// A cached answer must not outlive the TTL it was served with.
func TestCacheExpires(t *testing.T) {
	c := newResponseCache(10, 0)
	req := query("example.com", dns.TypeA)
	c.put(req, answer("example.com", 300, "1.2.3.4"))

	c.mu.Lock()
	c.entries[cacheKey(req.Question[0])].Value.(*cacheEntry).expiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()

	if _, ok := c.get(req); ok {
		t.Error("expected an expired entry to miss")
	}
	if c.len() != 0 {
		t.Error("expected the expired entry to be dropped")
	}
}

// The TTL handed to a client counts down, so the client does not cache longer
// than the origin allowed.
func TestCacheCountsDownTTL(t *testing.T) {
	c := newResponseCache(10, 0)
	req := query("example.com", dns.TypeA)
	c.put(req, answer("example.com", 300, "1.2.3.4"))

	c.mu.Lock()
	c.entries[cacheKey(req.Question[0])].Value.(*cacheEntry).expiresAt = time.Now().Add(100 * time.Second)
	c.mu.Unlock()

	got, ok := c.get(req)
	if !ok {
		t.Fatal("expected a hit")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 100 || ttl < 98 {
		t.Errorf("expected roughly 100s left, got %d", ttl)
	}
}

func TestCacheKeyedByType(t *testing.T) {
	c := newResponseCache(10, 0)
	a := query("example.com", dns.TypeA)
	aaaa := query("example.com", dns.TypeAAAA)
	c.put(a, answer("example.com", 300, "1.2.3.4"))

	if _, ok := c.get(aaaa); ok {
		t.Error("an A answer must not be served for an AAAA query")
	}
}

func TestCacheNegativeAnswers(t *testing.T) {
	c := newResponseCache(10, 5*time.Second)
	req := query("nope.example.com", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)

	c.put(req, resp)
	got, ok := c.get(req)
	if !ok {
		t.Fatal("expected NXDOMAIN to be cached")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("unexpected rcode %v", got.Rcode)
	}
}

// A shorter SOA lifetime wins over the configured cap.
func TestCacheNegativeTTLFromSOA(t *testing.T) {
	c := newResponseCache(10, time.Hour)
	req := query("nope.example.com", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	soa, err := dns.NewRR("example.com. 60 IN SOA ns.example.com. root.example.com. 1 2 3 4 30")
	if err != nil {
		t.Fatal(err)
	}
	resp.Ns = []dns.RR{soa}

	if got := c.ttlFor(resp); got != 30*time.Second {
		t.Errorf("expected the SOA minimum of 30s, got %v", got)
	}
}

func TestCacheSkipsFailuresAndZeroTTL(t *testing.T) {
	c := newResponseCache(10, 0)
	req := query("example.com", dns.TypeA)

	failure := new(dns.Msg)
	failure.SetRcode(req, dns.RcodeServerFailure)
	c.put(req, failure)
	if c.len() != 0 {
		t.Error("SERVFAIL must not be cached")
	}

	c.put(req, answer("example.com", 0, "1.2.3.4"))
	if c.len() != 0 {
		t.Error("a zero TTL means do not cache")
	}
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := newResponseCache(2, 0)
	for _, name := range []string{"a.example.com", "b.example.com"} {
		c.put(query(name, dns.TypeA), answer(name, 300, "1.2.3.4"))
	}
	// Touch a so b becomes the least recently used.
	if _, ok := c.get(query("a.example.com", dns.TypeA)); !ok {
		t.Fatal("expected a to be cached")
	}
	c.put(query("c.example.com", dns.TypeA), answer("c.example.com", 300, "1.2.3.4"))

	if c.len() != 2 {
		t.Errorf("expected the cache to stay bounded, got %d", c.len())
	}
	if _, ok := c.get(query("b.example.com", dns.TypeA)); ok {
		t.Error("expected b to be evicted")
	}
	if _, ok := c.get(query("a.example.com", dns.TypeA)); !ok {
		t.Error("expected a to survive")
	}
}

func TestCacheDisabled(t *testing.T) {
	var c *responseCache = newResponseCache(-1, 0)
	if c != nil {
		t.Fatal("expected a nil cache when disabled")
	}
	req := query("example.com", dns.TypeA)
	c.put(req, answer("example.com", 300, "1.2.3.4")) // must not panic
	if _, ok := c.get(req); ok {
		t.Error("a disabled cache must always miss")
	}
}

// The cached copy must not be mutated by whoever received an earlier answer.
func TestCacheReturnsIndependentCopies(t *testing.T) {
	c := newResponseCache(10, 0)
	req := query("example.com", dns.TypeA)
	c.put(req, answer("example.com", 300, "1.2.3.4"))

	first, _ := c.get(req)
	first.Answer[0].Header().Ttl = 1
	first.Answer[0].(*dns.A).A = []byte{9, 9, 9, 9}

	second, ok := c.get(req)
	if !ok {
		t.Fatal("expected a hit")
	}
	if second.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Errorf("the cached entry was mutated: %v", second.Answer[0])
	}
	if second.Answer[0].Header().Ttl == 1 {
		t.Error("the cached TTL was mutated")
	}
}
