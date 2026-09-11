package resolver

import (
	"fmt"
	"testing"

	"github.com/davehornigan/dns-forward/internal/config"
	"github.com/davehornigan/dns-forward/internal/records"
	"github.com/miekg/dns"
)

func intPtr(v int) *int { return &v }

func TestRuleCoversName(t *testing.T) {
	tests := []struct {
		name string
		rule config.DomainRule
		want map[string]bool
	}{
		{
			name: "exact only",
			rule: config.DomainRule{Domain: "example.com"},
			want: map[string]bool{
				"example.com":     true,
				"www.example.com": false,
				"example.org":     false,
				"notexample.com":  false,
			},
		},
		{
			name: "subdomains unlimited",
			rule: config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains},
			want: map[string]bool{
				"example.com":       true,
				"www.example.com":   true,
				"a.b.example.com":   true,
				"badexample.com":    false,
				"example.com.evil":  false,
				"www.example.co.uk": false,
			},
		},
		{
			name: "subdomains with maxDepth",
			rule: config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, MaxDepth: intPtr(1)},
			want: map[string]bool{
				"example.com":     true,
				"www.example.com": true,
				"a.b.example.com": false,
			},
		},
		{
			name: "subdomains only",
			rule: config.DomainRule{Domain: "example.com", MatchingType: config.MatchSubdomainsOnly},
			want: map[string]bool{
				"example.com":     false,
				"www.example.com": true,
				"a.b.example.com": true,
				"example.org":     false,
			},
		},
		{
			name: "subdomains only with maxDepth",
			rule: config.DomainRule{Domain: "example.com", MatchingType: config.MatchSubdomainsOnly, MaxDepth: intPtr(1)},
			want: map[string]bool{
				"example.com":     false,
				"www.example.com": true,
				"a.b.example.com": false,
			},
		},
		{
			name: "zero value behaves as exact",
			rule: config.DomainRule{Domain: "example.com"},
			want: map[string]bool{"example.com": true, "www.example.com": false},
		},
		{
			name: "empty domain",
			rule: config.DomainRule{MatchingType: config.MatchWithSubdomains},
			want: map[string]bool{"": false, "example.com": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, want := range tt.want {
				if got := ruleCoversName(tt.rule, name); got != want {
					t.Errorf("ruleCoversName(%q) = %v, want %v", name, got, want)
				}
			}
		})
	}
}

// An exact rule beats a subdomain rule no matter which is declared first.
func TestMatchDomainPrefersExactRule(t *testing.T) {
	exact := config.DomainRule{Domain: "api.example.com", ListName: "exact"}
	wildcard := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, ListName: "wildcard"}

	orders := map[string][]config.DomainRule{
		"wildcard declared first": {wildcard, exact},
		"exact declared first":    {exact, wildcard},
	}
	for name, rules := range orders {
		t.Run(name, func(t *testing.T) {
			res := New(nil, nil, rules, nil, nil, nil, nil, 0, 0, 0, false, nil)

			match, rule, _ := res.matchDomain("api.example.com.")
			if !match || rule.ListName != "exact" {
				t.Errorf("expected the exact rule for api.example.com, got %q", rule.ListName)
			}
			// Names the exact rule does not name still fall to the wildcard.
			for _, qname := range []string{"www.example.com.", "example.com."} {
				match, rule, _ = res.matchDomain(qname)
				if !match || rule.ListName != "wildcard" {
					t.Errorf("expected the wildcard rule for %s, got %q", qname, rule.ListName)
				}
			}
		})
	}
}

// Exactness wins over declaration order, but a deeper subdomain rule does not:
// among subdomain rules the config order still decides.
func TestMatchDomainKeepsOrderAmongSubdomainRules(t *testing.T) {
	broad := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, ListName: "broad"}
	deep := config.DomainRule{Domain: "api.example.com", MatchingType: config.MatchWithSubdomains, ListName: "deep"}

	res := New(nil, nil, []config.DomainRule{broad, deep}, nil, nil, nil, nil, 0, 0, 0, false, nil)
	if _, rule, _ := res.matchDomain("v1.api.example.com."); rule.ListName != "broad" {
		t.Errorf("expected the first subdomain rule, got %q", rule.ListName)
	}
	// The exact name of the deeper rule still reaches it.
	if _, rule, _ := res.matchDomain("api.example.com."); rule.ListName != "deep" {
		t.Errorf("expected the exact rule, got %q", rule.ListName)
	}
}

// A subdomainsOnly rule must not answer for the domain it is named after, even
// though it is the only rule naming it.
func TestMatchDomainSubdomainsOnlySkipsApex(t *testing.T) {
	rules := []config.DomainRule{
		{Domain: "example.com", MatchingType: config.MatchSubdomainsOnly, ListName: "subs"},
	}
	res := New(nil, nil, rules, nil, nil, nil, nil, 0, 0, 0, false, nil)

	if match, _, _ := res.matchDomain("example.com."); match {
		t.Error("expected the apex to be unmatched")
	}
	if match, rule, _ := res.matchDomain("www.example.com."); !match || rule.ListName != "subs" {
		t.Errorf("expected the subdomain to match, got (%v, %q)", match, rule.ListName)
	}
}

// An exact rule and a subdomainsOnly rule for the same domain split the work.
func TestMatchDomainSubdomainsOnlyAlongsideExact(t *testing.T) {
	rules := []config.DomainRule{
		{Domain: "example.com", MatchingType: config.MatchSubdomainsOnly, ListName: "subs"},
		{Domain: "example.com", MatchingType: config.MatchExact, ListName: "apex"},
	}
	res := New(nil, nil, rules, nil, nil, nil, nil, 0, 0, 0, false, nil)

	if _, rule, index := res.matchDomain("example.com."); rule.ListName != "apex" || index != 1 {
		t.Errorf("expected the exact rule for the apex, got (%q, %d)", rule.ListName, index)
	}
	if _, rule, index := res.matchDomain("www.example.com."); rule.ListName != "subs" || index != 0 {
		t.Errorf("expected the subdomains rule, got (%q, %d)", rule.ListName, index)
	}
}

// Among several rules naming the same domain, the first one still wins.
func TestMatchDomainFirstExactRuleWins(t *testing.T) {
	rules := []config.DomainRule{
		{Domain: "", ListName: "ignored"},
		{Domain: "example.com", ListName: "first"},
		{Domain: "example.com", ListName: "second"},
	}
	res := New(nil, nil, rules, nil, nil, nil, nil, 0, 0, 0, false, nil)
	match, rule, index := res.matchDomain("example.com.")
	if !match || rule.ListName != "first" || index != 1 {
		t.Errorf("matchDomain = (%v, %q, %d), want (true, \"first\", 1)", match, rule.ListName, index)
	}
}

// config.Load normalizes domains, but the index must not depend on that.
func TestIndexExactRulesNormalizes(t *testing.T) {
	index := indexExactRules([]config.DomainRule{
		{Domain: " Example.COM. "},
		{Domain: ""},
		{Domain: "other.org"},
	})
	if got, ok := index["example.com"]; !ok || got != 0 {
		t.Errorf("expected example.com at 0, got (%d, %v)", got, ok)
	}
	if _, ok := index[""]; ok {
		t.Error("expected empty domains to be skipped")
	}
	if len(index) != 2 {
		t.Errorf("unexpected index %v", index)
	}
}

func TestMatchDomainFallsThroughToBroaderRule(t *testing.T) {
	narrow := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, MaxDepth: intPtr(1), ListName: "narrow"}
	broad := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, ListName: "broad"}
	res := New(nil, nil, []config.DomainRule{narrow, broad}, nil, nil, nil, nil, 0, 0, 0, false, nil)

	tests := map[string]struct {
		match bool
		list  string
		index int
	}{
		"example.com.":       {true, "narrow", 0},
		"www.example.com.":   {true, "narrow", 0},
		"a.b.example.com.":   {true, "broad", 1},
		"a.b.c.example.com.": {true, "broad", 1},
		"example.org.":       {false, "", -1},
	}
	for qname, want := range tests {
		match, rule, index := res.matchDomain(qname)
		if match != want.match || rule.ListName != want.list || index != want.index {
			t.Errorf("matchDomain(%q) = (%v, %q, %d), want (%v, %q, %d)",
				qname, match, rule.ListName, index, want.match, want.list, want.index)
		}
	}
}

func TestMatchDomainWithoutRulesMatchesEverything(t *testing.T) {
	res := New(nil, nil, nil, nil, nil, nil, nil, 0, 0, 0, false, nil)
	match, _, index := res.matchDomain("anything.example.org.")
	if !match || index != -1 {
		t.Errorf("expected a catch-all match with index -1, got (%v, %d)", match, index)
	}
}

func newResolverWithRecords(t *testing.T, rule config.DomainRule, raw map[string][]string) (*Resolver, *records.Set) {
	t.Helper()
	set, err := records.Compile(rule.Domain, raw, 0, true)
	if err != nil {
		t.Fatalf("compile records: %v", err)
	}
	res := New(nil, nil, []config.DomainRule{rule}, nil, map[int]*records.Set{0: set}, nil, nil, 0, 0, 0, false, nil)
	return res, set
}

func question(qname string, qtype uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	return req
}

func TestStaticResponseSubdomains(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, MaxDepth: intPtr(1)}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"A": {"111.111.111.111"}})

	t.Run("exact name", func(t *testing.T) {
		resp, ch, ok := res.staticResponse(question("example.com", dns.TypeA), rule, set, nil)
		if !ok {
			t.Fatal("expected a static answer")
		}
		if !resp.Authoritative || len(resp.Answer) != 1 {
			t.Fatalf("unexpected response: %v", resp)
		}
		if got := resp.Answer[0].Header().Name; got != "example.com." {
			t.Errorf("unexpected name %q", got)
		}
		if ch == nil {
			t.Error("expected an output channel")
		}
	})

	t.Run("subdomain within depth", func(t *testing.T) {
		resp, _, ok := res.staticResponse(question("www.example.com", dns.TypeA), rule, set, nil)
		if !ok {
			t.Fatal("expected a static answer for the subdomain")
		}
		if got := resp.Answer[0].Header().Name; got != "www.example.com." {
			t.Errorf("expected the answer to echo the subdomain, got %q", got)
		}
	})

	t.Run("subdomain beyond depth", func(t *testing.T) {
		if _, _, ok := res.staticResponse(question("a.b.example.com", dns.TypeA), rule, set, nil); ok {
			t.Error("expected the query to be forwarded past maxDepth")
		}
	})

	t.Run("unrelated name", func(t *testing.T) {
		if _, _, ok := res.staticResponse(question("example.org", dns.TypeA), rule, set, nil); ok {
			t.Error("expected an unrelated name to be forwarded")
		}
	})

	t.Run("unknown type falls through", func(t *testing.T) {
		if _, _, ok := res.staticResponse(question("example.com", dns.TypeMX), rule, set, nil); ok {
			t.Error("expected an unconfigured type to be forwarded")
		}
	})
}

func TestStaticResponseExactRuleIgnoresSubdomains(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com"}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"A": {"111.111.111.111"}})

	if _, _, ok := res.staticResponse(question("www.example.com", dns.TypeA), rule, set, nil); ok {
		t.Error("expected subdomains to be forwarded by an exact rule")
	}
}

func TestStaticResponseRecordsOnly(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, RecordsOnly: true}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"A": {"111.111.111.111"}})

	for _, qname := range []string{"example.com", "www.example.com"} {
		resp, ch, ok := res.staticResponse(question(qname, dns.TypeAAAA), rule, set, nil)
		if !ok {
			t.Fatalf("expected %q to be answered locally", qname)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
			t.Errorf("expected NODATA for %q, got %v", qname, resp)
		}
		if ch != nil {
			t.Errorf("expected no outputs for a NODATA answer to %q", qname)
		}
	}
}

// A CNAME whose target is the queried name is a loop; it must not be served.
// The config check cannot catch this one: the rule covers subdomains, so the
// record answers under a name that only equals the target at query time.
func TestStaticResponseSkipsSelfCNAME(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"CNAME": {"www.example.com"}})

	// Querying the loop name: nothing usable, so the query is forwarded.
	if _, _, ok := res.staticResponse(question("www.example.com", dns.TypeA), rule, set, nil); ok {
		t.Error("expected a self-referencing CNAME to be skipped for A")
	}
	if _, _, ok := res.staticResponse(question("www.example.com", dns.TypeCNAME), rule, set, nil); ok {
		t.Error("expected a self-referencing CNAME to be skipped for CNAME")
	}

	// Any other name under the rule still gets the alias.
	resp, _, ok := res.staticResponse(question("api.example.com", dns.TypeCNAME), rule, set, nil)
	if !ok || len(resp.Answer) != 1 {
		t.Fatalf("expected the alias for a different name, got %v", resp)
	}
	if target := resp.Answer[0].(*dns.CNAME).Target; target != "www.example.com." {
		t.Errorf("unexpected target %q", target)
	}
}

// With recordsOnly the loop still must not be served, and the query must not
// escape upstream either.
func TestStaticResponseSelfCNAMEWithRecordsOnly(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com", MatchingType: config.MatchWithSubdomains, RecordsOnly: true}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"CNAME": {"www.example.com"}})

	resp, ch, ok := res.staticResponse(question("www.example.com", dns.TypeA), rule, set, nil)
	if !ok {
		t.Fatal("expected recordsOnly to keep answering locally")
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("expected NODATA instead of a loop, got %v", resp)
	}
	if ch != nil {
		t.Error("expected no outputs for a NODATA answer")
	}
}

func TestStaticResponseIgnoresNonINETClass(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com"}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"A": {"111.111.111.111"}})

	req := question("example.com", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS
	if _, _, ok := res.staticResponse(req, rule, set, nil); ok {
		t.Error("expected non-INET classes to be forwarded")
	}
}

func benchmarkRules(n int) []config.DomainRule {
	rules := make([]config.DomainRule, 0, n+1)
	for i := 0; i < n; i++ {
		rules = append(rules, config.DomainRule{Domain: fmt.Sprintf("domain%d.example", i)})
	}
	rules = append(rules, config.DomainRule{Domain: "catchall.example", MatchingType: config.MatchWithSubdomains})
	return rules
}

// The exact hit is the common case and must not depend on list length.
func BenchmarkMatchDomainExact(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			res := New(nil, nil, benchmarkRules(n), nil, nil, nil, nil, 0, 0, 0, false, nil)
			qname := fmt.Sprintf("domain%d.example.", n-1)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res.matchDomain(qname)
			}
		})
	}
}

func BenchmarkMatchDomainSubdomain(b *testing.B) {
	for _, n := range []int{10, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			res := New(nil, nil, benchmarkRules(n), nil, nil, nil, nil, 0, 0, 0, false, nil)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res.matchDomain("www.catchall.example.")
			}
		})
	}
}
