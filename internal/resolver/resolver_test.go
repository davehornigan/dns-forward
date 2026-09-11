package resolver

import (
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
			rule: config.DomainRule{Domain: "example.com", MatchSubDomains: true},
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
			rule: config.DomainRule{Domain: "example.com", MatchSubDomains: true, MaxDepth: intPtr(1)},
			want: map[string]bool{
				"example.com":     true,
				"www.example.com": true,
				"a.b.example.com": false,
			},
		},
		{
			name: "empty domain",
			rule: config.DomainRule{MatchSubDomains: true},
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

func TestMatchDomainFallsThroughToBroaderRule(t *testing.T) {
	narrow := config.DomainRule{Domain: "example.com", MatchSubDomains: true, MaxDepth: intPtr(1), ListName: "narrow"}
	broad := config.DomainRule{Domain: "example.com", MatchSubDomains: true, ListName: "broad"}
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
	set, err := records.Compile(rule.Domain, raw, 0)
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
	rule := config.DomainRule{Domain: "example.com", MatchSubDomains: true, MaxDepth: intPtr(1)}
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
		t.Error("expected subdomains to be forwarded without matchSubDomains")
	}
}

func TestStaticResponseRecordsOnly(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com", MatchSubDomains: true, RecordsOnly: true}
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

func TestStaticResponseIgnoresNonINETClass(t *testing.T) {
	rule := config.DomainRule{Domain: "example.com"}
	res, set := newResolverWithRecords(t, rule, map[string][]string{"A": {"111.111.111.111"}})

	req := question("example.com", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS
	if _, _, ok := res.staticResponse(req, rule, set, nil); ok {
		t.Error("expected non-INET classes to be forwarded")
	}
}
