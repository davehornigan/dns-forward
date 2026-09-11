package records

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCompileAnswers(t *testing.T) {
	set, err := Compile("example.com", map[string][]string{
		"A":    {"111.111.111.111", "111.111.111.112"},
		"aaaa": {"fe80::1"},
		"TXT":  {"hello world"},
		"MX":   {"10 mail.example.com"},
	}, 0, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	answers := set.Answer("Example.COM.", dns.TypeA)
	if len(answers) != 2 {
		t.Fatalf("expected 2 A records, got %d", len(answers))
	}
	if got := answers[0].Header().Name; got != "Example.COM." {
		t.Errorf("expected the query name echoed, got %q", got)
	}
	if got := answers[0].Header().Ttl; got != uint32(DefaultTTL/time.Second) {
		t.Errorf("expected default TTL, got %d", got)
	}
	if got := answers[0].(*dns.A).A.String(); got != "111.111.111.111" {
		t.Errorf("unexpected address %q", got)
	}

	if got := set.Answer("example.com.", dns.TypeTXT)[0].(*dns.TXT).Txt[0]; got != "hello world" {
		t.Errorf("unexpected TXT %q", got)
	}
	if got := set.Answer("example.com.", dns.TypeMX)[0].(*dns.MX).Mx; got != "mail.example.com." {
		t.Errorf("expected an absolute MX target, got %q", got)
	}
	if got := len(set.Answer("example.com.", dns.TypeANY)); got != 5 {
		t.Errorf("expected all 5 records for ANY, got %d", got)
	}
	if got := set.Answer("example.com.", dns.TypeSRV); got != nil {
		t.Errorf("expected no SRV answer, got %v", got)
	}
}

func TestAnswerRewritesSubdomainName(t *testing.T) {
	set, err := Compile("example.com", map[string][]string{"A": {"1.2.3.4"}}, 0, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	answer := set.Answer("www.example.com.", dns.TypeA)[0]
	if got := answer.Header().Name; got != "www.example.com." {
		t.Errorf("expected the subdomain echoed, got %q", got)
	}
	if got := answer.(*dns.A).A.String(); got != "1.2.3.4" {
		t.Errorf("unexpected address %q", got)
	}
}

func TestAnswerDoesNotMutateStoredRecords(t *testing.T) {
	set, err := Compile("example.com", map[string][]string{"A": {"1.2.3.4"}}, time.Minute, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	set.Answer("other.example.com.", dns.TypeA)[0].Header().Ttl = 1

	answer := set.Answer("", dns.TypeA)[0]
	if got := answer.Header().Name; got != "example.com." {
		t.Errorf("stored name was overwritten: %q", got)
	}
	if got := answer.Header().Ttl; got != 60 {
		t.Errorf("stored TTL was overwritten: %d", got)
	}
}

func TestCompileCNAME(t *testing.T) {
	set, err := Compile("alias.example.com", map[string][]string{"CNAME": {"google.com"}}, 0, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cname := set.CNAME("alias.example.com.")
	if cname == nil {
		t.Fatal("expected a CNAME record")
	}
	if cname.Target != "google.com." {
		t.Errorf("expected an absolute target, got %q", cname.Target)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := map[string]map[string][]string{
		"unknown type":       {"FOO": {"bar"}},
		"invalid value":      {"A": {"not-an-ip"}},
		"empty value":        {"A": {"  "}},
		"cname with sibling": {"CNAME": {"google.com"}, "A": {"1.2.3.4"}},
		"multiple cnames":    {"CNAME": {"google.com", "example.org"}},
		"any type":           {"ANY": {"1.2.3.4"}},
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile("example.com", raw, 0, true); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestCompileEmpty(t *testing.T) {
	set, err := Compile("example.com", nil, 0, true)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if set != nil {
		t.Errorf("expected no set, got %v", set)
	}
}

func TestCompileRejectsSelfCNAME(t *testing.T) {
	for _, target := range []string{"example.com", "example.com.", "EXAMPLE.COM"} {
		_, err := Compile("example.com", map[string][]string{"CNAME": {target}}, 0, true)
		if err == nil {
			t.Errorf("expected a self-referencing CNAME %q to be rejected", target)
		}
	}
	// A different name is still fine.
	if _, err := Compile("example.com", map[string][]string{"CNAME": {"other.example.com"}}, 0, true); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// A rule that serves only subdomains never answers for the domain itself, so
// aliasing every subdomain to the apex is legitimate, not a loop.
func TestCompileAllowsCNAMEToApexForSubdomainRules(t *testing.T) {
	set, err := Compile("example.com", map[string][]string{"CNAME": {"example.com"}}, 0, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cname := set.CNAME("www.example.com.")
	if cname == nil || cname.Target != "example.com." {
		t.Errorf("unexpected record %v", cname)
	}
	if cname.Hdr.Name != "www.example.com." {
		t.Errorf("expected the answer to carry the queried name, got %q", cname.Hdr.Name)
	}
}
