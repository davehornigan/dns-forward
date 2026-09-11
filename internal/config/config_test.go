package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadWithoutIncludes(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
server:
  listenAddr: ":53"
upstreams:
  - udp://1.1.1.1:53
domains:
  - domain: Example.COM.
outputs:
  - type: file
    id: f
    path: ./data
    listName: l
`)
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0].Domain != "example.com" {
		t.Errorf("expected the domain lowercased and de-dotted, got %+v", cfg.Domains)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0] != main {
		t.Errorf("unexpected sources %v", cfg.Sources)
	}
}

// Files named after a section hold that section's bare value.
func TestLoadMergesSectionFiles(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
include:
  - conf.d/*.yaml
server:
  listenAddr: ":53"
  timeout: 5s
upstreams:
  - udp://1.1.1.1:53
`)
	writeFile(t, dir, "conf.d/domains.yaml", `
- domain: google.com
  matchingType: withSubdomains
- domain: openai.com
`)
	writeFile(t, dir, "conf.d/outputs.yaml", `
- type: file
  id: f
  path: ./data
  listName: l
`)
	writeFile(t, dir, "conf.d/server.yaml", `
timeout: 9s
debug: true
`)

	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Domains) != 2 || cfg.Domains[0].Domain != "google.com" || cfg.Domains[1].Domain != "openai.com" {
		t.Errorf("unexpected domains %+v", cfg.Domains)
	}
	if cfg.Domains[0].MatchingType != MatchWithSubdomains {
		t.Errorf("expected matchingType to survive the merge, got %q", cfg.Domains[0].MatchingType)
	}
	if cfg.Domains[1].MatchingType != MatchExact {
		t.Errorf("expected exact matching by default, got %q", cfg.Domains[1].MatchingType)
	}
	if len(cfg.Outputs) != 1 || cfg.Outputs[0].Type != "file" || cfg.Outputs[0].File == nil {
		t.Errorf("unexpected outputs %+v", cfg.Outputs)
	}
	// server.yaml overrides timeout but leaves listenAddr from the main file.
	if cfg.Server.ListenAddr != ":53" {
		t.Errorf("expected listenAddr to survive, got %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.Timeout != 9*time.Second {
		t.Errorf("expected the included file to win, got %v", cfg.Server.Timeout)
	}
	if !cfg.Server.Debug {
		t.Error("expected debug from the included file")
	}
	if len(cfg.Sources) != 4 {
		t.Errorf("expected 4 sources, got %v", cfg.Sources)
	}
}

// An included list is appended to what the main config already declares.
func TestLoadAppendsToMainConfigList(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
include: [upstreams.yaml]
upstreams:
  - udp://1.1.1.1:53
outputs:
  - type: file
    id: f
    path: ./data
    listName: l
`)
	writeFile(t, dir, "upstreams.yaml", "- tls://dns.google\n")

	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Upstreams) != 2 || cfg.Upstreams[0] != "udp://1.1.1.1:53" || cfg.Upstreams[1] != "tls://dns.google" {
		t.Errorf("expected upstreams to be appended in order, got %v", cfg.Upstreams)
	}
}

// Several files may contribute to the same list; numeric prefixes order them.
func TestLoadAppendsAcrossFilesInOrder(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
include: ["conf.d/*.yaml"]
upstreams: [udp://1.1.1.1:53]
outputs:
  - type: file
    id: f
    path: ./data
    listName: l
`)
	writeFile(t, dir, "conf.d/20-domains.yaml", "- domain: second.com\n")
	writeFile(t, dir, "conf.d/10-domains.yaml", "- domain: first.com\n")

	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Domains) != 2 || cfg.Domains[0].Domain != "first.com" || cfg.Domains[1].Domain != "second.com" {
		t.Errorf("expected numeric prefixes to order the merge, got %+v", cfg.Domains)
	}
}

func TestSectionForFile(t *testing.T) {
	tests := map[string]string{
		"domains.yaml":            "domains",
		"10-domains.yaml":         "domains",
		"05_outputs.yaml":         "outputs",
		"fallback_upstreams.yaml": "fallbackUpstreams",
		"fallback-upstreams.yaml": "fallbackUpstreams",
		"fallbackUpstreams.yaml":  "fallbackUpstreams",
		"Server.YAML":             "server",
	}
	for name, want := range tests {
		got, ok := sectionForFile(filepath.Join("/conf.d", name))
		if !ok || got != want {
			t.Errorf("sectionForFile(%q) = (%q, %v), want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"whatever.yaml", "domains.yml", "domains.json", "domains"} {
		if _, ok := sectionForFile(filepath.Join("/conf.d", name)); ok {
			t.Errorf("expected %q to be rejected", name)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	t.Run("file not named after a section", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "config.yaml", "include: [extra.yaml]\nupstreams: [udp://1.1.1.1:53]\n")
		writeFile(t, dir, "extra.yaml", "- domain: example.com\n")
		_, err := Load(main)
		if err == nil || !strings.Contains(err.Error(), "name an included file after the section") {
			t.Errorf("expected a naming error, got %v", err)
		}
	})

	t.Run("yml extension is rejected", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "config.yaml", "include: [domains.yml]\nupstreams: [udp://1.1.1.1:53]\n")
		writeFile(t, dir, "domains.yml", "- domain: example.com\n")
		_, err := Load(main)
		if err == nil || !strings.Contains(err.Error(), "name an included file after the section") {
			t.Errorf("expected .yml to be rejected, got %v", err)
		}
	})

	t.Run("missing include", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "config.yaml", "include: [nope.yaml]\nupstreams: [udp://1.1.1.1:53]\n")
		_, err := Load(main)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected a missing-file error, got %v", err)
		}
	})

	t.Run("empty glob is fine", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "config.yaml", "include: [\"conf.d/*.yaml\"]\nupstreams: [udp://1.1.1.1:53]\n")
		if _, err := Load(main); err != nil {
			t.Errorf("an empty conf.d should not be an error, got %v", err)
		}
	})

	t.Run("type mismatch", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "config.yaml", "include: [domains.yaml]\ndomains: []\n")
		writeFile(t, dir, "domains.yaml", "key: value\n")
		_, err := Load(main)
		if err == nil || !strings.Contains(err.Error(), "cannot merge") {
			t.Errorf("expected a merge type error, got %v", err)
		}
	})

	t.Run("empty main config", func(t *testing.T) {
		dir := t.TempDir()
		main := writeFile(t, dir, "config.yaml", "")
		if _, err := Load(main); err == nil {
			t.Error("expected an error for an empty config")
		}
	})
}

func TestStringListAcceptsScalarAndSequence(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
upstreams: [udp://1.1.1.1:53]
outputs:
  - type: file
    id: f
    path: ./data
    listName: l
domains:
  - domain: example.com
    records:
      A: 1.2.3.4
      AAAA: ["fe80::1", "fe80::2"]
`)
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	records := cfg.Domains[0].Records
	if len(records["A"]) != 1 || records["A"][0] != "1.2.3.4" {
		t.Errorf("expected a scalar to become a one-item list, got %v", records["A"])
	}
	if len(records["AAAA"]) != 2 {
		t.Errorf("expected both AAAA values, got %v", records["AAAA"])
	}
}

func TestParseMatchingType(t *testing.T) {
	accepted := map[string]MatchingType{
		"":                 MatchExact,
		"exact":            MatchExact,
		"EXACT":            MatchExact,
		"withSubdomains":   MatchWithSubdomains,
		"with_subdomains":  MatchWithSubdomains,
		"WITH-SUBDOMAINS":  MatchWithSubdomains,
		"subdomainsOnly":   MatchSubdomainsOnly,
		"subdomains_only":  MatchSubdomainsOnly,
		" subdomainsonly ": MatchSubdomainsOnly,
	}
	for input, want := range accepted {
		got, err := ParseMatchingType(input)
		if err != nil || got != want {
			t.Errorf("ParseMatchingType(%q) = (%q, %v), want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"wildcard", "subdomains", "static_only", "nope"} {
		if _, err := ParseMatchingType(input); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}

func TestMatchingTypePredicates(t *testing.T) {
	tests := []struct {
		value      MatchingType
		exact      bool
		subdomains bool
	}{
		{"", true, false},
		{MatchExact, true, false},
		{MatchWithSubdomains, true, true},
		{MatchSubdomainsOnly, false, true},
	}
	for _, tt := range tests {
		if got := tt.value.MatchesExactly(); got != tt.exact {
			t.Errorf("%q.MatchesExactly() = %v, want %v", tt.value, got, tt.exact)
		}
		if got := tt.value.MatchesSubdomains(); got != tt.subdomains {
			t.Errorf("%q.MatchesSubdomains() = %v, want %v", tt.value, got, tt.subdomains)
		}
	}
}

func TestLoadRejectsRemovedMatchSubDomains(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
upstreams: [udp://1.1.1.1:53]
outputs:
  - {type: file, id: f, path: ./data, listName: l}
domains:
  - domain: example.com
    matchSubDomains: true
`)
	_, err := Load(main)
	if err == nil {
		t.Fatal("expected the removed field to be rejected")
	}
	for _, want := range []string{"matchSubDomains", "matchingType", "withSubdomains"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestLoadRejectsUnknownMatchingType(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
upstreams: [udp://1.1.1.1:53]
outputs:
  - {type: file, id: f, path: ./data, listName: l}
domains:
  - domain: example.com
    matchingType: wildcard
`)
	_, err := Load(main)
	if err == nil || !strings.Contains(err.Error(), "unsupported matchingType") {
		t.Errorf("expected an enum error, got %v", err)
	}
}

func TestRecordsRejectCNAMEList(t *testing.T) {
	dir := t.TempDir()
	write := func(records string) error {
		main := writeFile(t, dir, "config.yaml", `
upstreams: [udp://1.1.1.1:53]
outputs:
  - {type: file, id: f, path: ./data, listName: l}
domains:
  - domain: alias.example.com
    records:
`+records)
		_, err := Load(main)
		return err
	}

	for _, form := range []string{
		"      CNAME: [target.example.com]\n",
		"      CNAME:\n        - target.example.com\n",
		"      cname: [target.example.com]\n",
	} {
		err := write(form)
		if err == nil || !strings.Contains(err.Error(), "takes a single value") {
			t.Errorf("expected a list CNAME to be rejected for %q, got %v", form, err)
		}
	}

	if err := write("      CNAME: target.example.com\n"); err != nil {
		t.Errorf("expected the scalar form to be accepted, got %v", err)
	}
}

// Only CNAME is restricted; the rest may repeat on a name.
func TestRecordsAllowMultipleTXT(t *testing.T) {
	dir := t.TempDir()
	main := writeFile(t, dir, "config.yaml", `
upstreams: [udp://1.1.1.1:53]
outputs:
  - {type: file, id: f, path: ./data, listName: l}
domains:
  - domain: example.com
    records:
      TXT:
        - "v=spf1 -all"
        - "google-site-verification=abc"
      A: [1.2.3.4, 5.6.7.8]
`)
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	records := cfg.Domains[0].Records
	if len(records["TXT"]) != 2 {
		t.Errorf("expected both TXT values, got %v", records["TXT"])
	}
	if len(records["A"]) != 2 {
		t.Errorf("expected both A values, got %v", records["A"])
	}
}
