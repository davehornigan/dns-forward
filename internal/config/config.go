package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davehornigan/dns-forward/internal/outputs"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Include           []string       `yaml:"include"`
	Upstreams         []string       `yaml:"upstreams"`
	FallbackUpstreams []string       `yaml:"fallbackUpstreams"`
	Domains           []DomainRule   `yaml:"domains"`
	Outputs           []OutputConfig `yaml:"outputs"`
	Server            ServerConfig   `yaml:"server"`

	// Sources lists the files the config was assembled from, main config first.
	Sources []string `yaml:"-"`
}

type ServerConfig struct {
	Debug             bool          `yaml:"debug"`
	ListenAddr        string        `yaml:"listenAddr"`
	Timeout           time.Duration `yaml:"timeout"`
	DNSTimeout        time.Duration `yaml:"dnsTimeout"`
	HTTPTimeout       time.Duration `yaml:"httpTimeout"`
	ExcludeSubnets    []string      `yaml:"excludeSubnets"`
	WriteIPWithPrefix bool          `yaml:"writeIPWithPrefix"`
	ResolveAllOnStart bool          `yaml:"resolveAllDomainsOnStart"`
	CacheSize         *int          `yaml:"cacheSize"`
	NegativeTTL       time.Duration `yaml:"negativeTTL"`
}

type OutputConfig struct {
	Type                  string                               `yaml:"type"`
	Mode                  string                               `yaml:"mode"`
	RosApiAddressList     *outputs.RosApiAddressListConfig     `yaml:"-"`
	RosRestApiAddressList *outputs.RosRestApiAddressListConfig `yaml:"-"`
	File                  *outputs.FileOutputConfig            `yaml:"-"`
	Webhook               *outputs.WebhookConfig               `yaml:"-"`
}

// MatchingType says which names a domain rule applies to.
type MatchingType string

const (
	// MatchExact matches the domain itself and nothing else. The default.
	MatchExact MatchingType = "exact"
	// MatchWithSubdomains matches the domain and its subdomains.
	MatchWithSubdomains MatchingType = "withSubdomains"
	// MatchSubdomainsOnly matches the subdomains but not the domain itself.
	MatchSubdomainsOnly MatchingType = "subdomainsOnly"
)

var matchingTypes = []MatchingType{MatchExact, MatchWithSubdomains, MatchSubdomainsOnly}

// ParseMatchingType accepts the value in any case, with or without separators,
// so "withSubdomains", "with_subdomains" and "WITH-SUBDOMAINS" all work.
func ParseMatchingType(value string) (MatchingType, error) {
	normalized := normalizeEnumValue(value)
	if normalized == "" {
		return MatchExact, nil
	}
	for _, candidate := range matchingTypes {
		if normalizeEnumValue(string(candidate)) == normalized {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("unsupported matchingType %q, expected one of %s", value, joinMatchingTypes())
}

func normalizeEnumValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "_", "")
	return value
}

func joinMatchingTypes() string {
	names := make([]string, 0, len(matchingTypes))
	for _, candidate := range matchingTypes {
		names = append(names, string(candidate))
	}
	return strings.Join(names, ", ")
}

// MatchesExactly reports whether the rule applies to the domain itself. The
// zero value behaves as MatchExact, so a rule built in code without setting the
// field matches its domain rather than nothing.
func (t MatchingType) MatchesExactly() bool {
	return t == "" || t == MatchExact || t == MatchWithSubdomains
}

// MatchesSubdomains reports whether the rule applies to subdomains.
func (t MatchingType) MatchesSubdomains() bool {
	return t == MatchWithSubdomains || t == MatchSubdomainsOnly
}

type DomainRule struct {
	Domain             string        `yaml:"domain"`
	MatchingType       MatchingType  `yaml:"matchingType"`
	MaxDepth           *int          `yaml:"maxDepth"`
	ListName           string        `yaml:"listName"`
	Outputs            []string      `yaml:"outputs"`
	DisableFallback    bool          `yaml:"disableFallback"`
	UpstreamsOverride  []string      `yaml:"upstreamsOverride"`
	UpstreamsBlacklist []string      `yaml:"upstreamsBlacklist"`
	Records            RecordSet     `yaml:"records"`
	RecordsTTL         time.Duration `yaml:"recordsTTL"`
	RecordsOnly        bool          `yaml:"recordsOnly"`
}

// removedDomainFields map retired keys to the migration hint shown for them.
var removedDomainFields = map[string]string{
	"matchsubdomains": "matchSubDomains has been replaced by matchingType: use `matchingType: withSubdomains` instead of `matchSubDomains: true`, and drop the field (or use `matchingType: exact`) instead of `matchSubDomains: false`",
}

func (r *DomainRule) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if hint, removed := removedDomainFields[normalizeEnumValue(node.Content[i].Value)]; removed {
				return errors.New(hint)
			}
		}
	}

	type raw DomainRule
	var rule raw
	if err := node.Decode(&rule); err != nil {
		return err
	}
	matching, err := ParseMatchingType(string(rule.MatchingType))
	if err != nil {
		return err
	}
	rule.MatchingType = matching
	*r = DomainRule(rule)
	return nil
}

// RecordSet maps a DNS record type name (A, AAAA, CNAME, ...) to its values.
type RecordSet map[string]StringList

// ToMap flattens the set into plain string slices.
func (r RecordSet) ToMap() map[string][]string {
	if len(r) == 0 {
		return nil
	}
	out := make(map[string][]string, len(r))
	for key, values := range r {
		out[key] = values
	}
	return out
}

// singleValueRecords are the record types a name may hold only one of, so a
// list is a config mistake rather than a shorthand.
var singleValueRecords = map[string]bool{"CNAME": true}

func (r *RecordSet) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag == "!!null" {
		*r = nil
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return errors.New("records must map a record type to its value(s)")
	}
	out := make(RecordSet, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		name := strings.ToUpper(strings.TrimSpace(key.Value))
		if singleValueRecords[name] && value.Kind == yaml.SequenceNode {
			return fmt.Errorf("%s takes a single value, not a list: write `%s: target.example.com`", name, key.Value)
		}
		var values StringList
		if err := value.Decode(&values); err != nil {
			return err
		}
		out[key.Value] = values
	}
	*r = out
	return nil
}

// StringList accepts either a single scalar or a sequence in YAML.
type StringList []string

func (l *StringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var value string
		if err := node.Decode(&value); err != nil {
			return err
		}
		*l = StringList{value}
		return nil
	}
	var values []string
	if err := node.Decode(&values); err != nil {
		return err
	}
	*l = values
	return nil
}

func (o *OutputConfig) UnmarshalYAML(node *yaml.Node) error {
	var typeHolder struct {
		Type string `yaml:"type"`
		Mode string `yaml:"mode"`
	}
	if err := node.Decode(&typeHolder); err != nil {
		return err
	}
	o.Type = strings.TrimSpace(typeHolder.Type)
	o.Mode = strings.ToLower(strings.TrimSpace(typeHolder.Mode))
	if o.Mode == "" {
		o.Mode = "active"
	}
	switch o.Mode {
	case "active", "passive":
	default:
		return fmt.Errorf("unsupported output mode %q", o.Mode)
	}
	switch o.Type {
	case "rosApiAddressList":
		var cfg outputs.RosApiAddressListConfig
		if err := node.Decode(&cfg); err != nil {
			return err
		}
		o.RosApiAddressList = &cfg
	case "rosRestApiAddressList":
		var cfg outputs.RosRestApiAddressListConfig
		if err := node.Decode(&cfg); err != nil {
			return err
		}
		o.RosRestApiAddressList = &cfg
	case "file":
		var cfg outputs.FileOutputConfig
		if err := node.Decode(&cfg); err != nil {
			return err
		}
		o.File = &cfg
	case "webhook":
		var cfg outputs.WebhookConfig
		if err := node.Decode(&cfg); err != nil {
			return err
		}
		o.Webhook = &cfg
	case "":
		return errors.New("output type is required")
	default:
		return fmt.Errorf("unsupported output type %q", o.Type)
	}
	return nil
}

// Load reads the config and merges every file it includes. Included files may
// be named after the section they carry (domains.yaml, outputs.yaml, ...) or
// key their sections explicitly. Lists are appended across files, so domains
// and outputs can be split up; mappings merge key by key, later files winning.
func Load(path string) (*Config, error) {
	root, err := loadDocument(path)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, fmt.Errorf("%s is empty", path)
	}

	var main struct {
		Include []string `yaml:"include"`
	}
	if err := root.Decode(&main); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	includes, err := resolveIncludes(path, main.Include)
	if err != nil {
		return nil, err
	}

	for _, include := range includes {
		doc, err := loadDocument(include)
		if err != nil {
			return nil, err
		}
		if doc == nil {
			continue
		}
		section, err := sectionDocument(include, doc)
		if err != nil {
			return nil, err
		}
		if err := mergeNodes(root, section, include); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := root.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Sources = append([]string{path}, includes...)
	for i := range cfg.Domains {
		cfg.Domains[i].Domain = strings.TrimSuffix(strings.ToLower(cfg.Domains[i].Domain), ".")
	}
	return &cfg, nil
}
