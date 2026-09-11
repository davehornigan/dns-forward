package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/davehornigan/dns-forward/internal/outputs"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Upstreams         []string       `yaml:"upstreams"`
	FallbackUpstreams []string       `yaml:"fallbackUpstreams"`
	Domains           []DomainRule   `yaml:"domains"`
	Outputs           []OutputConfig `yaml:"outputs"`
	Server            ServerConfig   `yaml:"server"`
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
}

type OutputConfig struct {
	Type                  string                               `yaml:"type"`
	Mode                  string                               `yaml:"mode"`
	RosApiAddressList     *outputs.RosApiAddressListConfig     `yaml:"-"`
	RosRestApiAddressList *outputs.RosRestApiAddressListConfig `yaml:"-"`
	File                  *outputs.FileOutputConfig            `yaml:"-"`
	Webhook               *outputs.WebhookConfig               `yaml:"-"`
}

type DomainRule struct {
	Domain             string        `yaml:"domain"`
	MatchSubDomains    bool          `yaml:"matchSubDomains"`
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

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	for i := range cfg.Domains {
		cfg.Domains[i].Domain = strings.TrimSuffix(strings.ToLower(cfg.Domains[i].Domain), ".")
	}
	return &cfg, nil
}
