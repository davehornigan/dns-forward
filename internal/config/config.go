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
	Debug       bool          `yaml:"debug"`
	ListenAddr  string        `yaml:"listenAddr"`
	Timeout     time.Duration `yaml:"timeout"`
	DNSTimeout  time.Duration `yaml:"dnsTimeout"`
	HTTPTimeout time.Duration `yaml:"httpTimeout"`
}

type OutputConfig struct {
	Type              string                           `yaml:"type"`
	RosApiAddressList *outputs.RosApiAddressListConfig `yaml:"-"`
	File              *outputs.FileOutputConfig        `yaml:"-"`
	Webhook           *outputs.WebhookConfig           `yaml:"-"`
}

type DomainRule struct {
	Domain          string   `yaml:"domain"`
	MatchSubDomains bool     `yaml:"matchSubDomains"`
	MaxDepth        *int     `yaml:"maxDepth"`
	ListName        string   `yaml:"listName"`
	Outputs         []string `yaml:"outputs"`
}

func (o *OutputConfig) UnmarshalYAML(node *yaml.Node) error {
	var typeHolder struct {
		Type string `yaml:"type"`
	}
	if err := node.Decode(&typeHolder); err != nil {
		return err
	}
	o.Type = strings.TrimSpace(typeHolder.Type)
	switch o.Type {
	case "rosApiAddressList":
		var cfg outputs.RosApiAddressListConfig
		if err := node.Decode(&cfg); err != nil {
			return err
		}
		o.RosApiAddressList = &cfg
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
