package main

import (
	"flag"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/davehornigan/dns-forward/internal/config"
	"github.com/davehornigan/dns-forward/internal/outputs"
	"github.com/davehornigan/dns-forward/internal/resolver"
	"github.com/davehornigan/dns-forward/internal/upstreams"
	"github.com/miekg/dns"
	"log/slog"
)

const (
	defaultListenAddr = ":53"
	defaultTimeout    = 5 * time.Second
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "path to config YAML")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}
	if cfg.Server.Debug {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
	}

	upstreamsList, err := upstreams.ParseUpstreams(cfg.Upstreams)
	if err != nil {
		slog.Error("parse upstreams", "error", err)
		os.Exit(1)
	}
	if len(upstreamsList) == 0 {
		slog.Error("no upstreams configured")
		os.Exit(1)
	}

	ruleUpstreams := make(map[int][]upstreams.Upstream)
	for i, rule := range cfg.Domains {
		if len(rule.UpstreamsOverride) > 0 && len(rule.UpstreamsBlacklist) > 0 {
			slog.Error("domain upstreams cannot set both upstreamsOverride and upstreamsBlacklist", "domain", rule.Domain)
			os.Exit(1)
		}
		if len(rule.UpstreamsOverride) == 0 && len(rule.UpstreamsBlacklist) == 0 {
			continue
		}
		if len(rule.UpstreamsOverride) > 0 {
			parsed, err := upstreams.ParseUpstreams(rule.UpstreamsOverride)
			if err != nil {
				slog.Error("parse domain upstreamsOverride", "domain", rule.Domain, "error", err)
				os.Exit(1)
			}
			if len(parsed) == 0 {
				slog.Error("domain upstreamsOverride empty", "domain", rule.Domain)
				os.Exit(1)
			}
			ruleUpstreams[i] = parsed
			continue
		}
		blacklist, err := upstreams.ParseUpstreams(rule.UpstreamsBlacklist)
		if err != nil {
			slog.Error("parse domain upstreamsBlacklist", "domain", rule.Domain, "error", err)
			os.Exit(1)
		}
		if len(blacklist) == 0 {
			slog.Error("domain upstreamsBlacklist empty", "domain", rule.Domain)
			os.Exit(1)
		}
		blacklisted := make(map[string]struct{}, len(blacklist))
		for _, entry := range blacklist {
			blacklisted[upstreamKey(entry)] = struct{}{}
		}
		filtered := make([]upstreams.Upstream, 0, len(upstreamsList))
		for _, upstream := range upstreamsList {
			if _, ok := blacklisted[upstreamKey(upstream)]; ok {
				continue
			}
			filtered = append(filtered, upstream)
		}
		if len(filtered) == 0 {
			slog.Error("domain upstreamBlacklist removed all upstreams", "domain", rule.Domain)
			os.Exit(1)
		}
		ruleUpstreams[i] = filtered
	}

	fallbackUpstreams, err := upstreams.ParseUpstreams(cfg.FallbackUpstreams)
	if err != nil {
		slog.Error("parse fallback upstreams", "error", err)
		os.Exit(1)
	}
	if len(fallbackUpstreams) == 0 {
		fallbackUpstreams, err = upstreams.ParseUpstreams([]string{"udp://1.1.1.1:53"})
		if err != nil {
			slog.Error("parse fallback upstreams", "error", err)
			os.Exit(1)
		}
	}

	timeout := cfg.Server.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	dnsTimeout := cfg.Server.DNSTimeout
	if dnsTimeout == 0 {
		dnsTimeout = timeout
	}
	httpTimeout := cfg.Server.HTTPTimeout
	if httpTimeout == 0 {
		httpTimeout = timeout
	}
	excludeSubnets, err := parseExcludeSubnets(cfg.Server.ExcludeSubnets)
	if err != nil {
		slog.Error("parse exclude subnets", "error", err)
		os.Exit(1)
	}

	var outputTargets []resolver.OutputTarget
	outputIDs := make(map[string]struct{})

	dohHTTP := &http.Client{
		Timeout: dnsTimeout,
	}
	webhookHTTP := &http.Client{
		Timeout: httpTimeout,
	}

	for _, output := range cfg.Outputs {
		outputID := ""
		switch output.Type {
		case "rosApiAddressList":
			if output.RosApiAddressList == nil {
				slog.Error("rosApiAddressList config missing")
				os.Exit(1)
			}
			outputID = strings.TrimSpace(output.RosApiAddressList.ID)
			ros, err := outputs.NewRouterOSClient(*output.RosApiAddressList, httpTimeout)
			if err != nil {
				slog.Error("routeros", "error", err)
				os.Exit(1)
			}
			outputTargets = append(outputTargets, resolver.OutputTarget{ID: outputID, Mode: output.Mode, Writer: ros})
		case "rosRestApiAddressList":
			if output.RosRestApiAddressList == nil {
				slog.Error("rosRestApiAddressList config missing")
				os.Exit(1)
			}
			outputID = strings.TrimSpace(output.RosRestApiAddressList.ID)
			ros, err := outputs.NewRouterOSRestClient(*output.RosRestApiAddressList, httpTimeout)
			if err != nil {
				slog.Error("routeros rest", "error", err)
				os.Exit(1)
			}
			outputTargets = append(outputTargets, resolver.OutputTarget{ID: outputID, Mode: output.Mode, Writer: ros})
		case "file":
			if output.File == nil {
				slog.Error("file config missing")
				os.Exit(1)
			}
			outputID = strings.TrimSpace(output.File.ID)
			fileWriter, err := outputs.NewFileWriter(*output.File)
			if err != nil {
				slog.Error("file writer", "error", err)
				os.Exit(1)
			}
			outputTargets = append(outputTargets, resolver.OutputTarget{ID: outputID, Mode: output.Mode, Writer: fileWriter})
		case "webhook":
			if output.Webhook == nil {
				slog.Error("webhook config missing")
				os.Exit(1)
			}
			outputID = strings.TrimSpace(output.Webhook.ID)
			sender, err := outputs.NewWebhookSender(*output.Webhook, webhookHTTP)
			if err != nil {
				slog.Error("webhook", "error", err)
				os.Exit(1)
			}
			outputTargets = append(outputTargets, resolver.OutputTarget{ID: outputID, Mode: output.Mode, Webhook: sender})
		default:
			slog.Error("unsupported output type", "type", output.Type)
			os.Exit(1)
		}

		if outputID == "" {
			slog.Error("output id is required", "type", output.Type)
			os.Exit(1)
		}
		if _, exists := outputIDs[outputID]; exists {
			slog.Error("output id must be unique", "id", outputID)
			os.Exit(1)
		}
		outputIDs[outputID] = struct{}{}
	}

	if len(outputTargets) == 0 {
		slog.Error("no outputs configured (outputs[].type required)")
		os.Exit(1)
	}

	outputSummaries := make([]string, 0, len(cfg.Outputs))
	for _, output := range cfg.Outputs {
		switch output.Type {
		case "rosApiAddressList":
			if output.RosApiAddressList != nil && output.RosApiAddressList.Access.Host != "" {
				summaryCfg := output.RosApiAddressList.Access
				if err := outputs.ApplyHostOverrides(&summaryCfg); err == nil {
					address := outputs.FormatRouterOSAddress(summaryCfg)
					outputSummaries = append(outputSummaries, "rosApiAddressList:"+output.RosApiAddressList.ID+"@"+address)
				} else {
					outputSummaries = append(outputSummaries, "rosApiAddressList:"+output.RosApiAddressList.ID+"@"+output.RosApiAddressList.Access.Host)
				}
			}
		case "rosRestApiAddressList":
			if output.RosRestApiAddressList != nil && output.RosRestApiAddressList.Access.Host != "" {
				summaryCfg := output.RosRestApiAddressList.Access
				if err := outputs.ApplyHostOverrides(&summaryCfg); err == nil {
					address := outputs.FormatRouterOSRestBaseURL(summaryCfg)
					outputSummaries = append(outputSummaries, "rosRestApiAddressList:"+output.RosRestApiAddressList.ID+"@"+address)
				} else {
					outputSummaries = append(outputSummaries, "rosRestApiAddressList:"+output.RosRestApiAddressList.ID+"@"+output.RosRestApiAddressList.Access.Host)
				}
			}
		case "file":
			if output.File != nil && output.File.Path != "" {
				outputSummaries = append(outputSummaries, "file:"+output.File.ID+"@"+output.File.Path)
			}
		case "webhook":
			if output.Webhook != nil && strings.TrimSpace(output.Webhook.URL) != "" {
				method := strings.ToUpper(strings.TrimSpace(output.Webhook.Method))
				if method == "" {
					method = http.MethodPost
				}
				outputSummaries = append(outputSummaries, "webhook:"+output.Webhook.ID+" "+method+" "+output.Webhook.URL)
			}
		}
	}

	fallbackLabels := make([]string, 0, len(fallbackUpstreams))
	for _, upstream := range fallbackUpstreams {
		fallbackLabels = append(fallbackLabels, upstreams.Label(upstream))
	}

	slog.Info("config",
		"upstreams", upstreams.Labels(upstreamsList),
		"fallback_upstreams", fallbackLabels,
		"outputs", outputSummaries,
	)

	res := resolver.New(upstreamsList, fallbackUpstreams, cfg.Domains, ruleUpstreams, outputTargets, excludeSubnets, timeout, dnsTimeout, httpTimeout, cfg.Server.WriteIPWithPrefix, dohHTTP)

	addr := cfg.Server.ListenAddr
	if addr == "" {
		addr = defaultListenAddr
	}

	slog.Info("listening", "addr", addr, "proto", "udp/tcp")
	dns.HandleFunc(".", res.HandleDNS)

	udpSrv := &dns.Server{Addr: addr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp"}

	go func() {
		if err := udpSrv.ListenAndServe(); err != nil {
			slog.Error("udp server", "error", err)
			os.Exit(1)
		}
	}()
	if err := tcpSrv.ListenAndServe(); err != nil {
		slog.Error("tcp server", "error", err)
		os.Exit(1)
	}
}

func parseExcludeSubnets(subnets []string) ([]*net.IPNet, error) {
	if len(subnets) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(subnets))
	for _, entry := range subnets {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, parsed, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

func upstreamKey(upstream upstreams.Upstream) string {
	switch upstream.Kind {
	case "udp", "tcp", "dot":
		return upstream.Kind + "|" + upstream.Address
	case "doh":
		if upstream.URL != nil {
			return upstream.Kind + "|" + upstream.URL.String()
		}
		return upstream.Kind + "|<nil>"
	default:
		return upstream.Kind + "|" + upstreams.Label(upstream)
	}
}
