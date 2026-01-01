package main

import (
	"flag"
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

	var writers []outputs.AddressWriter
	var webhooks []*outputs.WebhookSender

	dohHTTP := &http.Client{
		Timeout: dnsTimeout,
	}
	webhookHTTP := &http.Client{
		Timeout: httpTimeout,
	}

	for _, output := range cfg.Outputs {
		switch output.Type {
		case "rosApiAddressList":
			if output.RosApiAddressList == nil {
				slog.Error("rosApiAddressList config missing")
				os.Exit(1)
			}
			ros, err := outputs.NewRouterOSClient(*output.RosApiAddressList, httpTimeout)
			if err != nil {
				slog.Error("routeros", "error", err)
				os.Exit(1)
			}
			writers = append(writers, ros)
		case "file":
			if output.File == nil {
				slog.Error("file config missing")
				os.Exit(1)
			}
			fileWriter, err := outputs.NewFileWriter(*output.File)
			if err != nil {
				slog.Error("file writer", "error", err)
				os.Exit(1)
			}
			writers = append(writers, fileWriter)
		case "webhook":
			if output.Webhook == nil {
				slog.Error("webhook config missing")
				os.Exit(1)
			}
			sender, err := outputs.NewWebhookSender(*output.Webhook, webhookHTTP)
			if err != nil {
				slog.Error("webhook", "error", err)
				os.Exit(1)
			}
			webhooks = append(webhooks, sender)
		default:
			slog.Error("unsupported output type", "type", output.Type)
			os.Exit(1)
		}
	}

	if len(writers) == 0 && len(webhooks) == 0 {
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
					outputSummaries = append(outputSummaries, "rosApiAddressList:"+address)
				} else {
					outputSummaries = append(outputSummaries, "rosApiAddressList:"+output.RosApiAddressList.Access.Host)
				}
			}
		case "file":
			if output.File != nil && output.File.Path != "" {
				outputSummaries = append(outputSummaries, "file:"+output.File.Path)
			}
		case "webhook":
			if output.Webhook != nil && strings.TrimSpace(output.Webhook.URL) != "" {
				method := strings.ToUpper(strings.TrimSpace(output.Webhook.Method))
				if method == "" {
					method = http.MethodPost
				}
				outputSummaries = append(outputSummaries, "webhook:"+method+" "+output.Webhook.URL)
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

	res := resolver.New(upstreamsList, fallbackUpstreams, cfg.Domains, writers, webhooks, timeout, dnsTimeout, httpTimeout, dohHTTP)

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
