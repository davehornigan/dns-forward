package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-routeros/routeros"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"log/slog"
)

const (
	defaultListenAddr = ":53"
	defaultTimeout    = 5 * time.Second
	defaultRouterOSCacheRefresh = 5 * time.Minute
)

type Config struct {
	Upstreams         []string       `yaml:"upstreams"`
	FallbackUpstreams []string       `yaml:"fallbackUpstreams"`
	Domains           []DomainRule   `yaml:"domains"`
	Outputs           []OutputConfig `yaml:"outputs"`
	Debug             bool           `yaml:"debug"`
	ListenAddr        string         `yaml:"listenAddr"`
	Timeout           time.Duration  `yaml:"timeout"`
	HTTP              HTTPConfig     `yaml:"http"`
}

type HTTPConfig struct {
	Proxy string `yaml:"proxy"`
}

type OutputConfig struct {
	RouterOS *RouterOSConfig   `yaml:"routerOsApi"`
	File     *FileOutputConfig `yaml:"file"`
}

type FileOutputConfig struct {
	Path            string `yaml:"path"`
	AddressListName string `yaml:"addressListName"`
}

type DomainRule struct {
	Domain          string  `yaml:"domain"`
	MatchSubDomains bool    `yaml:"matchSubDomains"`
	MaxDepth        *int    `yaml:"maxDepth"`
	TTL             *string `yaml:"ttl"`
	RecordType      string  `yaml:"recordType"`
	AddressListName string  `yaml:"addressListName"`
	UpdateTTL       *bool   `yaml:"updateTTL"`
}

type DNSLog struct {
	Qname     string
	Qtype     string
	Upstream  string
	Upstreams []string
	Rcode     string
	Answers   int
	Reason    string
	List      string
	Domain    string
	Address   string
	Duration  time.Duration
}

const (
	outputFile     = "file"
	outputRouterOS = "routeros"
)

type RouterOSConfig struct {
	Host            string  `yaml:"host"`
	Port            int     `yaml:"port"`
	UseTLS          bool    `yaml:"useTLS"`
	Username        string  `yaml:"username"`
	Password        string  `yaml:"password"`
	AddressListName string  `yaml:"addressListName"`
	TTL             *string `yaml:"ttl"`
	UpdateTTL       *bool   `yaml:"updateTTL"`
	RecordType      string  `yaml:"recordType"`
}

type Upstream struct {
	Raw      string
	Kind     string
	Address  string
	URL      *url.URL
	ServerNI string
}

type Resolver struct {
	upstreams         []Upstream
	fallbackUpstreams []Upstream
	rules             []DomainRule
	writers           []AddressWriter
	timeout           time.Duration
	http              *http.Client
	fallbackCache     map[string]cachedResponse
	fallbackMu        sync.Mutex
}

type AddressWriter interface {
	EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error
	DefaultListName() string
	DefaultRecordType() string
	OutputType() string
}

type RouterOSClient struct {
	cfg    RouterOSConfig
	conn   *routeros.Client
	cache  map[string]string
	loaded map[string]bool
	mu     sync.Mutex
}

type FileWriter struct {
	basePath string
	listName string
	writers  map[string]*csv.Writer
	files    map[string]*os.File
	cache    map[string]map[string]bool
	mu       sync.Mutex
}

type cachedResponse struct {
	resp      *dns.Msg
	expiresAt time.Time
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "path to config YAML")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig(configPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}
	if cfg.Debug {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
	}

	upstreams, err := parseUpstreams(cfg.Upstreams)
	if err != nil {
		slog.Error("parse upstreams", "error", err)
		os.Exit(1)
	}
	if len(upstreams) == 0 {
		slog.Error("no upstreams configured")
		os.Exit(1)
	}

	fallbackUpstreams, err := parseUpstreams(cfg.FallbackUpstreams)
	if err != nil {
		slog.Error("parse fallback upstreams", "error", err)
		os.Exit(1)
	}
	if len(fallbackUpstreams) == 0 {
		fallbackUpstreams, err = parseUpstreams([]string{"udp://1.1.1.1:53"})
		if err != nil {
			slog.Error("parse fallback upstreams", "error", err)
			os.Exit(1)
		}
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	var writers []AddressWriter

	for _, output := range cfg.Outputs {
		if output.RouterOS != nil && output.RouterOS.Host != "" {
			ros, err := NewRouterOSClient(*output.RouterOS)
			if err != nil {
				slog.Error("routeros", "error", err)
				os.Exit(1)
			}
			writers = append(writers, ros)
		}

		if output.File != nil && output.File.Path != "" {
			fileWriter, err := NewFileWriter(*output.File)
			if err != nil {
				slog.Error("file writer", "error", err)
				os.Exit(1)
			}
			writers = append(writers, fileWriter)
		}
	}

	if len(writers) == 0 {
		slog.Error("no outputs configured (outputs[].routerOsApi.host or outputs[].file.path required)")
		os.Exit(1)
	}

	outputSummaries := make([]string, 0, len(cfg.Outputs))
	for _, output := range cfg.Outputs {
		if output.RouterOS != nil && output.RouterOS.Host != "" {
			address := formatRouterOSAddress(*output.RouterOS)
			outputSummaries = append(outputSummaries, "routeros:"+address)
		}
		if output.File != nil && output.File.Path != "" {
			outputSummaries = append(outputSummaries, "file:"+output.File.Path)
		}
	}

	fallbackLabels := make([]string, 0, len(fallbackUpstreams))
	for _, upstream := range fallbackUpstreams {
		fallbackLabels = append(fallbackLabels, upstreamLabel(upstream))
	}

	slog.Info("config",
		"upstreams", upstreamLabels(upstreams),
		"fallback_upstreams", fallbackLabels,
		"outputs", outputSummaries,
	)

	httpClient := &http.Client{
		Timeout: timeout,
	}
	if cfg.HTTP.Proxy != "" {
		proxyURL, err := url.Parse(cfg.HTTP.Proxy)
		if err != nil {
			slog.Error("http proxy", "error", err)
			os.Exit(1)
		}
		httpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	resolver := &Resolver{
		upstreams:         upstreams,
		fallbackUpstreams: fallbackUpstreams,
		rules:             cfg.Domains,
		writers:           writers,
		timeout:           timeout,
		http:              httpClient,
		fallbackCache:     make(map[string]cachedResponse),
	}

	addr := cfg.ListenAddr
	if addr == "" {
		addr = defaultListenAddr
	}

	slog.Info("listening", "addr", addr, "proto", "udp/tcp")
	dns.HandleFunc(".", resolver.handleDNS)

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

func resolveErrorAttrs(entry DNSLog, err error) []any {
	return []any{
		"qname", entry.Qname,
		"qtype", entry.Qtype,
		"upstreams", entry.Upstreams,
		"reason", entry.Reason,
		"error", err,
	}
}

func dnsReplyAttrs(entry DNSLog) []any {
	return []any{
		"qname", entry.Qname,
		"qtype", entry.Qtype,
		"upstream", entry.Upstream,
		"rcode", entry.Rcode,
		"answers", entry.Answers,
	}
}

func upstreamResultAttrs(entry DNSLog, err error) []any {
	if err != nil {
		return []any{
			"qname", entry.Qname,
			"qtype", entry.Qtype,
			"upstream", entry.Upstream,
			"duration_ms", entry.Duration.Milliseconds(),
			"error", err,
		}
	}
	return []any{
		"qname", entry.Qname,
		"qtype", entry.Qtype,
		"upstream", entry.Upstream,
		"rcode", entry.Rcode,
		"answers", entry.Answers,
		"duration_ms", entry.Duration.Milliseconds(),
	}
}

func writeAddressAttrs(entry DNSLog, err error) []any {
	return []any{
		"list", entry.List,
		"domain", entry.Domain,
		"address", entry.Address,
		"error", err,
	}
}

func loadConfig(path string) (*Config, error) {
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

func parseUpstreams(raw []string) ([]Upstream, error) {
	var upstreams []Upstream
	for _, entry := range raw {
		original := strings.TrimSpace(entry)
		if original == "" {
			continue
		}
		entry = original
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "://") {
			host, port, err := parseHostPortDefault(entry, "53")
			if err != nil {
				return nil, fmt.Errorf("invalid udp upstream %q: %w", entry, err)
			}
			upstreams = append(upstreams, Upstream{
				Raw:     original,
				Kind:    "udp",
				Address: net.JoinHostPort(host, port),
			})
			continue
		}
		u, err := url.Parse(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream %q: %w", entry, err)
		}
		switch u.Scheme {
		case "tls":
			host := u.Hostname()
			if host == "" {
				return nil, fmt.Errorf("invalid tls upstream %q", entry)
			}
			port := u.Port()
			if port == "" {
				port = "853"
			}
			upstreams = append(upstreams, Upstream{
				Raw:      original,
				Kind:     "dot",
				Address:  net.JoinHostPort(host, port),
				ServerNI: host,
			})
		case "udp", "tcp":
			host := u.Hostname()
			if host == "" {
				return nil, fmt.Errorf("invalid %s upstream %q", u.Scheme, entry)
			}
			port := u.Port()
			if port == "" {
				port = "53"
			}
			upstreams = append(upstreams, Upstream{
				Raw:     original,
				Kind:    u.Scheme,
				Address: net.JoinHostPort(host, port),
			})
		case "https":
			if u.Hostname() == "" {
				return nil, fmt.Errorf("invalid https upstream %q", entry)
			}
			if u.Path == "" {
				return nil, fmt.Errorf("https upstream %q missing path", entry)
			}
			upstreams = append(upstreams, Upstream{
				Raw:  original,
				Kind: "doh",
				URL:  u,
			})
		default:
			return nil, fmt.Errorf("unsupported upstream scheme %q", u.Scheme)
		}
	}
	return upstreams, nil
}

func parseHostPortDefault(input, defaultPort string) (string, string, error) {
	entry := strings.TrimSpace(input)
	if entry == "" {
		return "", "", errors.New("empty host")
	}
	if strings.HasPrefix(entry, "[") {
		if strings.Contains(entry, "]:") {
			host, port, err := net.SplitHostPort(entry)
			if err != nil {
				return "", "", err
			}
			return host, port, nil
		}
		if strings.HasSuffix(entry, "]") {
			host := strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")
			if host == "" {
				return "", "", errors.New("empty host")
			}
			return host, defaultPort, nil
		}
		return "", "", errors.New("invalid bracketed host")
	}

	colons := strings.Count(entry, ":")
	switch colons {
	case 0:
		return entry, defaultPort, nil
	case 1:
		host, port, err := net.SplitHostPort(entry)
		if err == nil {
			return host, port, nil
		}
		idx := strings.LastIndex(entry, ":")
		if idx <= 0 || idx >= len(entry)-1 {
			return "", "", errors.New("invalid host:port")
		}
		host = entry[:idx]
		port = entry[idx+1:]
		if _, err := strconv.Atoi(port); err != nil {
			return "", "", fmt.Errorf("invalid port %q", port)
		}
		return host, port, nil
	default:
		if ip := net.ParseIP(entry); ip != nil {
			return entry, defaultPort, nil
		}
		return "", "", errors.New("invalid host")
	}
}

func (r *Resolver) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp, firstUpstream, allCh, reason, err := r.resolveParallel(req)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		qname := ""
		qtype := ""
		if len(req.Question) > 0 {
			qname = req.Question[0].Name
			qtype = dns.TypeToString[req.Question[0].Qtype]
		}
		slog.Error("resolve error", resolveErrorAttrs(DNSLog{
			Qname:     qname,
			Qtype:     qtype,
			Upstreams: r.upstreamSummary(),
			Reason:    reason,
		}, err)...)
		return
	}
	_ = w.WriteMsg(resp)

	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	slog.Debug("dns reply", dnsReplyAttrs(DNSLog{
		Qname:    q.Name,
		Qtype:    dns.TypeToString[q.Qtype],
		Upstream: firstUpstream,
		Rcode:    dns.RcodeToString[resp.Rcode],
		Answers:  len(resp.Answer),
	})...)
	match, rule := r.matchDomain(q.Name)
	if !match {
		return
	}

	listName := rule.AddressListName

	recordType := strings.ToLower(strings.TrimSpace(rule.RecordType))

	domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	go func() {
		ipSet := make(map[string]bool)
		hostSeen := false
		for resp := range allCh {
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			hostSeen = true
			for _, ip := range extractIPs(resp.Answer) {
				ipSet[ip] = true
			}
		}
		for _, writer := range r.writers {
			effectiveList := listName
			if effectiveList == "" {
				effectiveList = writer.DefaultListName()
			}
			if effectiveList == "" {
				continue
			}

			switch writer.OutputType() {
			case outputFile:
				for ip := range ipSet {
					r.writeAddress(writer, effectiveList, domain, ip, rule.TTL, rule.UpdateTTL)
				}
			case outputRouterOS:
				effectiveRecordType := recordType
				if effectiveRecordType == "" {
					effectiveRecordType = writer.DefaultRecordType()
				}
				if effectiveRecordType == "host" {
					if hostSeen {
						r.writeAddress(writer, effectiveList, domain, domain, rule.TTL, rule.UpdateTTL)
					}
				} else {
					for ip := range ipSet {
						r.writeAddress(writer, effectiveList, domain, ip, rule.TTL, rule.UpdateTTL)
					}
				}
			default:
				for ip := range ipSet {
					r.writeAddress(writer, effectiveList, domain, ip, rule.TTL, rule.UpdateTTL)
				}
			}
		}
	}()
}

func (r *Resolver) writeAddress(writer AddressWriter, listName, domain, address string, ttl *string, updateTTL *bool) {
	if err := writer.EnsureAddress(listName, domain, address, ttl, updateTTL); err != nil {
		slog.Error("write address", writeAddressAttrs(DNSLog{
			List:    listName,
			Domain:  domain,
			Address: address,
		}, err)...)
	}
}

func (r *Resolver) resolveParallel(req *dns.Msg) (*dns.Msg, string, <-chan *dns.Msg, string, error) {
	resp, upstream, allCh, reason, ok := r.resolvePrimary(req)
	if ok {
		return resp, upstream, allCh, "", nil
	}
	if len(r.fallbackUpstreams) == 0 {
		return nil, "", allCh, reason, errors.New("all upstreams failed")
	}
	fbResp, fbUpstream, fbReason, err := r.resolveFallback(req)
	if err != nil {
		combined := reason
		if combined == "" {
			combined = fbReason
		} else if fbReason != "" {
			combined = combined + "; fallback: " + fbReason
		}
		return nil, "", allCh, combined, err
	}
	return fbResp, fbUpstream, allCh, "", nil
}

func (r *Resolver) resolvePrimary(req *dns.Msg) (*dns.Msg, string, <-chan *dns.Msg, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)

	type result struct {
		resp     *dns.Msg
		err      error
		upstream string
		duration time.Duration
	}

	resCh := make(chan result, len(r.upstreams))

	var wg sync.WaitGroup
	for _, upstream := range r.upstreams {
		upstream := upstream
		wg.Add(1)
		go func() {
			defer wg.Done()
			var resp *dns.Msg
			var err error
			qname := ""
			qtype := ""
			if len(req.Question) > 0 {
				qname = req.Question[0].Name
				qtype = dns.TypeToString[req.Question[0].Qtype]
			}
			start := time.Now()
			var rtt time.Duration
			switch upstream.Kind {
			case "udp", "tcp":
				resp, rtt, err = exchangeDNS(ctx, upstream.Kind, upstream.Address, req, r.timeout)
			case "dot":
				resp, rtt, err = exchangeDoT(ctx, upstream, req, r.timeout)
			case "doh":
				resp, rtt, err = exchangeDoH(ctx, r.http, upstream.URL, req)
			default:
				err = fmt.Errorf("unknown upstream kind %q", upstream.Kind)
			}
			upLabel := upstreamLabel(upstream)
			if rtt == 0 {
				rtt = time.Since(start)
			}
			resCh <- result{resp: resp, err: err, upstream: upLabel, duration: rtt}
			if err != nil {
				slog.Error("upstream error", upstreamResultAttrs(DNSLog{
					Qname:    qname,
					Qtype:    qtype,
					Upstream: upLabel,
					Duration: rtt,
				}, err)...)
				return
			}
			slog.Debug("upstream resolve", upstreamResultAttrs(DNSLog{
				Qname:    qname,
				Qtype:    qtype,
				Upstream: upLabel,
				Rcode:    dns.RcodeToString[resp.Rcode],
				Answers:  len(resp.Answer),
				Duration: rtt,
			}, nil)...)
		}()
	}

	go func() {
		wg.Wait()
		close(resCh)
		cancel()
	}()

	allCh := make(chan *dns.Msg, len(r.upstreams))
	firstCh := make(chan result, 1)
	reasonCh := make(chan string, 1)

	qtype := uint16(0)
	if len(req.Question) > 0 {
		qtype = req.Question[0].Qtype
	}

	go func() {
		firstSent := false
		errs := make([]string, 0, len(r.upstreams))
		normalSeen := false
		for res := range resCh {
			if res.err != nil {
				errs = append(errs, res.err.Error())
				continue
			}
			allCh <- res.resp
			hasAddress := responseHasAddress(res.resp, qtype)
			if hasAddress {
				normalSeen = true
			}
			if !firstSent && hasAddress {
				firstSent = true
				firstCh <- res
			}
		}
		if !firstSent {
			if len(errs) == len(r.upstreams) && len(errs) > 0 {
				reasonCh <- strings.Join(errs, "; ")
			} else if !normalSeen {
				reason := "no primary upstream returned address"
				if len(errs) > 0 {
					reason += "; errors: " + strings.Join(errs, "; ")
				}
				reasonCh <- reason
			} else {
				reasonCh <- "all upstreams failed"
			}
		}
		close(allCh)
		close(firstCh)
		close(reasonCh)
	}()

	select {
	case res, ok := <-firstCh:
		if ok {
			return res.resp, res.upstream, allCh, "", true
		}
		reason := "all upstreams failed"
		if msg, ok := <-reasonCh; ok && msg != "" {
			reason = msg
		}
		return nil, "", allCh, reason, false
	case <-ctx.Done():
		return nil, "", allCh, "timeout", false
	case reason, ok := <-reasonCh:
		if ok && reason != "" {
			return nil, "", allCh, reason, false
		}
		return nil, "", allCh, "all upstreams failed", false
	}
}

func (r *Resolver) resolveFallback(req *dns.Msg) (*dns.Msg, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	if cached, ok := r.fallbackCacheGet(req); ok {
		return cached, "fallback:cache", "", nil
	}

	type result struct {
		resp     *dns.Msg
		err      error
		upstream string
		duration time.Duration
	}

	resCh := make(chan result, len(r.fallbackUpstreams))
	var wg sync.WaitGroup
	for _, upstream := range r.fallbackUpstreams {
		upstream := upstream
		wg.Add(1)
		go func() {
			defer wg.Done()
			var resp *dns.Msg
			var err error
			qname := ""
			qtype := ""
			if len(req.Question) > 0 {
				qname = req.Question[0].Name
				qtype = dns.TypeToString[req.Question[0].Qtype]
			}
			start := time.Now()
			var rtt time.Duration
			switch upstream.Kind {
			case "udp", "tcp":
				resp, rtt, err = exchangeDNS(ctx, upstream.Kind, upstream.Address, req, r.timeout)
			case "dot":
				resp, rtt, err = exchangeDoT(ctx, upstream, req, r.timeout)
			case "doh":
				resp, rtt, err = exchangeDoH(ctx, r.http, upstream.URL, req)
			default:
				err = fmt.Errorf("unknown upstream kind %q", upstream.Kind)
			}
			upLabel := "fallback:" + upstreamLabel(upstream)
			if rtt == 0 {
				rtt = time.Since(start)
			}
			resCh <- result{resp: resp, err: err, upstream: upLabel, duration: rtt}
			if err != nil {
				slog.Error("upstream error", upstreamResultAttrs(DNSLog{
					Qname:    qname,
					Qtype:    qtype,
					Upstream: upLabel,
					Duration: rtt,
				}, err)...)
				return
			}
			slog.Debug("upstream resolve", upstreamResultAttrs(DNSLog{
				Qname:    qname,
				Qtype:    qtype,
				Upstream: upLabel,
				Rcode:    dns.RcodeToString[resp.Rcode],
				Answers:  len(resp.Answer),
				Duration: rtt,
			}, nil)...)
		}()
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	errs := make([]string, 0, len(r.fallbackUpstreams))
	for res := range resCh {
		if res.err != nil {
			errs = append(errs, res.err.Error())
			continue
		}
		r.fallbackCacheSet(req, res.resp)
		return res.resp, res.upstream, "", nil
	}
	reason := "all fallback upstreams failed"
	if len(errs) > 0 {
		reason = strings.Join(errs, "; ")
	}
	return nil, "", reason, errors.New("all fallback upstreams failed")
}

func (r *Resolver) upstreamSummary() []string {
	out := make([]string, 0, len(r.upstreams))
	for _, upstream := range r.upstreams {
		out = append(out, upstreamLabel(upstream))
	}
	return out
}

func upstreamLabels(upstreams []Upstream) []string {
	out := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		out = append(out, upstreamLabel(upstream))
	}
	return out
}

func fallbackCacheKey(q dns.Question) string {
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

func minAnswerTTL(resp *dns.Msg) uint32 {
	if resp == nil || len(resp.Answer) == 0 {
		return 0
	}
	minTTL := resp.Answer[0].Header().Ttl
	for _, rr := range resp.Answer[1:] {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}
	return minTTL
}

func (r *Resolver) fallbackCacheGet(req *dns.Msg) (*dns.Msg, bool) {
	if len(req.Question) == 0 {
		return nil, false
	}
	key := fallbackCacheKey(req.Question[0])

	r.fallbackMu.Lock()
	entry, ok := r.fallbackCache[key]
	if !ok {
		r.fallbackMu.Unlock()
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(r.fallbackCache, key)
		r.fallbackMu.Unlock()
		return nil, false
	}
	remaining := entry.expiresAt.Sub(time.Now())
	r.fallbackMu.Unlock()

	resp := entry.resp.Copy()
	resp.Id = req.Id
	resp.Compress = req.Compress

	remainingSec := uint32(remaining / time.Second)
	for _, rr := range resp.Answer {
		if rr.Header().Ttl > remainingSec {
			rr.Header().Ttl = remainingSec
		}
	}
	return resp, true
}

func (r *Resolver) fallbackCacheSet(req *dns.Msg, resp *dns.Msg) {
	if len(req.Question) == 0 || resp == nil {
		return
	}
	ttl := minAnswerTTL(resp)
	if ttl == 0 {
		return
	}
	key := fallbackCacheKey(req.Question[0])
	expiry := time.Now().Add(time.Duration(ttl) * time.Second)

	r.fallbackMu.Lock()
	r.fallbackCache[key] = cachedResponse{
		resp:      resp.Copy(),
		expiresAt: expiry,
	}
	r.fallbackMu.Unlock()
}

func upstreamLabel(upstream Upstream) string {
	if upstream.Raw != "" {
		return upstream.Raw
	}
	switch upstream.Kind {
	case "udp", "tcp":
		return upstream.Address
	case "dot":
		return upstream.Address
	case "doh":
		if upstream.URL != nil {
			return upstream.URL.String()
		}
		return "<nil>"
	default:
		return fmt.Sprintf("unknown:%s", upstream.Kind)
	}
}

func exchangeDoT(ctx context.Context, upstream Upstream, req *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			ServerName: upstream.ServerNI,
		},
		Timeout: timeout,
	}
	return client.ExchangeContext(ctx, req, upstream.Address)
}

func exchangeDNS(ctx context.Context, network, address string, req *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net:     network,
		Timeout: timeout,
	}
	return client.ExchangeContext(ctx, req, address)
}

func exchangeDoH(ctx context.Context, client *http.Client, endpoint *url.URL, req *dns.Msg) (*dns.Msg, time.Duration, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, 0, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, 0, fmt.Errorf("doh status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, 0, err
	}

	return msg, time.Since(start), nil
}

func extractIPs(records []dns.RR) []string {
	seen := make(map[string]bool)
	var out []string
	for _, rr := range records {
		switch v := rr.(type) {
		case *dns.A:
			ip := v.A.String()
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		case *dns.AAAA:
			ip := v.AAAA.String()
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out
}

func hasAnswerType(records []dns.RR, qtype uint16) bool {
	for _, rr := range records {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func responseHasAddress(resp *dns.Msg, qtype uint16) bool {
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return false
	}
	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		return hasAnswerType(resp.Answer, qtype)
	case dns.TypeANY:
		return len(extractIPs(resp.Answer)) > 0
	default:
		return true
	}
}

func (r *Resolver) matchDomain(qname string) (bool, DomainRule) {
	if len(r.rules) == 0 {
		return true, DomainRule{}
	}
	name := strings.TrimSuffix(strings.ToLower(qname), ".")
	labels := strings.Split(name, ".")

	for _, rule := range r.rules {
		if rule.Domain == "" {
			continue
		}
		domain := rule.Domain
		if name == domain {
			return true, rule
		}
		if !rule.MatchSubDomains {
			continue
		}
		if strings.HasSuffix(name, "."+domain) {
			if rule.MaxDepth == nil {
				return true, rule
			}
			domainLabels := strings.Split(domain, ".")
			depth := len(labels) - len(domainLabels)
			if depth <= *rule.MaxDepth {
				return true, rule
			}
		}
	}
	return false, DomainRule{}
}

func NewRouterOSClient(cfg RouterOSConfig) (*RouterOSClient, error) {
	if cfg.Host == "" {
		return nil, errors.New("routeros host is required")
	}
	if strings.TrimSpace(cfg.RecordType) == "" {
		return nil, errors.New("routeros recordType is required")
	}
	cfg.RecordType = strings.ToLower(strings.TrimSpace(cfg.RecordType))
	if cfg.RecordType != "ip" && cfg.RecordType != "host" {
		return nil, fmt.Errorf("routeros recordType must be ip or host, got %q", cfg.RecordType)
	}
	if cfg.AddressListName == "" {
		return nil, errors.New("routeros addressListName is required")
	}
	if cfg.Username == "" {
		cfg.Username = os.Getenv("ROUTEROS_USER")
	}
	if cfg.Password == "" {
		cfg.Password = os.Getenv("ROUTEROS_PASS")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("routeros credentials are required (username/password or env ROUTEROS_USER/ROUTEROS_PASS)")
	}

	address := formatRouterOSAddress(cfg)

	var (
		conn *routeros.Client
		err  error
	)
	if cfg.UseTLS {
		conn, err = routeros.DialTLS(address, cfg.Username, cfg.Password, &tls.Config{})
	} else {
		conn, err = routeros.Dial(address, cfg.Username, cfg.Password)
	}
	if err != nil {
		return nil, err
	}

	client := &RouterOSClient{
		cfg:    cfg,
		conn:   conn,
		cache:  make(map[string]string),
		loaded: make(map[string]bool),
	}
	if err := client.ensureListCache(cfg.AddressListName); err != nil {
		return nil, err
	}
	client.startCacheRefresher(defaultRouterOSCacheRefresh)
	return client, nil
}

func (c *RouterOSClient) DefaultListName() string {
	return c.cfg.AddressListName
}

func (c *RouterOSClient) DefaultRecordType() string {
	return c.cfg.RecordType
}

func (c *RouterOSClient) OutputType() string {
	return outputRouterOS
}

func NewFileWriter(cfg FileOutputConfig) (*FileWriter, error) {
	basePath := strings.TrimSpace(cfg.Path)
	if basePath == "" {
		return nil, errors.New("file output path is required")
	}
	listName := strings.TrimSpace(cfg.AddressListName)
	if listName == "" {
		return nil, errors.New("file output addressListName is required")
	}
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}
	writer := &FileWriter{
		basePath: basePath,
		listName: listName,
		writers:  make(map[string]*csv.Writer),
		files:    make(map[string]*os.File),
		cache:    make(map[string]map[string]bool),
	}
	return writer, nil
}

func formatRouterOSAddress(cfg RouterOSConfig) string {
	port := cfg.Port
	if port == 0 {
		if cfg.UseTLS {
			port = 8729
		} else {
			port = 8728
		}
	}
	return net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port))
}

func (c *RouterOSClient) ensureListCache(listName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.loaded[listName] {
		return nil
	}

	reply, err := c.conn.Run("/ip/firewall/address-list/print", fmt.Sprintf("?list=%s", listName))
	if err != nil {
		lower := strings.ToLower(err.Error())
		// If the list is not present yet, allow runtime population on first add.
		if strings.Contains(lower, "no such item") {
			c.loaded[listName] = true
			return nil
		}
		// RouterOS can return !empty for an empty list; ignore and let runtime populate.
		if strings.Contains(lower, "routeros reply word: !empty") {
			c.loaded[listName] = true
			return nil
		}
		return err
	}
	for _, re := range reply.Re {
		id := re.Map[".id"]
		address := re.Map["address"]
		if address != "" && id != "" {
			key := fmt.Sprintf("%s|%s", listName, address)
			c.cache[key] = id
		}
	}
	c.loaded[listName] = true
	return nil
}

func (c *RouterOSClient) EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error {
	if err := c.ensureListCache(listName); err != nil {
		return err
	}

	key := fmt.Sprintf("%s|%s", listName, address)
	effectiveTTL := ""
	if ttl != nil && strings.TrimSpace(*ttl) != "" {
		effectiveTTL = strings.TrimSpace(*ttl)
	} else if c.cfg.TTL != nil && strings.TrimSpace(*c.cfg.TTL) != "" {
		effectiveTTL = strings.TrimSpace(*c.cfg.TTL)
	}

	c.mu.Lock()
	if id, ok := c.cache[key]; ok && id != "" {
		c.mu.Unlock()
		if effectiveTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
			return nil
		}
		return c.updateAddressTTL(id, effectiveTTL)
	} else if ok && id == "" {
		c.mu.Unlock()
		if err := c.refreshListCache(listName); err != nil {
			return err
		}
		if effectiveTTL == "" || !shouldUpdateTTL(c.cfg.UpdateTTL, updateTTL) {
			return nil
		}
		c.mu.Lock()
		id = c.cache[key]
		c.mu.Unlock()
		if id != "" {
			return c.updateAddressTTL(id, effectiveTTL)
		}
		return nil
	}
	c.mu.Unlock()

	args := []string{
		"/ip/firewall/address-list/add",
		fmt.Sprintf("=list=%s", listName),
		fmt.Sprintf("=address=%s", address),
		fmt.Sprintf("=comment=%s", domain),
	}
	if effectiveTTL != "" {
		args = append(args, fmt.Sprintf("=timeout=%s", effectiveTTL))
	}

	c.mu.Lock()
	if _, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	reply, err := c.conn.RunArgs(args)
	if err != nil {
		return err
	}
	if len(reply.Re) > 0 {
		if id := reply.Re[0].Map[".id"]; id != "" {
			c.mu.Lock()
			c.cache[key] = id
			c.mu.Unlock()
			return nil
		}
	}
	// Fallback: refresh cache if add response doesn't include .id.
	if err := c.refreshListCache(listName); err != nil {
		return err
	}
	return nil
}

func (c *RouterOSClient) updateAddressTTL(id, ttl string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.conn.RunArgs([]string{
		"/ip/firewall/address-list/set",
		fmt.Sprintf("=.id=%s", id),
		fmt.Sprintf("=timeout=%s", ttl),
	})
	return err
}

func (c *RouterOSClient) refreshListCache(listName string) error {
	c.mu.Lock()
	c.loaded[listName] = false
	c.mu.Unlock()
	return c.ensureListCache(listName)
}

func (c *RouterOSClient) refreshAllLists() {
	c.mu.Lock()
	listNames := make([]string, 0, len(c.loaded))
	for listName, loaded := range c.loaded {
		if loaded {
			listNames = append(listNames, listName)
		}
	}
	c.mu.Unlock()

	for _, listName := range listNames {
		if err := c.refreshListCache(listName); err != nil {
			slog.Error("routeros refresh list cache", "list", listName, "error", err)
		}
	}
}

func (c *RouterOSClient) startCacheRefresher(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			c.refreshAllLists()
		}
	}()
}

func (f *FileWriter) EnsureAddress(listName, domain, address string, ttl *string, updateTTL *bool) error {
	_ = ttl
	_ = updateTTL
	if listName == "" {
		return nil
	}
	key := fmt.Sprintf("%s|%s", listName, address)

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.cache[listName] == nil {
		f.cache[listName] = make(map[string]bool)
	}
	if f.cache[listName][key] {
		return nil
	}

	if err := f.writeLine(listName, domain, address); err != nil {
		return err
	}
	f.cache[listName][key] = true
	return nil
}

func (f *FileWriter) DefaultListName() string {
	return f.listName
}

func (f *FileWriter) DefaultRecordType() string {
	return "ip"
}

func (f *FileWriter) OutputType() string {
	return outputFile
}

func (f *FileWriter) writeLine(listName, domain, address string) error {
	writer, err := f.getWriter(listName)
	if err != nil {
		return err
	}
	if err := writer.Write([]string{domain, address}); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func (f *FileWriter) getWriter(listName string) (*csv.Writer, error) {
	if writer, ok := f.writers[listName]; ok {
		return writer, nil
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	filePath := filepath.Join(f.basePath, fmt.Sprintf("%s.csv", listName))
	file, err := os.OpenFile(filePath, flags, 0644)
	if err != nil {
		return nil, err
	}
	buf := bufio.NewWriter(file)
	writer := csv.NewWriter(buf)
	f.files[listName] = file
	f.writers[listName] = writer
	return writer, nil
}

func shouldUpdateTTL(global *bool, override *bool) bool {
	if override != nil {
		return *override
	}
	if global == nil {
		return true
	}
	return *global
}
