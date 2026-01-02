package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/davehornigan/dns-forward/internal/config"
	"github.com/davehornigan/dns-forward/internal/outputs"
	"github.com/davehornigan/dns-forward/internal/upstreams"
	"github.com/miekg/dns"
	"log/slog"
)

type DNSLog struct {
	Qname     string
	Qtype     string
	Upstream  string
	Upstreams []string
	Rcode     string
	Answers   int
	Addresses []string
	Reason    string
	List      string
	Domain    string
	Address   string
	Duration  time.Duration
}

type Resolver struct {
	upstreams         []upstreams.Upstream
	fallbackUpstreams []upstreams.Upstream
	rules             []config.DomainRule
	ruleUpstreams     map[int][]upstreams.Upstream
	outputs           []OutputTarget
	excludeSubnets    []*net.IPNet
	timeout           time.Duration
	dnsTimeout        time.Duration
	httpTimeout       time.Duration
	dohHTTP           *http.Client
	fallbackCache     map[string]cachedResponse
	fallbackMu        sync.Mutex
}

type cachedResponse struct {
	resp      *dns.Msg
	expiresAt time.Time
}

type OutputTarget struct {
	ID      string
	Writer  outputs.AddressWriter
	Webhook *outputs.WebhookSender
}

func New(upstreamsList []upstreams.Upstream, fallbackList []upstreams.Upstream, rules []config.DomainRule, ruleUpstreams map[int][]upstreams.Upstream, outputsList []OutputTarget, excludeSubnets []*net.IPNet, timeout, dnsTimeout, httpTimeout time.Duration, dohHTTP *http.Client) *Resolver {
	if ruleUpstreams == nil {
		ruleUpstreams = make(map[int][]upstreams.Upstream)
	}
	return &Resolver{
		upstreams:         upstreamsList,
		fallbackUpstreams: fallbackList,
		rules:             rules,
		ruleUpstreams:     ruleUpstreams,
		outputs:           outputsList,
		excludeSubnets:    excludeSubnets,
		timeout:           timeout,
		dnsTimeout:        dnsTimeout,
		httpTimeout:       httpTimeout,
		dohHTTP:           dohHTTP,
		fallbackCache:     make(map[string]cachedResponse),
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
	attrs := []any{
		"qname", entry.Qname,
		"qtype", entry.Qtype,
		"upstream", entry.Upstream,
		"rcode", entry.Rcode,
		"answers", entry.Answers,
		"duration_ms", entry.Duration.Milliseconds(),
	}
	if len(entry.Addresses) > 0 {
		attrs = append(attrs, "addresses", entry.Addresses)
	}
	return attrs
}

func writeAddressAttrs(entry DNSLog, err error) []any {
	return []any{
		"list", entry.List,
		"domain", entry.Domain,
		"address", entry.Address,
		"error", err,
	}
}

func (r *Resolver) HandleDNS(w dns.ResponseWriter, req *dns.Msg) {
	qname := ""
	qtype := ""
	match := false
	rule := config.DomainRule{}
	ruleIndex := -1
	if len(req.Question) > 0 {
		q := req.Question[0]
		qname = q.Name
		qtype = dns.TypeToString[q.Qtype]
		match, rule, ruleIndex = r.matchDomain(q.Name)
	}

	upstreamsList := r.upstreams
	if match && ruleIndex >= 0 {
		if ruleUpstreams, ok := r.ruleUpstreams[ruleIndex]; ok && len(ruleUpstreams) > 0 {
			upstreamsList = ruleUpstreams
		}
	}

	resp, firstUpstream, allCh, reason, err := r.resolveParallel(req, upstreamsList)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		slog.Error("resolve error", resolveErrorAttrs(DNSLog{
			Qname:     qname,
			Qtype:     qtype,
			Upstreams: upstreams.Labels(upstreamsList),
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
	if !match {
		return
	}

	listName := rule.ListName
	ruleList := strings.TrimSpace(listName)
	ruleOutputs := normalizeOutputs(rule.Outputs)

	domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	go func() {
		ipSet := make(map[string]bool)
		hostSeen := false
		for resp := range allCh {
			if resp == nil || resp.Rcode != dns.RcodeSuccess {
				continue
			}
			hostSeen = true
			for _, ip := range upstreams.ExtractIPs(resp.Answer) {
				ipSet[ip] = true
			}
		}
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		ips = filterExcludedIPs(ips, r.excludeSubnets)
		if hostSeen && len(ips) > 0 && shouldWriteOutputs(ruleOutputs, true) {
			ctx, cancel := context.WithTimeout(context.Background(), r.httpTimeout)
			defer cancel()
			for _, target := range r.outputs {
				if target.Webhook == nil {
					continue
				}
				if !shouldWriteTarget(ruleOutputs, target.ID) {
					continue
				}
				if err := target.Webhook.Send(ctx, ruleList, domain, ips); err != nil {
					slog.Error("webhook send", "url", target.Webhook.URL(), "error", err)
				}
			}
		}
		for _, target := range r.outputs {
			if target.Writer == nil {
				continue
			}
			if !shouldWriteTarget(ruleOutputs, target.ID) {
				continue
			}
			writer := target.Writer
			effectiveList := ruleList
			if effectiveList == "" {
				effectiveList = writer.DefaultListName()
			}
			if effectiveList == "" {
				continue
			}

			switch writer.OutputType() {
			case outputs.OutputFile:
				for _, ip := range ips {
					r.writeAddress(writer, effectiveList, domain, ip)
				}
			case outputs.OutputRouterOS:
				effectiveRecordType := writer.DefaultRecordType()
				if effectiveRecordType == "host" {
					if hostSeen {
						r.writeAddress(writer, effectiveList, domain, domain)
					}
					break
				}
				for _, ip := range ips {
					r.writeAddress(writer, effectiveList, domain, ip)
				}
			default:
				for _, ip := range ips {
					r.writeAddress(writer, effectiveList, domain, ip)
				}
			}
		}
	}()
}

func (r *Resolver) writeAddress(writer outputs.AddressWriter, listName, domain, address string) {
	if err := writer.EnsureAddress(listName, domain, address, nil, nil); err != nil {
		slog.Error("write address", writeAddressAttrs(DNSLog{
			List:    listName,
			Domain:  domain,
			Address: address,
		}, err)...)
	}
}

func (r *Resolver) resolveParallel(req *dns.Msg, upstreamsList []upstreams.Upstream) (*dns.Msg, string, <-chan *dns.Msg, string, error) {
	resp, upstream, allCh, reason, ok := r.resolvePrimary(req, upstreamsList)
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

func (r *Resolver) resolvePrimary(req *dns.Msg, upstreamsList []upstreams.Upstream) (*dns.Msg, string, <-chan *dns.Msg, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)

	type result struct {
		resp     *dns.Msg
		err      error
		upstream string
		duration time.Duration
	}

	resCh := make(chan result, len(upstreamsList))

	var wg sync.WaitGroup
	for _, upstream := range upstreamsList {
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
			reqCtx, cancel := context.WithTimeout(ctx, r.dnsTimeout)
			defer cancel()
			switch upstream.Kind {
			case "udp", "tcp":
				resp, rtt, err = upstreams.ExchangeDNS(reqCtx, upstream.Kind, upstream.Address, req, r.dnsTimeout)
			case "dot":
				resp, rtt, err = upstreams.ExchangeDoT(reqCtx, upstream, req, r.dnsTimeout)
			case "doh":
				resp, rtt, err = upstreams.ExchangeDoH(reqCtx, r.dohHTTP, upstream.URL, req)
			default:
				err = fmt.Errorf("unknown upstream kind %q", upstream.Kind)
			}
			upLabel := upstreams.Label(upstream)
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
			if upstream.Kind == "udp" || upstream.Kind == "tcp" {
				checkEDNS(req, resp, upLabel, qname)
			}
			addresses := upstreams.ExtractIPs(resp.Answer)
			if len(addresses) > 1 {
				sort.Strings(addresses)
			}
			slog.Debug("upstream resolve", upstreamResultAttrs(DNSLog{
				Qname:     qname,
				Qtype:     qtype,
				Upstream:  upLabel,
				Rcode:     dns.RcodeToString[resp.Rcode],
				Answers:   len(resp.Answer),
				Duration:  rtt,
				Addresses: addresses,
			}, nil)...)
		}()
	}

	go func() {
		wg.Wait()
		close(resCh)
		cancel()
	}()

	allCh := make(chan *dns.Msg, len(upstreamsList))
	firstCh := make(chan result, 1)
	reasonCh := make(chan string, 1)

	qtype := uint16(0)
	if len(req.Question) > 0 {
		qtype = req.Question[0].Qtype
	}

	go func() {
		firstSent := false
		errs := make([]string, 0, len(upstreamsList))
		normalSeen := false
		for res := range resCh {
			if res.err != nil {
				errs = append(errs, res.err.Error())
				continue
			}
			allCh <- res.resp
			hasAddress := upstreams.ResponseHasAddress(res.resp, qtype)
			if hasAddress {
				normalSeen = true
			}
			if !firstSent && hasAddress {
				firstSent = true
				firstCh <- res
			}
		}
		if !firstSent {
			if len(errs) == len(upstreamsList) && len(errs) > 0 {
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
			reqCtx, cancel := context.WithTimeout(ctx, r.dnsTimeout)
			defer cancel()
			switch upstream.Kind {
			case "udp", "tcp":
				resp, rtt, err = upstreams.ExchangeDNS(reqCtx, upstream.Kind, upstream.Address, req, r.dnsTimeout)
			case "dot":
				resp, rtt, err = upstreams.ExchangeDoT(reqCtx, upstream, req, r.dnsTimeout)
			case "doh":
				resp, rtt, err = upstreams.ExchangeDoH(reqCtx, r.dohHTTP, upstream.URL, req)
			default:
				err = fmt.Errorf("unknown upstream kind %q", upstream.Kind)
			}
			upLabel := "fallback:" + upstreams.Label(upstream)
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
			if upstream.Kind == "udp" || upstream.Kind == "tcp" {
				checkEDNS(req, resp, upLabel, qname)
			}
			addresses := upstreams.ExtractIPs(resp.Answer)
			if len(addresses) > 1 {
				sort.Strings(addresses)
			}
			slog.Debug("upstream resolve", upstreamResultAttrs(DNSLog{
				Qname:     qname,
				Qtype:     qtype,
				Upstream:  upLabel,
				Rcode:     dns.RcodeToString[resp.Rcode],
				Answers:   len(resp.Answer),
				Duration:  rtt,
				Addresses: addresses,
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

func filterExcludedIPs(ips []string, subnets []*net.IPNet) []string {
	if len(ips) == 0 || len(subnets) == 0 {
		return ips
	}
	filtered := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			filtered = append(filtered, ip)
			continue
		}
		excluded := false
		for _, subnet := range subnets {
			if subnet != nil && subnet.Contains(parsed) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

func ednsCookie(msg *dns.Msg) (string, bool) {
	if msg == nil {
		return "", false
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return "", false
	}
	for _, option := range opt.Option {
		if cookie, ok := option.(*dns.EDNS0_COOKIE); ok {
			return cookie.Cookie, true
		}
	}
	return "", false
}

func checkEDNS(req *dns.Msg, resp *dns.Msg, upstreamLabel string, qname string) {
	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		return
	}
	respOpt := resp.IsEdns0()
	if respOpt == nil {
		slog.Warn("upstream missing EDNS response", "qname", qname, "upstream", upstreamLabel)
		return
	}
	reqCookie, reqHasCookie := ednsCookie(req)
	if !reqHasCookie {
		return
	}
	respCookie, respHasCookie := ednsCookie(resp)
	if !respHasCookie || respCookie != reqCookie {
		slog.Warn("upstream EDNS cookie mismatch", "qname", qname, "upstream", upstreamLabel)
	}
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

func (r *Resolver) matchDomain(qname string) (bool, config.DomainRule, int) {
	if len(r.rules) == 0 {
		return true, config.DomainRule{}, -1
	}
	name := strings.TrimSuffix(strings.ToLower(qname), ".")
	labels := strings.Split(name, ".")

	for i, rule := range r.rules {
		if rule.Domain == "" {
			continue
		}
		domain := rule.Domain
		if name == domain {
			return true, rule, i
		}
		if !rule.MatchSubDomains {
			continue
		}
		if strings.HasSuffix(name, "."+domain) {
			if rule.MaxDepth == nil {
				return true, rule, i
			}
			domainLabels := strings.Split(domain, ".")
			depth := len(labels) - len(domainLabels)
			if depth <= *rule.MaxDepth {
				return true, rule, i
			}
		}
	}
	return false, config.DomainRule{}, -1
}

func normalizeOutputs(outputsList []string) []string {
	if outputsList == nil {
		return nil
	}
	out := make([]string, 0, len(outputsList))
	for _, id := range outputsList {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		out = append(out, id)
	}
	return out
}

func shouldWriteOutputs(outputsList []string, hasAddresses bool) bool {
	if outputsList == nil {
		return hasAddresses
	}
	return len(outputsList) > 0 && hasAddresses
}

func shouldWriteTarget(outputsList []string, id string) bool {
	if outputsList == nil {
		return true
	}
	if len(outputsList) == 0 {
		return false
	}
	for _, allowed := range outputsList {
		if allowed == id {
			return true
		}
	}
	return false
}
