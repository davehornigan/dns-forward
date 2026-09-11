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
	"github.com/davehornigan/dns-forward/internal/records"
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
	exactRules        map[string]int
	ruleUpstreams     map[int][]upstreams.Upstream
	ruleRecords       map[int]*records.Set
	outputs           []OutputTarget
	excludeSubnets    []*net.IPNet
	timeout           time.Duration
	dnsTimeout        time.Duration
	httpTimeout       time.Duration
	writeIPWithPrefix bool
	dohHTTP           *http.Client
	dotPool           *upstreams.DoTPool
	cache             *responseCache
}

type OutputTarget struct {
	ID      string
	Mode    string
	Writer  outputs.AddressWriter
	Webhook *outputs.WebhookSender
}

func New(upstreamsList []upstreams.Upstream, fallbackList []upstreams.Upstream, rules []config.DomainRule, ruleUpstreams map[int][]upstreams.Upstream, ruleRecords map[int]*records.Set, outputsList []OutputTarget, excludeSubnets []*net.IPNet, timeout, dnsTimeout, httpTimeout time.Duration, writeIPWithPrefix bool, dohHTTP *http.Client, cacheSize int, negativeTTL time.Duration) *Resolver {
	if ruleUpstreams == nil {
		ruleUpstreams = make(map[int][]upstreams.Upstream)
	}
	if ruleRecords == nil {
		ruleRecords = make(map[int]*records.Set)
	}
	return &Resolver{
		upstreams:         upstreamsList,
		fallbackUpstreams: fallbackList,
		rules:             rules,
		exactRules:        indexExactRules(rules),
		ruleUpstreams:     ruleUpstreams,
		ruleRecords:       ruleRecords,
		outputs:           outputsList,
		excludeSubnets:    excludeSubnets,
		timeout:           timeout,
		dnsTimeout:        dnsTimeout,
		httpTimeout:       httpTimeout,
		writeIPWithPrefix: writeIPWithPrefix,
		dohHTTP:           dohHTTP,
		dotPool:           upstreams.NewDoTPool(),
		cache:             newResponseCache(cacheSize, negativeTTL),
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

	if match && len(req.Question) > 0 {
		if staticResp, staticCh, ok := r.staticResponse(req, rule, r.ruleRecords[ruleIndex], upstreamsList); ok {
			_ = w.WriteMsg(staticResp)
			slog.Debug("dns reply", dnsReplyAttrs(DNSLog{
				Qname:    qname,
				Qtype:    qtype,
				Upstream: staticUpstreamLabel,
				Rcode:    dns.RcodeToString[staticResp.Rcode],
				Answers:  len(staticResp.Answer),
			})...)
			if staticCh != nil {
				r.processMatchedResponses(rule, req.Question[0], staticCh)
			}
			return
		}
	}

	if cached, ok := r.cache.get(req); ok {
		_ = w.WriteMsg(cached)
		slog.Debug("dns reply", dnsReplyAttrs(DNSLog{
			Qname:    qname,
			Qtype:    qtype,
			Upstream: cacheUpstreamLabel,
			Rcode:    dns.RcodeToString[cached.Rcode],
			Answers:  len(cached.Answer),
		})...)
		if match {
			// Keep feeding outputs: the address lists have their own lifetime
			// and may need the entry refreshed even while we answer from cache.
			r.processMatchedResponses(rule, req.Question[0], singleResponseChannel(cached))
		}
		return
	}

	disableFallback := match && rule.DisableFallback
	resp, firstUpstream, allCh, reason, err := r.resolveParallel(req, upstreamsList, disableFallback)
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
	r.cache.put(req, resp)
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
	r.processMatchedResponses(rule, q, allCh)
}

func (r *Resolver) ResolveDomain(domain string, rule config.DomainRule, ruleIndex int) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return
	}
	fqdn := dns.Fqdn(domain)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		req := new(dns.Msg)
		req.SetQuestion(fqdn, qtype)
		q := req.Question[0]

		upstreamsList := r.upstreams
		if ruleIndex >= 0 {
			if ruleUpstreams, ok := r.ruleUpstreams[ruleIndex]; ok && len(ruleUpstreams) > 0 {
				upstreamsList = ruleUpstreams
			}
		}

		if staticResp, staticCh, ok := r.staticResponse(req, rule, r.ruleRecords[ruleIndex], upstreamsList); ok {
			slog.Debug("dns reply", dnsReplyAttrs(DNSLog{
				Qname:    q.Name,
				Qtype:    dns.TypeToString[q.Qtype],
				Upstream: staticUpstreamLabel,
				Rcode:    dns.RcodeToString[staticResp.Rcode],
				Answers:  len(staticResp.Answer),
			})...)
			if staticCh != nil {
				r.processMatchedResponses(rule, q, staticCh)
			}
			continue
		}

		disableFallback := rule.DisableFallback
		resp, firstUpstream, allCh, reason, err := r.resolveParallel(req, upstreamsList, disableFallback)
		if err != nil {
			slog.Error("resolve error", resolveErrorAttrs(DNSLog{
				Qname:     q.Name,
				Qtype:     dns.TypeToString[q.Qtype],
				Upstreams: upstreams.Labels(upstreamsList),
				Reason:    reason,
			}, err)...)
			continue
		}
		slog.Debug("dns reply", dnsReplyAttrs(DNSLog{
			Qname:    q.Name,
			Qtype:    dns.TypeToString[q.Qtype],
			Upstream: firstUpstream,
			Rcode:    dns.RcodeToString[resp.Rcode],
			Answers:  len(resp.Answer),
		})...)
		r.processMatchedResponses(rule, q, allCh)
	}
}

// Labels marking where a reply came from when it did not come from an upstream.
const (
	staticUpstreamLabel = "static"
	cacheUpstreamLabel  = "cache"
)

// staticResponse answers from preconfigured records when the rule covers the
// queried name and type. Records apply to the rule's domain and, when the rule
// matches subdomains, to every subdomain it covers. The returned channel
// feeds outputs the same way upstream answers do; it is nil when there is
// nothing to emit. When the rule has no record of the queried type, ok is
// false and the query is forwarded, unless the rule sets recordsOnly.
func (r *Resolver) staticResponse(req *dns.Msg, rule config.DomainRule, set *records.Set, upstreamsList []upstreams.Upstream) (*dns.Msg, <-chan *dns.Msg, bool) {
	if set == nil || len(req.Question) == 0 {
		return nil, nil, false
	}
	q := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	if q.Qclass != dns.ClassINET || !ruleCoversName(rule, name) {
		return nil, nil, false
	}

	answers := dropSelfCNAMEs(set.Answer(q.Name, q.Qtype), q.Name)
	chased := false
	if len(answers) == 0 && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) {
		if cname := set.CNAME(q.Name); cname != nil && !isSelfCNAME(cname, q.Name) {
			answers = append(answers, cname)
			chased = true
		}
	}
	if len(answers) == 0 && !rule.RecordsOnly {
		return nil, nil, false
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.Answer = answers
	if len(answers) == 0 {
		// recordsOnly rule with nothing for this type: NODATA, no outputs.
		return resp, nil, true
	}
	if !chased {
		return resp, singleResponseChannel(resp), true
	}

	// The CNAME target is not part of this rule, so follow it upstream and
	// return the full chain; the target's addresses are what outputs need.
	target := answers[0].(*dns.CNAME).Target
	targetResp, targetCh := r.resolveCNAMETarget(target, q.Qtype, rule, upstreamsList)
	if targetResp == nil {
		return resp, singleResponseChannel(resp), true
	}
	resp.Answer = append(resp.Answer, targetResp.Answer...)
	resp.Rcode = targetResp.Rcode
	return resp, targetCh, true
}

// isSelfCNAME reports whether the record sends the resolver back to the name it
// just asked about. A rule matching subdomains can produce one even when the
// config looked fine, because the record answers under the queried name: a
// `CNAME: [www.example.com]` on a rule covering example.com and its subdomains
// becomes `www.example.com -> www.example.com` for that subdomain.
func isSelfCNAME(cname *dns.CNAME, qname string) bool {
	if cname == nil {
		return false
	}
	if !strings.EqualFold(cname.Target, dns.Fqdn(qname)) {
		return false
	}
	slog.Warn("static CNAME points at the queried name, ignoring", "qname", qname, "target", cname.Target)
	return true
}

func dropSelfCNAMEs(answers []dns.RR, qname string) []dns.RR {
	kept := answers[:0]
	for _, rr := range answers {
		if cname, ok := rr.(*dns.CNAME); ok && isSelfCNAME(cname, qname) {
			continue
		}
		kept = append(kept, rr)
	}
	return kept
}

func (r *Resolver) resolveCNAMETarget(target string, qtype uint16, rule config.DomainRule, upstreamsList []upstreams.Upstream) (*dns.Msg, <-chan *dns.Msg) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(target), qtype)
	req.RecursionDesired = true

	resp, _, allCh, reason, err := r.resolveParallel(req, upstreamsList, rule.DisableFallback)
	if err != nil {
		slog.Error("resolve cname target", resolveErrorAttrs(DNSLog{
			Qname:     req.Question[0].Name,
			Qtype:     dns.TypeToString[qtype],
			Upstreams: upstreams.Labels(upstreamsList),
			Reason:    reason,
		}, err)...)
		drainResponses(allCh)
		return nil, nil
	}
	return resp, allCh
}

func singleResponseChannel(resp *dns.Msg) <-chan *dns.Msg {
	ch := make(chan *dns.Msg, 1)
	ch <- resp
	close(ch)
	return ch
}

func drainResponses(ch <-chan *dns.Msg) {
	if ch == nil {
		return
	}
	go func() {
		for range ch {
		}
	}()
}

func (r *Resolver) processMatchedResponses(rule config.DomainRule, q dns.Question, allCh <-chan *dns.Msg) {
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
				if !shouldWriteTarget(ruleOutputs, target) {
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
			if !shouldWriteTarget(ruleOutputs, target) {
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
	effectiveAddress := address
	if r.writeIPWithPrefix {
		if ip := net.ParseIP(strings.TrimSpace(address)); ip != nil {
			if ip.To4() != nil {
				effectiveAddress = ip.String() + "/32"
			} else {
				effectiveAddress = ip.String() + "/128"
			}
		}
	}
	if err := writer.EnsureAddress(listName, domain, effectiveAddress, nil, nil); err != nil {
		slog.Error("write address", writeAddressAttrs(DNSLog{
			List:    listName,
			Domain:  domain,
			Address: effectiveAddress,
		}, err)...)
	}
}

type fallbackResult struct {
	resp     *dns.Msg
	upstream string
	reason   string
	err      error
}

// resolveParallel answers from the primary upstreams, using the fallback when
// none of them returns an address.
//
// The fallback starts as soon as the first primary comes back without an
// address, in parallel with the primaries still in flight, rather than after
// all of them have finished. A name that genuinely does not resolve used to
// cost the slowest primary plus a full fallback round trip in sequence; now the
// two overlap. Primaries usually agree, so the extra fallback query is only
// really sent when it was going to be needed anyway.
func (r *Resolver) resolveParallel(req *dns.Msg, upstreamsList []upstreams.Upstream, disableFallback bool) (*dns.Msg, string, <-chan *dns.Msg, string, error) {
	useFallback := !disableFallback && len(r.fallbackUpstreams) > 0

	var startOnce sync.Once
	fbCh := make(chan fallbackResult, 1)
	startFallback := func() {
		if !useFallback {
			return
		}
		startOnce.Do(func() {
			go func() {
				resp, upstream, reason, err := r.resolveFallback(req)
				fbCh <- fallbackResult{resp: resp, upstream: upstream, reason: reason, err: err}
			}()
		})
	}

	resp, upstream, allCh, reason, ok := r.resolvePrimary(req, upstreamsList, disableFallback, startFallback)
	if ok {
		return resp, upstream, allCh, "", nil
	}
	if disableFallback {
		if reason == "" {
			reason = "all upstreams failed"
		}
		return nil, "", allCh, reason, errors.New("all upstreams failed")
	}
	if !useFallback {
		return nil, "", allCh, reason, errors.New("all upstreams failed")
	}

	// Every primary is done and none had an address, so the fallback decides.
	// It was started at the first negative answer and may already be waiting.
	startFallback()
	fb := <-fbCh
	if fb.err != nil {
		combined := reason
		if combined == "" {
			combined = fb.reason
		} else if fb.reason != "" {
			combined = combined + "; fallback: " + fb.reason
		}
		return nil, "", allCh, combined, fb.err
	}
	return fb.resp, fb.upstream, allCh, "", nil
}

func (r *Resolver) resolvePrimary(req *dns.Msg, upstreamsList []upstreams.Upstream, disableFallback bool, onNoAddress func()) (*dns.Msg, string, <-chan *dns.Msg, string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)

	type result struct {
		resp     *dns.Msg
		err      error
		upstream string
		duration time.Duration
	}

	resCh := make(chan result, len(upstreamsList))
	dnsTimeout := r.dnsTimeout
	if disableFallback && r.timeout > 0 {
		dnsTimeout = r.timeout
	}

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
			reqCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()
			switch upstream.Kind {
			case "udp", "tcp":
				resp, rtt, err = upstreams.ExchangeDNS(reqCtx, upstream.Kind, upstream.Address, req, dnsTimeout)
			case "dot":
				resp, rtt, err = upstreams.ExchangeDoT(reqCtx, r.dotPool, upstream, req, dnsTimeout)
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
				onNoAddress()
				continue
			}
			allCh <- res.resp
			hasAddress := upstreams.ResponseHasAddress(res.resp, qtype)
			if hasAddress {
				normalSeen = true
			} else {
				// This upstream has nothing; get the fallback moving now
				// instead of waiting for the rest to come back too.
				onNoAddress()
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
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			select {
			case res, ok := <-firstCh:
				if ok {
					return res.resp, res.upstream, allCh, "", true
				}
			default:
			}
			return nil, "", allCh, "timeout", false
		}
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
		case reason, ok := <-reasonCh:
			if ok && reason != "" {
				return nil, "", allCh, reason, false
			}
			return nil, "", allCh, "all upstreams failed", false
		}
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
				resp, rtt, err = upstreams.ExchangeDoT(reqCtx, r.dotPool, upstream, req, r.dnsTimeout)
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
		return res.resp, res.upstream, "", nil
	}
	reason := "all fallback upstreams failed"
	if len(errs) > 0 {
		reason = strings.Join(errs, "; ")
	}
	return nil, "", reason, errors.New("all fallback upstreams failed")
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

// matchDomain picks the rule for a query name. A rule naming the domain exactly
// always wins over one that only covers it as a subdomain, whatever order they
// appear in; among rules of the same kind the first one in the config wins.
func (r *Resolver) matchDomain(qname string) (bool, config.DomainRule, int) {
	if len(r.rules) == 0 {
		return true, config.DomainRule{}, -1
	}
	name := strings.TrimSuffix(strings.ToLower(qname), ".")

	// Exact names are indexed, so the common case is a single map lookup and no
	// scan at all. Only a name without an exact rule walks the list, and that
	// walk stops at the first subdomain rule covering it.
	if i, ok := r.exactRules[name]; ok {
		return true, r.rules[i], i
	}
	for i, rule := range r.rules {
		if ruleCoversSubdomain(rule, name) {
			return true, rule, i
		}
	}
	return false, config.DomainRule{}, -1
}

// indexExactRules maps each domain to the first rule that applies to the domain
// itself, so an exact match never needs a scan. Rules matching only subdomains
// are left out: they must not answer for the domain they are named after.
func indexExactRules(rules []config.DomainRule) map[string]int {
	index := make(map[string]int, len(rules))
	for i, rule := range rules {
		if !rule.MatchingType.MatchesExactly() {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rule.Domain)), ".")
		if domain == "" {
			continue
		}
		if _, exists := index[domain]; !exists {
			index[domain] = i
		}
	}
	return index
}

// ruleCoversName reports whether the rule applies to name at all, either
// exactly or as a subdomain. name must be lowercase and without a trailing dot.
func ruleCoversName(rule config.DomainRule, name string) bool {
	return ruleMatchesExactly(rule, name) || ruleCoversSubdomain(rule, name)
}

func ruleMatchesExactly(rule config.DomainRule, name string) bool {
	return rule.Domain != "" && rule.MatchingType.MatchesExactly() && name == rule.Domain
}

func ruleCoversSubdomain(rule config.DomainRule, name string) bool {
	if rule.Domain == "" || !rule.MatchingType.MatchesSubdomains() {
		return false
	}
	if !strings.HasSuffix(name, "."+rule.Domain) {
		return false
	}
	if rule.MaxDepth == nil {
		return true
	}
	depth := strings.Count(name, ".") - strings.Count(rule.Domain, ".")
	return depth <= *rule.MaxDepth
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

func shouldWriteTarget(outputsList []string, target OutputTarget) bool {
	if outputsList == nil {
		return target.Mode != "passive"
	}
	if len(outputsList) == 0 {
		return false
	}
	for _, allowed := range outputsList {
		if allowed == target.ID {
			return true
		}
	}
	return false
}
