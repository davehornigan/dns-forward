package upstreams

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Upstream struct {
	Raw      string
	Kind     string
	Address  string
	URL      *url.URL
	ServerNI string
}

func ParseUpstreams(raw []string) ([]Upstream, error) {
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
			host, port, err := ParseHostPortDefault(entry, "53")
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

func ParseHostPortDefault(input, defaultPort string) (string, string, error) {
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

func Label(upstream Upstream) string {
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

func Labels(upstreams []Upstream) []string {
	out := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		out = append(out, Label(upstream))
	}
	return out
}

func ExchangeDoT(ctx context.Context, upstream Upstream, req *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			ServerName: upstream.ServerNI,
		},
		Timeout: timeout,
	}
	return client.ExchangeContext(ctx, req, upstream.Address)
}

func ExchangeDNS(ctx context.Context, network, address string, req *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net:     network,
		Timeout: timeout,
	}
	return client.ExchangeContext(ctx, req, address)
}

func ExchangeDoH(ctx context.Context, client *http.Client, endpoint *url.URL, req *dns.Msg) (*dns.Msg, time.Duration, error) {
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

func ExtractIPs(records []dns.RR) []string {
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

func HasAnswerType(records []dns.RR, qtype uint16) bool {
	for _, rr := range records {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func ResponseHasAddress(resp *dns.Msg, qtype uint16) bool {
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return false
	}
	switch qtype {
	case dns.TypeA, dns.TypeAAAA:
		return HasAnswerType(resp.Answer, qtype)
	case dns.TypeANY:
		return len(ExtractIPs(resp.Answer)) > 0
	default:
		return true
	}
}
