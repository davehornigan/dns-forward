package upstreams

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultDoTIdleTimeout is how long an unused connection is kept. RFC 7858
	// asks clients to reuse connections; servers commonly close them after
	// something like this, so we drop ours first rather than fail a query.
	defaultDoTIdleTimeout = 25 * time.Second
	// defaultDoTPerUpstream bounds how many connections we hold to one server.
	defaultDoTPerUpstream = 4
)

type pooledDoTConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

// DoTPool keeps TLS connections to DoT upstreams open between queries. Dialing
// afresh costs a TCP round trip plus a two round trip TLS handshake, which
// dwarfs the query itself; reusing a connection removes all of it.
type DoTPool struct {
	mu          sync.Mutex
	idle        map[string][]*pooledDoTConn
	sessions    tls.ClientSessionCache
	idleTimeout time.Duration
	perUpstream int
	closed      bool
}

func NewDoTPool() *DoTPool {
	return &DoTPool{
		idle: make(map[string][]*pooledDoTConn),
		// Even when a fresh connection is unavoidable, a cached TLS session
		// lets the handshake resume instead of running in full.
		sessions:    tls.NewLRUClientSessionCache(64),
		idleTimeout: defaultDoTIdleTimeout,
		perUpstream: defaultDoTPerUpstream,
	}
}

// get returns an idle connection for the upstream, or nil when none is usable.
func (p *DoTPool) get(address string) *dns.Conn {
	if p == nil {
		return nil
	}
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.idle[address]
	for len(conns) > 0 {
		last := conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		if now.Sub(last.lastUsed) < p.idleTimeout {
			p.idle[address] = conns
			return last.conn
		}
		last.conn.Close() // idle too long to trust
	}
	delete(p.idle, address)
	return nil
}

// put returns a healthy connection to the pool.
func (p *DoTPool) put(address string, conn *dns.Conn) {
	if p == nil || conn == nil {
		return
	}
	p.mu.Lock()
	if p.closed || len(p.idle[address]) >= p.perUpstream {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.idle[address] = append(p.idle[address], &pooledDoTConn{conn: conn, lastUsed: time.Now()})
	p.mu.Unlock()
}

// Close drops every pooled connection.
func (p *DoTPool) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for address, conns := range p.idle {
		for _, pooled := range conns {
			pooled.conn.Close()
		}
		delete(p.idle, address)
	}
}

func (p *DoTPool) dial(ctx context.Context, upstream Upstream, timeout time.Duration) (*dns.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		ServerName:         upstream.ServerNI,
		ClientSessionCache: p.sessionCache(),
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", upstream.Address, tlsConfig)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return &dns.Conn{Conn: conn}, nil
}

func (p *DoTPool) sessionCache() tls.ClientSessionCache {
	if p == nil {
		return nil
	}
	return p.sessions
}

// ExchangeDoT sends a query over a pooled TLS connection, falling back to a
// fresh one when the pooled connection turns out to be dead. A pooled
// connection can be closed by the server at any time, and that only shows up
// when we try to use it, so one retry on a fresh connection is expected rather
// than exceptional.
func ExchangeDoT(ctx context.Context, pool *DoTPool, upstream Upstream, req *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	if conn := pool.get(upstream.Address); conn != nil {
		resp, err := exchangeOn(ctx, conn, req, timeout)
		if err == nil {
			pool.put(upstream.Address, conn)
			return resp, time.Since(start), nil
		}
		conn.Close()
	}

	conn, err := pool.dial(ctx, upstream, timeout)
	if err != nil {
		return nil, time.Since(start), err
	}
	resp, err := exchangeOn(ctx, conn, req, timeout)
	if err != nil {
		conn.Close()
		return nil, time.Since(start), err
	}
	pool.put(upstream.Address, conn)
	return resp, time.Since(start), nil
}

// exchangeOn runs one query on a connection, matching the reply to the request
// id: a stale reply left over from an earlier timed-out query would otherwise
// be handed back as the answer to this one.
func exchangeOn(ctx context.Context, conn *dns.Conn, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(req); err != nil {
		return nil, err
	}
	for {
		resp, err := conn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if resp.Id == req.Id {
			return resp, nil
		}
	}
}
