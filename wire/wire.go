// Package wire is the miekg/dns adapter that puts Hand of God on the actual network:
// it turns the neutral dns.Query/Response representation into real DNS messages
// over UDP/53, and vice versa.
//
//	Client  — satisfies transport.Config.WireSend: sends a query to a resolver and
//	          feeds the downstream datagram from the response back into the session.
//	Server  — an authoritative DNS handler: decodes the upstream datagram from the
//	          query name, hands it to the Hand of God server, attaches a downstream
//	          datagram to the response, and serves ServerMimic cover otherwise.
//
// This is the only package that imports github.com/miekg/dns; every other Hand of God
// package stays wire-agnostic via the neutral dns.Query/Response types.
package wire

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wdns "github.com/handofgod/dns"
	"github.com/handofgod/path"
	mdns "github.com/miekg/dns"
)

const defaultMaxConcurrent = 256

// ErrSaturated is returned by RoundTrip when the concurrency bound is reached.
var ErrSaturated = errors.New("handofgod/wire: concurrency limit reached")

// Inbound receives a downstream Hand of God datagram decoded from a DNS response,
// together with the path it arrived on. It is typically transport.Session.HandleInbound.
type Inbound func(datagram []byte, via *path.Path)

// ClientConfig configures the client-side wire adapter.
type ClientConfig struct {
	// Timeout bounds a single query round-trip (default 4s).
	Timeout time.Duration
	// Inbound handles the downstream datagram from each response. May be nil
	// (e.g. for pure upstream/cover probing).
	Inbound Inbound
	// EDNSUDPSize advertises a larger UDP buffer so downstream answers aren't
	// truncated (default 4096). Set <512 to disable EDNS.
	EDNSUDPSize uint16
	// MaxConcurrent bounds in-flight query round-trips. Beyond it, Send drops the
	// query (client-side backpressure) instead of spawning unbounded goroutines;
	// ARQ retransmits any dropped reliable frame. Default 256.
	MaxConcurrent int
}

// ClientStats is a snapshot of the client adapter's activity.
type ClientStats struct {
	InFlight         int    // query round-trips currently in flight
	DroppedSaturated uint64 // queries dropped because the concurrency bound was hit
}

// Client sends Hand of God queries over real DNS and routes downstream datagrams back
// into the transport. It satisfies transport.Config.WireSend via Send.
type Client struct {
	cfg ClientConfig
	udp *mdns.Client
	sem chan struct{} // bounds concurrent in-flight round-trips

	// roundTrip performs one query exchange; a field so tests can inject a stub.
	roundTrip func(m *mdns.Msg, resolver string) (*mdns.Msg, error)

	inboundMu sync.RWMutex
	inbound   Inbound // downstream handler; settable post-construction via SetInbound

	droppedSaturated uint64 // atomic
}

// NewClient builds a client-side wire adapter.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 4 * time.Second
	}
	if cfg.EDNSUDPSize == 0 {
		cfg.EDNSUDPSize = 4096
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	c := &Client{
		cfg:     cfg,
		udp:     &mdns.Client{Net: "udp", Timeout: cfg.Timeout, UDPSize: cfg.EDNSUDPSize},
		sem:     make(chan struct{}, cfg.MaxConcurrent),
		inbound: cfg.Inbound,
	}
	c.roundTrip = c.udpExchange
	return c
}

// SetInbound sets (or replaces) the downstream handler. This is the seam for the
// handshake bootstrap: create the client, Dial to establish the session, then
// point inbound at the session's HandleInbound. Safe to call concurrently.
func (c *Client) SetInbound(fn Inbound) {
	c.inboundMu.Lock()
	c.inbound = fn
	c.inboundMu.Unlock()
}

func (c *Client) currentInbound() Inbound {
	c.inboundMu.RLock()
	defer c.inboundMu.RUnlock()
	return c.inbound
}

func (c *Client) udpExchange(m *mdns.Msg, resolver string) (*mdns.Msg, error) {
	resp, _, err := c.udp.Exchange(m, resolver)
	return resp, err
}

// Send transmits one query to the path's resolver and, asynchronously, feeds any
// downstream datagram in the response to the Inbound handler. It returns nil
// immediately; transport failures are reported as path loss rather than to the
// caller, because the dns.Client scheduler must not block on a round-trip.
//
// Send has the signature required by transport.Config.WireSend.
func (c *Client) Send(q wdns.Query, p *path.Path) error {
	// Bound concurrency without blocking the scheduler: try to take a slot, and
	// if the pool is saturated drop the query. This is client-side backpressure,
	// NOT a path failure — marking the path down here would falsely trip failover;
	// ARQ retransmits any dropped reliable frame.
	select {
	case c.sem <- struct{}{}:
	default:
		atomic.AddUint64(&c.droppedSaturated, 1)
		return nil
	}

	m := c.buildMsg(q)
	go func() {
		defer func() { <-c.sem }()
		c.exchange(m, p)
	}()
	return nil
}

// RoundTrip sends one query synchronously and returns the downstream datagram
// from the response (nil if the response carried none). It is used for the
// handshake bootstrap, where the caller needs the response inline rather than via
// the async Inbound path. It honors the concurrency bound, returning ErrSaturated
// if no slot is free.
func (c *Client) RoundTrip(q wdns.Query, p *path.Path) ([]byte, error) {
	select {
	case c.sem <- struct{}{}:
	default:
		return nil, ErrSaturated
	}
	defer func() { <-c.sem }()

	resp, err := c.roundTrip(c.buildMsg(q), p.Resolver)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return extractDatagram(resp), nil
}

func (c *Client) buildMsg(q wdns.Query) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(q.FQDN), uint16(q.Type))
	m.RecursionDesired = true
	if c.cfg.EDNSUDPSize >= 512 {
		m.SetEdns0(c.cfg.EDNSUDPSize, false)
	}
	return m
}

func (c *Client) exchange(m *mdns.Msg, p *path.Path) {
	resp, err := c.roundTrip(m, p.Resolver)
	if err != nil || resp == nil {
		p.RecordResult(false) // no answer on this path counts as loss
		return
	}
	// Success/RTT on the path is recorded by the transport when the datagram
	// decodes (HandleInbound); here we only forward the bytes.
	if datagram := extractDatagram(resp); datagram != nil {
		if fn := c.currentInbound(); fn != nil {
			fn(datagram, p)
		}
	}
}

// Stats returns a snapshot of the client adapter's concurrency state.
func (c *Client) Stats() ClientStats {
	return ClientStats{
		InFlight:         len(c.sem),
		DroppedSaturated: atomic.LoadUint64(&c.droppedSaturated),
	}
}

// extractDatagram pulls a downstream Hand of God datagram out of a DNS response. The
// datagram rides base64url-encoded in TXT RDATA (one datagram, chunked across
// character-strings). base64 is required because miekg returns TXT strings in
// presentation form on unpack, which mangles raw binary; base64url chars survive
// verbatim. A cover TXT (plain text) fails base64 decode and is ignored here.
func extractDatagram(resp *mdns.Msg) []byte {
	var b strings.Builder
	found := false
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*mdns.TXT); ok {
			for _, s := range txt.Txt {
				b.WriteString(s)
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	out, err := base64.RawURLEncoding.DecodeString(b.String())
	if err != nil {
		return nil // cover or non-Hand of God TXT content
	}
	return out
}
