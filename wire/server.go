package wire

import (
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"time"

	wdns "github.com/handofgod/dns"
	mdns "github.com/miekg/dns"
)

// UpstreamFunc processes one decoded upstream datagram for a session and returns
// at most one downstream datagram to attach to the response (nil for none — the
// client polls again on its next query). The Hand of God server's transport logic
// lives behind this callback; the wire layer treats datagrams as opaque bytes.
type UpstreamFunc func(datagram []byte, sessionID uint16) (downstream []byte)

// ServerConfig configures the authoritative-side wire adapter.
type ServerConfig struct {
	// Zone is the authoritative zone (e.g. "v.example.com").
	Zone string
	// Mode is the label-entropy mode used to decode query names (must match the
	// client's). Defaults to "raw".
	Mode string
	// Handler processes decoded upstream datagrams. If nil, every query is served
	// as cover.
	Handler UpstreamFunc
	// Mimic generates cover responses and enforces the volume circuit breaker.
	// Defaults to a ServerMimic over DefaultZoneConfig.
	Mimic *wdns.ServerMimic
	// Jitter applies ServerMimic.ResponseJitter before replying, to mimic real
	// authoritative processing variance.
	Jitter bool
}

// Server is the authoritative DNS endpoint. It decodes Hand of God queries, drives the
// Handler, and otherwise presents a plausible nameserver via ServerMimic.
type Server struct {
	cfg     ServerConfig
	srv     *mdns.Server
	started chan struct{}
}

// NewServer builds an authoritative wire adapter.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Zone == "" {
		cfg.Zone = "example.com"
	}
	if cfg.Mode == "" {
		cfg.Mode = "raw"
	}
	if cfg.Mimic == nil {
		zc := wdns.DefaultZoneConfig()
		zc.Zone = cfg.Zone
		cfg.Mimic = wdns.NewServerMimic(zc)
	}
	return &Server{cfg: cfg, started: make(chan struct{})}
}

// Serve activates the server on an existing packet conn. Tests pass a
// 127.0.0.1:0 conn and read its LocalAddr; production typically uses
// ListenAndServe(":53").
func (s *Server) Serve(pc net.PacketConn) error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.srv = &mdns.Server{
		PacketConn:        pc,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: s.notifyStarted,
	}
	return s.srv.ActivateAndServe()
}

// ListenAndServe binds and serves UDP on addr.
func (s *Server) ListenAndServe(addr string) error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.srv = &mdns.Server{
		Addr:              addr,
		Net:               "udp",
		Handler:           mux,
		NotifyStartedFunc: s.notifyStarted,
	}
	return s.srv.ListenAndServe()
}

func (s *Server) notifyStarted() {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
}

// Started is closed once the server is accepting queries.
func (s *Server) Started() <-chan struct{} { return s.started }

// Shutdown stops the server.
func (s *Server) Shutdown() error {
	if s.srv != nil {
		return s.srv.Shutdown()
	}
	return nil
}

func (s *Server) handle(w mdns.ResponseWriter, r *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true
	if opt := r.IsEdns0(); opt != nil {
		resp.SetEdns0(4096, false)
	}

	if len(r.Question) == 1 {
		q := r.Question[0]
		datagram, sid, err := wdns.DecodeFQDNMode(q.Name, s.cfg.Zone, s.cfg.Mode)
		if err == nil && s.cfg.Mimic.ShouldAcceptTunnelQuery() {
			var down []byte
			if s.cfg.Handler != nil {
				down = s.cfg.Handler(datagram, sid)
			}
			attachTXTDatagram(resp, q.Name, down)
		} else {
			s.attachCover(resp, q)
		}
	}

	if s.cfg.Jitter {
		time.Sleep(s.cfg.Mimic.ResponseJitter())
	}
	_ = w.WriteMsg(resp)
}

// attachTXTDatagram embeds one downstream datagram as base64url TXT RDATA,
// chunked across character-strings. base64 is required because DNS TXT is not a
// binary-safe channel through miekg (presentation-form escaping on unpack). No
// downstream → NOERROR with no answer; the client polls again on its next query.
func attachTXTDatagram(resp *mdns.Msg, name string, down []byte) {
	if len(down) == 0 {
		return
	}
	b64 := base64.RawURLEncoding.EncodeToString(down)
	chunks := wdns.EncodeTXTValues([]byte(b64))
	strs := make([]string, len(chunks))
	for i, c := range chunks {
		strs[i] = string(c)
	}
	// TTL 0: tunnel data must never be cached by a recursive resolver, so a
	// retransmit (same seq → same query name) always reaches the server fresh
	// rather than getting a stale cached answer.
	hdr := mdns.RR_Header{Name: name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 0}
	resp.Answer = append(resp.Answer, &mdns.TXT{Hdr: hdr, Txt: strs})
}

// attachCover maps a ServerMimic cover decision onto concrete DNS records, so a
// non-Hand of God query (censor probe, stray lookup, circuit-broken query) gets a
// plausible authoritative answer instead of a tunnel fingerprint.
func (s *Server) attachCover(resp *mdns.Msg, q mdns.Question) {
	cr := s.cfg.Mimic.CoverResponseFor(q.Name, wdns.RecordType(q.Qtype))
	switch cr.Type {
	case wdns.CoverResponseNXDOMAIN:
		resp.Rcode = mdns.RcodeNameError
	case wdns.CoverResponseA:
		if ip := net.ParseIP(string(cr.Value)); ip != nil && ip.To4() != nil {
			resp.Answer = append(resp.Answer, &mdns.A{Hdr: rrHeader(q.Name, mdns.TypeA), A: ip.To4()})
		}
	case wdns.CoverResponseAAAA:
		if ip := net.ParseIP(string(cr.Value)); ip != nil {
			resp.Answer = append(resp.Answer, &mdns.AAAA{Hdr: rrHeader(q.Name, mdns.TypeAAAA), AAAA: ip})
		}
	case wdns.CoverResponseTXT:
		resp.Answer = append(resp.Answer, &mdns.TXT{Hdr: rrHeader(q.Name, mdns.TypeTXT), Txt: []string{string(cr.Value)}})
	case wdns.CoverResponseCNAME:
		resp.Answer = append(resp.Answer, &mdns.CNAME{Hdr: rrHeader(q.Name, mdns.TypeCNAME), Target: mdns.Fqdn(string(cr.Value))})
	case wdns.CoverResponseSOA:
		if soa := soaRecord(q.Name, cr.Value); soa != nil {
			resp.Answer = append(resp.Answer, soa)
		}
	default:
		// HTTPS/unknown cover: NOERROR with no answer.
	}
}

func rrHeader(name string, rrtype uint16) mdns.RR_Header {
	return mdns.RR_Header{Name: name, Rrtype: rrtype, Class: mdns.ClassINET, Ttl: 60}
}

// soaRecord parses ServerMimic's textual SOA ("ns mbox serial refresh retry
// expire minttl") into a concrete SOA record.
func soaRecord(name string, value []byte) *mdns.SOA {
	f := strings.Fields(string(value))
	if len(f) < 7 {
		return nil
	}
	u := func(s string) uint32 {
		n, _ := strconv.ParseUint(s, 10, 32)
		return uint32(n)
	}
	return &mdns.SOA{
		Hdr:     rrHeader(name, mdns.TypeSOA),
		Ns:      mdns.Fqdn(f[0]),
		Mbox:    mdns.Fqdn(f[1]),
		Serial:  u(f[2]),
		Refresh: u(f[3]),
		Retry:   u(f[4]),
		Expire:  u(f[5]),
		Minttl:  u(f[6]),
	}
}
