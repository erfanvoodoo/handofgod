// Package transport is the client-side glue that ties Hand of God's layers into one
// working data path:
//
//	app bytes ─▶ arq.Sender (seq + retransmit) ─▶ frame.EncodeDatagram (AEAD seal)
//	          ─▶ dns.Client.Send (stealth scheduling + encoding) ─▶ WireSend(top-K paths)
//
//	wire ─▶ HandleInbound ─▶ frame.DecodeDatagram (AEAD open + replay) ─▶ dispatch:
//	          DATA ─▶ arq.Receiver (reorder/dedup) ─▶ deliver + ACK
//	          ACK  ─▶ arq.Sender.OnAck (slide window, RTT)
//	          PING ─▶ PONG (echo)
//	          PONG ─▶ path RTT sample
//
// It owns the wiring between crypto, frame, arq, path and dns that those
// packages deliberately left to an integrator. The actual DNS wire send/receive
// is injected (WireSend + the caller pumping HandleInbound), so the same Session
// runs over a real resolver, a loopback, or a Phase 4 adapter. The handshake is
// performed by the caller, which constructs the directional Sealer/Opener and
// passes them in.
package transport

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/handofgod/arq"
	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/frame"
	"github.com/handofgod/path"
)

const (
	// maxPlausibleRTT caps RTT samples derived from PONGs; anything larger is a
	// stale/late echo and is discarded rather than poisoning the path estimate.
	maxPlausibleRTT = 30 * time.Second
	// pingTokenTTL bounds how long an outstanding PING token is remembered. It
	// must exceed maxPlausibleRTT so duplicated (multi-path) PONGs for one token
	// can each record their path's RTT before the token is pruned.
	pingTokenTTL = 60 * time.Second

	retransmitInterval = 20 * time.Millisecond
	probeInterval      = 5 * time.Second
	adaptInterval      = 1 * time.Second
)

// Config configures a Session. The caller completes the handshake and supplies
// the directional AEAD primitives and the path engine.
type Config struct {
	SessionID uint16
	// Sealer/Opener are the directional AEAD primitives from the handshake.
	Sealer *crypto.Sealer
	Opener *crypto.Opener
	// Engine is the path engine used for multi-path scheduling and health.
	Engine *path.Engine
	// Zone is the authoritative zone queries are sent under.
	Zone string
	// Deliver receives in-order application stream data. May be nil.
	Deliver func(streamID uint16, data []byte)
	// WireSend sends one encoded query on one path. Required in production; the
	// loopback/tests inject an in-memory implementation. Returning an error marks
	// the path as having lost that send.
	WireSend func(q dns.Query, p *path.Path) error
	// Controller optionally overrides the adaptive controller.
	Controller *dns.AdaptiveController
	// OnClose is invoked when the peer tears the session down (a SESSION_CLOSE is
	// received), with the error code. Optional.
	OnClose func(code byte)
	// WindowSize / MinRTO / MaxRTO tune the ARQ sender (sensible defaults if 0).
	WindowSize     int
	MinRTO, MaxRTO time.Duration
}

// Stats is a snapshot of a Session's transport state.
type Stats struct {
	InFlight     int    // unacked reliable frames
	Delivered    uint64 // frames delivered in order to the app
	DroppedIn    uint64 // inbound datagrams that failed to decode (cover/corrupt/replay)
	DroppedOut   uint64 // outbound datagrams dropped by the DNS scheduler (queue full or EncodeFQDNMode over the per-mode FQDN limit)
	HealthyPaths int
	Profile      string
	Level        string
}

// Session is one client↔server association's send/receive engine.
type Session struct {
	cfg        Config
	sender     *arq.Sender
	receiver   *arq.Receiver
	client     *dns.Client
	controller *dns.AdaptiveController // resolved controller (for the active entropy mode)

	// recvMu serializes inbound processing. The wire layer calls HandleInbound
	// from many goroutines (one per query round-trip), but crypto.Opener's replay
	// window is not concurrency-safe and in-order delivery must be preserved.
	recvMu sync.Mutex

	mu         sync.Mutex
	pings      map[string]time.Time // outstanding PING token -> send time
	ackPending bool                 // an ACK is owed; pulled (coalesced) per scheduler slot

	stop      chan struct{} // closed by Close to stop Run
	closeOnce sync.Once

	droppedIn uint64 // atomic
}

// NewSession wires the layers together for one session.
func NewSession(cfg Config) *Session {
	if cfg.Zone == "" {
		cfg.Zone = "example.com"
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 1024
	}
	if cfg.MinRTO <= 0 {
		cfg.MinRTO = 200 * time.Millisecond
	}
	if cfg.MaxRTO <= 0 {
		cfg.MaxRTO = 4 * time.Second
	}
	if cfg.WireSend == nil {
		cfg.WireSend = func(dns.Query, *path.Path) error { return nil }
	}
	if cfg.Controller == nil {
		cfg.Controller = dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	}

	s := &Session{
		cfg:        cfg,
		controller: cfg.Controller,
		sender:     arq.NewSender(cfg.WindowSize, cfg.MinRTO, cfg.MaxRTO),
		receiver:   arq.NewReceiver(),
		pings:      make(map[string]time.Time),
		stop:       make(chan struct{}),
	}

	s.client = dns.NewClient(dns.ClientConfig{
		SessionID:     cfg.SessionID,
		Zone:          cfg.Zone,
		Controller:    cfg.Controller,
		Transmit:      s.transmit,
		ControlSource: s.pullControl,
	})
	return s
}

// transmit is the dns.Client wire sink: it duplicates one query across the top-K
// healthy paths (PROTOCOL.md §8.2). A per-path send failure is recorded as loss;
// success is recorded when the response decodes in HandleInbound.
func (s *Session) transmit(q dns.Query) error {
	paths := s.cfg.Engine.SelectPaths()
	if len(paths) == 0 {
		return nil // no healthy path; nothing to do (engine health drives adaptation)
	}
	var firstErr error
	for _, p := range paths {
		if err := s.cfg.WireSend(q, p); err != nil {
			p.RecordResult(false)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// SessionID returns the session id (assigned by the server during the handshake).
func (s *Session) SessionID() uint16 { return s.cfg.SessionID }

// Close tears the session down: it sends a best-effort SESSION_CLOSE on the
// active paths and stops Run. Idempotent. SESSION_CLOSE is unreliable, so the
// server also reaps idle sessions as a backstop if it never arrives.
func (s *Session) Close(code byte) { s.shutdown(true, code) }

// onSessionClose handles an inbound SESSION_CLOSE from the peer: notify the app
// and stop, without echoing another close.
func (s *Session) onSessionClose(f frame.Frame) {
	code := byte(0)
	if len(f.Payload) > 0 {
		code = f.Payload[0]
	}
	if s.cfg.OnClose != nil {
		s.cfg.OnClose(code)
	}
	s.shutdown(false, code)
}

func (s *Session) shutdown(sendClose bool, code byte) {
	s.closeOnce.Do(func() {
		if sendClose && s.cfg.Engine != nil && s.cfg.WireSend != nil {
			f := frame.Frame{Type: frame.TypeSessionClose, Payload: []byte{code}}
			seq := s.sender.NextUnreliableSeq()
			dg := frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, seq, f)
			if fqdn, err := dns.EncodeFQDNMode(dg, s.cfg.SessionID, s.cfg.Zone, s.currentMode()); err == nil {
				for _, p := range s.cfg.Engine.SelectPaths() {
					_ = s.cfg.WireSend(dns.Query{FQDN: fqdn, Type: dns.TypeTXT, SessionID: s.cfg.SessionID}, p)
				}
			}
		}
		close(s.stop)
	})
}

// Run starts the scheduler and the maintenance loops (retransmission,
// path probing, and adaptive re-evaluation). It blocks until ctx is cancelled or
// the session is Closed.
func (s *Session) Run(ctx context.Context) {
	// Derive a context that Close (via s.stop) can also cancel, so teardown stops
	// the scheduler and these loops without the caller's ctx.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.stop:
		case <-ctx.Done():
		}
		cancel()
	}()

	go s.client.Run(ctx)

	retrans := time.NewTicker(retransmitInterval)
	probe := time.NewTicker(probeInterval)
	adapt := time.NewTicker(adaptInterval)
	defer retrans.Stop()
	defer probe.Stop()
	defer adapt.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-retrans.C:
			s.PumpRetransmits(now)
		case <-probe.C:
			s.SendPing()      // keep RTT fresh on active paths
			s.recoveryProbe() // re-probe excluded paths so they can recover (§8.3)
		case <-adapt.C:
			s.client.ObserveEngine(s.cfg.Engine)
		}
	}
}

// recoveryProbe sends a PING directly on each currently-unhealthy path, bypassing
// the scheduler and top-K selection (which exclude unhealthy paths). If the probe
// draws a response, HandleInbound's RecordResult(true) restores the path to the
// active set; if not, it stays excluded. This closes the §8.3 failover loop:
// without it a path that drops out never gets traffic again and can never recover.
func (s *Session) recoveryProbe() {
	for _, p := range s.cfg.Engine.RecoveryCandidates() {
		s.probePath(p)
	}
}

// probePath emits one PING aimed at a specific path, bypassing the stealth
// scheduler. Recovery probing is necessarily out-of-band because the scheduler
// only ever transmits on healthy top-K paths.
func (s *Session) probePath(p *path.Path) {
	var tok [8]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	cutoff := now.Add(-pingTokenTTL)
	for k, t := range s.pings {
		if t.Before(cutoff) {
			delete(s.pings, k)
		}
	}
	s.pings[string(tok[:])] = now
	s.mu.Unlock()

	f := frame.Frame{Type: frame.TypePing, Payload: tok[:]}
	seq := s.sender.NextUnreliableSeq()
	datagram := frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, seq, f)
	fqdn, err := dns.EncodeFQDNMode(datagram, s.cfg.SessionID, s.cfg.Zone, s.currentMode())
	if err != nil {
		return
	}
	_ = s.cfg.WireSend(dns.Query{FQDN: fqdn, Type: dns.TypeTXT, SessionID: s.cfg.SessionID}, p)
}

// currentMode resolves the active label-entropy mode from the adaptive
// controller's current profile (defaulting to "raw").
func (s *Session) currentMode() string {
	if m := s.controller.Current().LabelEntropyMode; m != "" {
		return m
	}
	return "raw"
}

// ── Outbound ──────────────────────────────────────────────────────────────────

// Write sends application data on a stream as a reliable DATA frame.
func (s *Session) Write(streamID uint16, data []byte) {
	f := frame.Frame{Type: frame.TypeData, StreamID: streamID, Payload: data}
	seq := s.sender.Next(f)
	s.transmitFrame(seq, f)
}

// OpenStream sends a reliable STREAM_OPEN for a new stream.
func (s *Session) OpenStream(streamID uint16) {
	f := frame.Frame{Type: frame.TypeStreamOpen, StreamID: streamID}
	seq := s.sender.Next(f)
	s.transmitFrame(seq, f)
}

// CloseStream sends a reliable STREAM_CLOSE (half-close) for a stream.
func (s *Session) CloseStream(streamID uint16) {
	f := frame.Frame{Type: frame.TypeStreamClose, StreamID: streamID}
	seq := s.sender.Next(f)
	s.transmitFrame(seq, f)
}

// SendPing emits a keepalive/RTT probe and returns its token. The token's send
// time is remembered so the matching PONG yields a per-path RTT sample.
func (s *Session) SendPing() []byte {
	var tok [8]byte
	_, _ = rand.Read(tok[:])

	now := time.Now()
	s.mu.Lock()
	cutoff := now.Add(-pingTokenTTL)
	for k, t := range s.pings {
		if t.Before(cutoff) {
			delete(s.pings, k)
		}
	}
	s.pings[string(tok[:])] = now
	s.mu.Unlock()

	f := frame.Frame{Type: frame.TypePing, Payload: tok[:]}
	seq := s.sender.NextUnreliableSeq()
	s.transmitFrame(seq, f)
	return tok[:]
}

// PumpRetransmits re-sends reliable frames whose RTO has expired. A retransmit
// reuses the frame's original seq, so it is the byte-identical datagram; the
// peer's replay window and ARQ dedup discard it if the original already arrived.
// Returns the number retransmitted.
func (s *Session) PumpRetransmits(now time.Time) int {
	due := s.sender.DueForRetransmit(now)
	for _, item := range due {
		s.transmitFrame(item.Seq, item.Frame)
	}
	return len(due)
}

// transmitFrame seals a frame into a datagram and queues it on the stealth
// scheduler. The actual wire send happens later via the transmit callback.
func (s *Session) transmitFrame(seq uint64, f frame.Frame) {
	datagram := frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, seq, f)
	s.client.Send(datagram)
}

// ── Inbound ───────────────────────────────────────────────────────────────────

// HandleInbound processes one received datagram that arrived over path `via`
// (which may be nil if unknown). Datagrams that fail to decode (cover traffic,
// corruption, or replays) are counted and dropped.
func (s *Session) HandleInbound(datagram []byte, via *path.Path) error {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	_, seq, f, err := frame.DecodeDatagram(s.cfg.Opener, datagram)
	if err != nil {
		atomic.AddUint64(&s.droppedIn, 1)
		return err
	}

	if via != nil {
		via.RecordResult(true)
		via.RecordDelivered(len(datagram))
	}

	switch f.Type {
	case frame.TypeData, frame.TypeStreamOpen, frame.TypeStreamClose:
		s.onReliable(seq, f)
	case frame.TypeAck:
		s.onAck(f)
	case frame.TypePing:
		s.onPing(f)
	case frame.TypePong:
		s.onPong(f, via)
	case frame.TypeSessionClose:
		s.onSessionClose(f)
	default:
		// Unknown/unhandled frame type: ignore (forward-compat).
	}
	return nil
}

// onReliable feeds a reliable frame to the receiver, delivers any now-in-order
// DATA to the app, and flags that an ACK is owed.
func (s *Session) onReliable(seq uint64, f frame.Frame) {
	delivered := s.receiver.Accept(seq, f)
	if s.cfg.Deliver != nil {
		for _, df := range delivered {
			if df.Type == frame.TypeData {
				s.cfg.Deliver(df.StreamID, df.Payload)
			}
		}
	}
	// Coalesce: just mark an ACK pending. The scheduler pulls one fresh ACK per
	// slot via pullControl (ControlSource), so a burst of DATA produces a single
	// up-to-date cumulative ACK instead of one queued ACK per frame.
	s.mu.Lock()
	s.ackPending = true
	s.mu.Unlock()
}

// pullControl is the dns.Client ControlSource: if an ACK is owed it returns one
// freshly built cumulative+selective ACK datagram (reflecting all data received
// so far) and clears the flag; otherwise nil. Called once per idle-ish slot.
func (s *Session) pullControl() []byte {
	s.mu.Lock()
	pending := s.ackPending
	s.ackPending = false
	s.mu.Unlock()
	if !pending {
		return nil
	}
	ack := s.receiver.BuildAck()
	f := frame.Frame{Type: frame.TypeAck, Payload: frame.EncodeAck(ack)}
	seq := s.sender.NextUnreliableSeq()
	return frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, seq, f)
}

func (s *Session) onAck(f frame.Frame) {
	ack, err := frame.DecodeAck(f.Payload)
	if err != nil {
		return
	}
	s.sender.OnAck(ack, time.Now())
}

func (s *Session) onPing(f frame.Frame) {
	pong := frame.Frame{Type: frame.TypePong, Payload: append([]byte(nil), f.Payload...)}
	seq := s.sender.NextUnreliableSeq()
	s.transmitFrame(seq, pong)
}

// onPong matches a PONG to its outstanding PING token and records the RTT on the
// path the PONG arrived over. This is the path RTT feed (PROTOCOL.md §6.4, §8.1).
func (s *Session) onPong(f frame.Frame, via *path.Path) {
	if len(f.Payload) < 8 {
		return
	}
	key := string(f.Payload[:8])

	s.mu.Lock()
	sentAt, ok := s.pings[key]
	s.mu.Unlock()
	if !ok {
		return // unknown/expired token
	}

	rtt := time.Since(sentAt)
	if rtt <= 0 || rtt > maxPlausibleRTT {
		return // stale/implausible
	}
	if via != nil {
		via.RecordRTT(rtt)
	}
}

// Stats returns a snapshot of the session's transport state.
func (s *Session) Stats() Stats {
	cs := s.client.Stats()
	return Stats{
		InFlight:     s.sender.Stats().InFlight,
		Delivered:    s.receiver.Stats().Delivered,
		DroppedIn:    atomic.LoadUint64(&s.droppedIn),
		DroppedOut:   cs.Dropped,
		HealthyPaths: s.cfg.Engine.HealthyCount(),
		Profile:      cs.Profile,
		Level:        cs.Level,
	}
}
