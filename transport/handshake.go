package transport

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/path"
)

// handshake.go drives the NK handshake over DNS so a session establishes itself
// end-to-end: the client knows only the server's pinned static public key, and
// the server mints a session id + keys on the fly and registers the session.
//
//	client                                   server (Listener)
//	------                                   -----------------
//	ClientInit ─ HANDSHAKE_INIT in QNAME ──▶ ServerProcessInit → mint sid+keys,
//	                (session id 0)            register ServerSession
//	ClientProcessResp ◀─ HANDSHAKE_RESP in ─ return RESP (carries sid)
//	  → derives sid+keys                      TXT response
//
// HANDSHAKE_INIT/RESP are the raw handshake wire format (not sealed datagrams);
// they ride a query/response just like data. Session id 0 is reserved to mark a
// query as a handshake; real sessions use 1..65535.

// HandshakeSessionID is the reserved id marking a query as a handshake message.
const HandshakeSessionID uint16 = 0

const (
	handshakeVersion = 0x01 // PROTOCOL.md §3.2 wire: [version][msg_type]...
	handshakeMsgInit = 0x01 // HANDSHAKE_INIT

	hsCacheTTL       = 30 * time.Second
	defaultReplayWin = 4096

	defaultIdleTimeout = 10 * time.Minute
	reapInterval       = 1 * time.Minute

	// Handshake envelope (transport-level, wrapping the §3.2 INIT/RESP). The first
	// byte of the query/response payload tags the message.
	hsFlagNoCookie  = 0x00 // query: bare INIT (first attempt)
	hsFlagCookie    = 0x01 // query: [cookie][INIT]
	hsKindChallenge = 0x00 // response: [cookie] — prove return-routability, no state
	hsKindAccept    = 0x01 // response: [RESP_wire] — session minted

	cookieLen        = 16
	cookieWindowSecs = 30 // cookie valid for the current and previous window
)

var (
	// ErrHandshakeFailed is returned by Dial when no attempt produced a valid response.
	ErrHandshakeFailed = errors.New("handofgod/transport: handshake failed")
	// ErrNoPath is returned by Dial when no path is available to handshake over.
	ErrNoPath = errors.New("handofgod/transport: no path available for handshake")
)

// ── Server: Listener ──────────────────────────────────────────────────────────

// ListenerConfig configures the authoritative-side handshake acceptor.
type ListenerConfig struct {
	// ServerStatic is the server's long-term key pair; its public half is what
	// clients pin.
	ServerStatic *crypto.KeyPair
	// Caps is the server capability bitfield advertised in ServerHello.
	Caps uint16
	// Zone is the authoritative zone (for documentation/consistency).
	Zone string
	// OnData receives in-order application data, tagged with its session id.
	OnData func(sessionID, streamID uint16, data []byte)
	// OnAccept is invoked once per newly established session (optional), e.g. so
	// the application can send downstream on it.
	OnAccept func(s *ServerSession, sessionID uint16)
	// ReplayWindow sizes each session's anti-replay window (default 4096).
	ReplayWindow uint64
	// IdleTimeout evicts a session after this long with no inbound query
	// (default 10m). The reaper is the backstop for clients that vanish.
	IdleTimeout time.Duration
	// ReapInterval is how often the reaper runs (default 1m).
	ReapInterval time.Duration
	// DisableCookie turns off the return-routability cookie. By default (false) the
	// server issues a stateless cookie challenge and only mints a session once the
	// client echoes a valid cookie — so blind/spoofed INIT floods can't create
	// state. Disable only on trusted paths where the extra round-trip isn't wanted.
	DisableCookie bool
	// CookieSecret keys the cookie HMAC; a random one is generated if empty.
	CookieSecret []byte
}

type hsEntry struct {
	resp []byte
	at   time.Time
}

// Listener accepts handshakes and routes data, letting one authoritative server
// host many self-establishing sessions. Its HandleUpstream is the wire.Server
// Handler. Safe for concurrent use.
type Listener struct {
	ctx context.Context
	cfg ListenerConfig
	mgr *ServerManager

	cookieSecret []byte

	mu      sync.Mutex
	nextSID uint16
	cache   map[string]hsEntry // client ephemeral pub -> cached response (idempotency)
}

// NewListener creates a handshake-accepting session router. Spawned sessions run
// until ctx is cancelled.
func NewListener(ctx context.Context, cfg ListenerConfig) *Listener {
	if cfg.ReplayWindow == 0 {
		cfg.ReplayWindow = defaultReplayWin
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.ReapInterval <= 0 {
		cfg.ReapInterval = reapInterval
	}
	secret := cfg.CookieSecret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	l := &Listener{
		ctx:          ctx,
		cfg:          cfg,
		mgr:          NewServerManager(),
		cache:        make(map[string]hsEntry),
		cookieSecret: secret,
	}
	if ctx != nil {
		go l.reapLoop()
	}
	return l
}

// reapLoop periodically evicts idle sessions until the listener's context ends.
func (l *Listener) reapLoop() {
	t := time.NewTicker(l.cfg.ReapInterval)
	defer t.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-t.C:
			l.mgr.Reap(l.cfg.IdleTimeout)
		}
	}
}

// Manager exposes the underlying session router (for stats/inspection).
func (l *Listener) Manager() *ServerManager { return l.mgr }

// HandleUpstream is the wire.Server Handler: a handshake query (session id 0)
// mints a session; everything else routes to its established session.
func (l *Listener) HandleUpstream(datagram []byte, sessionID uint16) []byte {
	if sessionID == HandshakeSessionID {
		return l.handleHandshake(datagram)
	}
	return l.mgr.HandleUpstream(datagram, sessionID)
}

func (l *Listener) handleHandshake(payload []byte) []byte {
	flag, cookie, initWire := parseHsQuery(payload)
	// Cheap structural check rejects cover/garbage without crypto work or sid use.
	if len(initWire) < 2+crypto.KeySize || initWire[0] != handshakeVersion || initWire[1] != handshakeMsgInit {
		return nil
	}
	ephPub := initWire[2 : 2+crypto.KeySize]
	ephKey := string(ephPub)

	// Return-routability gate: until the client echoes a valid cookie, answer with
	// a stateless challenge — no session id, no keys, no memory committed. This
	// stops blind/spoofed INIT floods from creating state, since the challenge is
	// only delivered to the (real) source that the query came from.
	if !l.cfg.DisableCookie {
		if flag != hsFlagCookie || !l.validCookie(ephPub, cookie) {
			return buildHsResp(hsKindChallenge, l.makeCookie(ephPub, currentCookieBucket()))
		}
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Idempotency: a retransmitted or multi-path-duplicated INIT (same client
	// ephemeral) returns the same response, so we don't mint duplicate sessions.
	l.pruneCacheLocked(now)
	if e, ok := l.cache[ephKey]; ok {
		return buildHsResp(hsKindAccept, e.resp)
	}

	sid := l.allocSIDLocked()
	if sid == HandshakeSessionID {
		return nil // session table full
	}

	respWire, keys, clientHello, err := crypto.ServerProcessInit(l.cfg.ServerStatic, initWire, sid, l.cfg.Caps)
	if err != nil {
		return nil // not a valid INIT under our static key → cover
	}
	aead := crypto.NegotiateAEAD(clientHello.Caps, l.cfg.Caps)
	sealer, err1 := crypto.NewSealerAEAD(keys.RxKey, crypto.DirServerToClient, aead)
	opener, err2 := crypto.NewOpenerAEAD(keys.TxKey, crypto.DirClientToServer, l.cfg.ReplayWindow, aead)
	if err1 != nil || err2 != nil {
		return nil
	}

	sess := NewServerSession(ServerConfig{
		SessionID: sid,
		Sealer:    sealer,
		Opener:    opener,
		Deliver: func(streamID uint16, data []byte) {
			if l.cfg.OnData != nil {
				l.cfg.OnData(sid, streamID, data)
			}
		},
	})
	// On a peer SESSION_CLOSE, evict immediately (the reaper is the idle backstop).
	sess.setOnClose(func() {
		l.mgr.Remove(sid)
		sess.Close()
	})
	l.mgr.Register(sid, sess) // registered under l.mu so allocSID can't reuse sid
	l.cache[ephKey] = hsEntry{resp: respWire, at: now}

	if l.ctx != nil {
		go sess.Run(l.ctx)
	}
	if l.cfg.OnAccept != nil {
		// Call without holding l.mu would be cleaner, but OnAccept is light and
		// must not call back into the listener; documented accordingly.
		l.cfg.OnAccept(sess, sid)
	}
	return buildHsResp(hsKindAccept, respWire)
}

// ── Handshake envelope + cookie helpers ────────────────────────────────────────

func parseHsQuery(payload []byte) (flag byte, cookie, initWire []byte) {
	if len(payload) < 1 {
		return 0xff, nil, nil
	}
	flag = payload[0]
	rest := payload[1:]
	if flag == hsFlagCookie {
		if len(rest) < cookieLen {
			return 0xff, nil, nil
		}
		return flag, rest[:cookieLen], rest[cookieLen:]
	}
	return flag, nil, rest
}

func buildHsQuery(cookie, initWire []byte) []byte {
	if len(cookie) == 0 {
		return append([]byte{hsFlagNoCookie}, initWire...)
	}
	out := make([]byte, 0, 1+len(cookie)+len(initWire))
	out = append(out, hsFlagCookie)
	out = append(out, cookie...)
	out = append(out, initWire...)
	return out
}

func buildHsResp(kind byte, body []byte) []byte {
	return append([]byte{kind}, body...)
}

func parseHsResp(payload []byte) (kind byte, body []byte, ok bool) {
	if len(payload) < 1 {
		return 0, nil, false
	}
	return payload[0], payload[1:], true
}

func currentCookieBucket() int64 { return time.Now().Unix() / cookieWindowSecs }

// makeCookie is a stateless HMAC over the client ephemeral key and a time bucket.
func (l *Listener) makeCookie(ephPub []byte, bucket int64) []byte {
	mac := hmac.New(sha256.New, l.cookieSecret)
	mac.Write(ephPub)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	mac.Write(b[:])
	return mac.Sum(nil)[:cookieLen]
}

// validCookie accepts a cookie minted in the current or previous window, so a
// handshake that crosses a bucket boundary still verifies.
func (l *Listener) validCookie(ephPub, cookie []byte) bool {
	if len(cookie) != cookieLen {
		return false
	}
	bucket := currentCookieBucket()
	return hmac.Equal(cookie, l.makeCookie(ephPub, bucket)) ||
		hmac.Equal(cookie, l.makeCookie(ephPub, bucket-1))
}

// allocSIDLocked returns a fresh, non-zero, unused session id (caller holds mu).
func (l *Listener) allocSIDLocked() uint16 {
	for i := 0; i < 0xffff; i++ {
		l.nextSID++
		if l.nextSID == HandshakeSessionID {
			l.nextSID = 1
		}
		if l.mgr.Get(l.nextSID) == nil {
			return l.nextSID
		}
	}
	return HandshakeSessionID // table full
}

func (l *Listener) pruneCacheLocked(now time.Time) {
	for k, e := range l.cache {
		if now.Sub(e.at) > hsCacheTTL {
			delete(l.cache, k)
		}
	}
}

// ── Client: Dial ───────────────────────────────────────────────────────────────

// DialConfig configures a client handshake.
type DialConfig struct {
	// ServerStaticPub is the pinned server static public key.
	ServerStaticPub [crypto.KeySize]byte
	// Caps is the client capability bitfield.
	Caps uint16
	// Zone is the authoritative zone to query under.
	Zone string
	// Mode is the label-entropy mode (must match the server). Default "raw".
	Mode string
	// Engine is the path engine the established session transmits over.
	Engine *path.Engine
	// HandshakePaths are tried in order for the handshake; if empty, the engine's
	// currently-selected paths are used.
	HandshakePaths []*path.Path
	// RoundTrip performs a synchronous query (e.g. wire.Client.RoundTrip).
	RoundTrip func(q dns.Query, p *path.Path) ([]byte, error)
	// WireSend is the established session's async send (e.g. wire.Client.Send).
	WireSend func(q dns.Query, p *path.Path) error
	// Deliver receives the established session's in-order downstream data.
	Deliver func(streamID uint16, data []byte)
	// OnClose is invoked if the server tears the session down. Optional.
	OnClose func(code byte)
	// Controller optionally overrides the session's adaptive controller.
	Controller *dns.AdaptiveController
	// ReplayWindow sizes the session's anti-replay window (default 4096).
	ReplayWindow uint64
	// Attempts bounds handshake retries across the paths (default 5).
	Attempts int
}

// Dial performs the NK handshake over DNS and returns an established Session. The
// caller then runs and uses the session as usual. Only the server's static
// public key needs to be known in advance.
func Dial(cfg DialConfig) (*Session, error) {
	if cfg.Mode == "" {
		cfg.Mode = "raw"
	}
	if cfg.Zone == "" {
		cfg.Zone = "example.com"
	}
	if cfg.ReplayWindow == 0 {
		cfg.ReplayWindow = defaultReplayWin
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 5
	}
	if cfg.RoundTrip == nil {
		return nil, errors.New("handofgod/transport: Dial requires RoundTrip")
	}

	init, err := crypto.ClientInit(cfg.ServerStaticPub, cfg.Caps)
	if err != nil {
		return nil, err
	}

	paths := cfg.HandshakePaths
	if len(paths) == 0 && cfg.Engine != nil {
		paths = cfg.Engine.SelectPaths()
	}
	if len(paths) == 0 {
		return nil, ErrNoPath
	}

	// cookie is empty on the first attempt; if the server challenges, we learn the
	// cookie and re-send it on the next attempt (return-routability round-trip).
	var cookie []byte
	for attempt := 0; attempt < cfg.Attempts; attempt++ {
		fqdn, err := dns.EncodeFQDNMode(buildHsQuery(cookie, init.Wire), HandshakeSessionID, cfg.Zone, cfg.Mode)
		if err != nil {
			return nil, err
		}
		q := dns.Query{FQDN: fqdn, Type: dns.TypeTXT, SessionID: HandshakeSessionID}

		for _, p := range paths {
			resp, err := cfg.RoundTrip(q, p)
			if err != nil || resp == nil {
				continue
			}
			kind, body, ok := parseHsResp(resp)
			if !ok {
				continue
			}
			if kind == hsKindChallenge {
				if len(body) == cookieLen {
					cookie = body // retry with the cookie on the next attempt
				}
				break
			}
			// kind == hsKindAccept: body is the HANDSHAKE_RESP wire.
			sid, keys, aead, err := crypto.ClientProcessResp(init.Ephemeral, cfg.ServerStaticPub, init.Hello, body)
			if err != nil {
				continue // cover/garbage — keep trying
			}
			sealer, err1 := crypto.NewSealerAEAD(keys.TxKey, crypto.DirClientToServer, aead)
			opener, err2 := crypto.NewOpenerAEAD(keys.RxKey, crypto.DirServerToClient, cfg.ReplayWindow, aead)
			if err1 != nil {
				return nil, err1
			}
			if err2 != nil {
				return nil, err2
			}
			return NewSession(Config{
				SessionID:  sid,
				Sealer:     sealer,
				Opener:     opener,
				Engine:     cfg.Engine,
				Zone:       cfg.Zone,
				Deliver:    cfg.Deliver,
				OnClose:    cfg.OnClose,
				Controller: cfg.Controller,
				WireSend:   cfg.WireSend,
			}), nil
		}
	}
	return nil, ErrHandshakeFailed
}
