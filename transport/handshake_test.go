package transport

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/path"
	"github.com/handofgod/wire"
)

// TestHandshakeOverDNS runs the full NK handshake over real UDP DNS with the
// default ChaCha20-Poly1305, and TestHandshakeOverDNS_AESGCM repeats it with both
// peers advertising AES-256-GCM so the negotiated AEAD is exercised end to end.
func TestHandshakeOverDNS(t *testing.T)        { runHandshakeE2E(t, 0x04) }
func TestHandshakeOverDNS_AESGCM(t *testing.T) { runHandshakeE2E(t, crypto.CapAEADAESGCM|0x04) }

// runHandshakeE2E performs a full Dial→Listener handshake over UDP using the
// given caps on both sides, then verifies data flows both ways. Data flowing at
// all proves both sides negotiated and used the same AEAD (a mismatch would fail
// to decrypt).
func runHandshakeE2E(t *testing.T, caps uint16) {
	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type accepted struct {
		s   *ServerSession
		sid uint16
	}
	acceptedCh := make(chan accepted, 4)
	serverGot := make(chan []byte, 8)

	lis := NewListener(ctx, ListenerConfig{
		ServerStatic: serverStatic,
		Caps:         caps,
		Zone:         testZone,
		OnData:       func(_, _ uint16, d []byte) { serverGot <- append([]byte(nil), d...) },
		OnAccept:     func(s *ServerSession, sid uint16) { acceptedCh <- accepted{s, sid} },
	})

	// DNS wire server (rate limiter disabled: the data phase floods queries).
	zc := dns.DefaultZoneConfig()
	zc.Zone = testZone
	zc.MaxQueryRatePerMin = 0
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	wsrv := wire.NewServer(wire.ServerConfig{
		Zone: testZone, Mode: "raw", Handler: lis.HandleUpstream, Mimic: dns.NewServerMimic(zc),
	})
	go func() { _ = wsrv.Serve(pc) }()
	select {
	case <-wsrv.Started():
	case <-time.After(2 * time.Second):
		t.Fatal("wire server did not start")
	}
	defer wsrv.Shutdown()

	// Client: only the server's static public key is known up front.
	wcli := wire.NewClient(wire.ClientConfig{Timeout: 2 * time.Second})
	pcfg := path.DefaultConfig()
	eng := path.NewEngine(pcfg)
	sp := eng.AddPath(addr, testZone, pcfg.WeightLoss, pcfg.WeightLatency, pcfg.WeightThroughput)

	clientGot := make(chan []byte, 8)
	prof := &dns.Profile{
		Name:              "hs",
		RecordTypeWeights: map[uint16]float64{16: 1.0},
		QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []dns.Bucket{{Min: 4, Max: 4, Weight: 1.0}},
		IdleGapMs:         []dns.Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:    0.0,
		LabelEntropyMode:  "raw",
	}
	ctrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	ctrl.SetProfile(dns.LevelStandard, prof)

	cli, err := Dial(DialConfig{
		ServerStaticPub: serverStatic.Public,
		Caps:            caps,
		Zone:            testZone,
		Mode:            "raw",
		Engine:          eng,
		HandshakePaths:  []*path.Path{sp},
		RoundTrip:       wcli.RoundTrip,
		WireSend:        wcli.Send,
		Deliver:         func(_ uint16, d []byte) { clientGot <- append([]byte(nil), d...) },
		Controller:      ctrl,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Route downstream responses into the established session.
	wcli.SetInbound(func(dg []byte, p *path.Path) { cli.HandleInbound(dg, p) })
	go cli.Run(ctx)

	// The server accepted a session, and both sides agree on its id.
	var srv accepted
	select {
	case srv = <-acceptedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not accept a session")
	}
	if srv.sid == HandshakeSessionID {
		t.Fatalf("server assigned the reserved handshake id")
	}
	if cli.SessionID() != srv.sid {
		t.Fatalf("session id mismatch: client=%d server=%d", cli.SessionID(), srv.sid)
	}

	// Client → server.
	up := []byte("hello after handshake")
	cli.Write(1, up)
	select {
	case d := <-serverGot:
		if !bytes.Equal(d, up) {
			t.Fatalf("server upstream: got %q want %q", d, up)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("server did not receive upstream data")
	}

	// Server → client.
	down := []byte("welcome")
	srv.s.Write(1, down)
	select {
	case d := <-clientGot:
		if !bytes.Equal(d, down) {
			t.Fatalf("client downstream: got %q want %q", d, down)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("client did not receive downstream data")
	}
}

// directHandshake performs the cookie dance against a listener without the wire
// (challenge → cookied INIT → accept) and returns the established session id and
// the client's derived keys.
func directHandshake(t *testing.T, lis *Listener, serverStatic *crypto.KeyPair) (uint16, *crypto.SessionKeys) {
	t.Helper()
	init, err := crypto.ClientInit(serverStatic.Public, 0x04)
	if err != nil {
		t.Fatal(err)
	}
	kind, body, ok := parseHsResp(lis.HandleUpstream(buildHsQuery(nil, init.Wire), HandshakeSessionID))
	if !ok {
		t.Fatal("no handshake response")
	}
	if kind == hsKindChallenge {
		kind, body, ok = parseHsResp(lis.HandleUpstream(buildHsQuery(body, init.Wire), HandshakeSessionID))
		if !ok {
			t.Fatal("no response to cookied INIT")
		}
	}
	if kind != hsKindAccept {
		t.Fatalf("handshake not accepted, kind=%d", kind)
	}
	sid, keys, _, err := crypto.ClientProcessResp(init.Ephemeral, serverStatic.Public, init.Hello, body)
	if err != nil {
		t.Fatal(err)
	}
	return sid, keys
}

// TestHandshakeCookieGate verifies the return-routability cookie: no session
// state is created until the client echoes a valid cookie.
func TestHandshakeCookieGate(t *testing.T) {
	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	lis := NewListener(context.Background(), ListenerConfig{ServerStatic: serverStatic, Caps: 0x04, Zone: testZone})
	init, err := crypto.ClientInit(serverStatic.Public, 0x04)
	if err != nil {
		t.Fatal(err)
	}

	// No cookie → challenge, and crucially NO session state.
	kind, cookie, _ := parseHsResp(lis.HandleUpstream(buildHsQuery(nil, init.Wire), HandshakeSessionID))
	if kind != hsKindChallenge {
		t.Fatalf("no-cookie INIT: kind=%d want challenge", kind)
	}
	if n := lis.Manager().Count(); n != 0 {
		t.Fatalf("no-cookie INIT created state: count=%d", n)
	}

	// Wrong cookie → challenge again, still no state.
	kind, _, _ = parseHsResp(lis.HandleUpstream(buildHsQuery(make([]byte, cookieLen), init.Wire), HandshakeSessionID))
	if kind != hsKindChallenge {
		t.Fatalf("bad-cookie INIT: kind=%d want challenge", kind)
	}
	if n := lis.Manager().Count(); n != 0 {
		t.Fatalf("bad-cookie INIT created state: count=%d", n)
	}

	// Correct cookie → accept, session minted.
	kind, _, _ = parseHsResp(lis.HandleUpstream(buildHsQuery(cookie, init.Wire), HandshakeSessionID))
	if kind != hsKindAccept {
		t.Fatalf("valid-cookie INIT: kind=%d want accept", kind)
	}
	if n := lis.Manager().Count(); n != 1 {
		t.Fatalf("valid-cookie INIT minted %d sessions, want 1", n)
	}
}

// TestListenerHandshakeIdempotent verifies a retransmitted/duplicated (cookied)
// INIT yields the same response and a single session — essential for multi-path.
func TestListenerHandshakeIdempotent(t *testing.T) {
	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	lis := NewListener(context.Background(), ListenerConfig{ServerStatic: serverStatic, Caps: 0x04, Zone: testZone})
	init, err := crypto.ClientInit(serverStatic.Public, 0x04)
	if err != nil {
		t.Fatal(err)
	}

	// Obtain a cookie via the challenge.
	kind, cookie, _ := parseHsResp(lis.HandleUpstream(buildHsQuery(nil, init.Wire), HandshakeSessionID))
	if kind != hsKindChallenge {
		t.Fatalf("expected challenge, kind=%d", kind)
	}

	// The same cookied INIT, sent twice, yields one session and identical replies.
	q := buildHsQuery(cookie, init.Wire)
	resp1 := lis.HandleUpstream(q, HandshakeSessionID)
	resp2 := lis.HandleUpstream(q, HandshakeSessionID) // duplicate
	if k, _, _ := parseHsResp(resp1); k != hsKindAccept {
		t.Fatalf("expected accept, kind=%d", k)
	}
	if !bytes.Equal(resp1, resp2) {
		t.Error("duplicate cookied INIT produced a different response (not idempotent)")
	}
	if n := lis.Manager().Count(); n != 1 {
		t.Errorf("duplicate INIT minted %d sessions, want 1", n)
	}

	// A malformed/garbage handshake mints nothing.
	if out := lis.HandleUpstream([]byte{0x05, 0x05, 0x05}, HandshakeSessionID); out != nil {
		t.Error("garbage handshake should not produce a response")
	}
	if n := lis.Manager().Count(); n != 1 {
		t.Errorf("garbage handshake changed session count to %d, want 1", n)
	}
}
