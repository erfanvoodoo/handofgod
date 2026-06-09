package transport

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/frame"
	"github.com/handofgod/path"
)

const testZone = "v.example.com"

// handshakeKeys runs a real NK handshake and returns the (identical) session
// keys both sides derive.
func handshakeKeys(t *testing.T) *crypto.SessionKeys {
	t.Helper()
	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	init, err := crypto.ClientInit(serverStatic.Public, 0x04)
	if err != nil {
		t.Fatal(err)
	}
	respWire, serverKeys, _, err := crypto.ServerProcessInit(serverStatic, init.Wire, 0xBEEF, 0x04)
	if err != nil {
		t.Fatal(err)
	}
	_, clientKeys, _, err := crypto.ClientProcessResp(init.Ephemeral, serverStatic.Public, init.Hello, respWire)
	if err != nil {
		t.Fatal(err)
	}
	if clientKeys.TxKey != serverKeys.TxKey || clientKeys.RxKey != serverKeys.RxKey {
		t.Fatal("client/server key mismatch")
	}
	return clientKeys
}

func newEngineWithPath(t *testing.T) (*path.Engine, *path.Path) {
	t.Helper()
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	p := e.AddPath("r", "d", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
	return e, p
}

// newClientSession builds a client-direction Session plus the Sealer the peer
// (server) uses to send datagrams the session will accept, and the path inbound
// datagrams are attributed to.
func newClientSession(t *testing.T, deliver func(uint16, []byte)) (*Session, *crypto.Sealer, *path.Path) {
	t.Helper()
	keys := handshakeKeys(t)
	sealer, err := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
	if err != nil {
		t.Fatal(err)
	}
	peerSealer, err := crypto.NewSealer(keys.RxKey, crypto.DirServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	e, p := newEngineWithPath(t)
	s := NewSession(Config{
		SessionID: 0xBEEF,
		Sealer:    sealer,
		Opener:    opener,
		Engine:    e,
		Zone:      testZone,
		Deliver:   deliver,
	})
	return s, peerSealer, p
}

// peerDatagram seals a frame as the peer (server→client) at the given seq.
func peerDatagram(peer *crypto.Sealer, seq uint64, f frame.Frame) []byte {
	return frame.EncodeDatagram(peer, 0xBEEF, seq, f)
}

func TestSessionDeliversInboundData(t *testing.T) {
	var gotStream uint16
	var gotData []byte
	s, peer, p := newClientSession(t, func(streamID uint16, data []byte) {
		gotStream = streamID
		gotData = append([]byte(nil), data...)
	})

	dg := peerDatagram(peer, 0, frame.Frame{Type: frame.TypeData, StreamID: 7, Payload: []byte("hello")})
	if err := s.HandleInbound(dg, p); err != nil {
		t.Fatalf("HandleInbound: %v", err)
	}
	if gotStream != 7 || string(gotData) != "hello" {
		t.Errorf("deliver: got stream=%d data=%q want 7/hello", gotStream, gotData)
	}
	if s.Stats().Delivered != 1 {
		t.Errorf("delivered count: got %d want 1", s.Stats().Delivered)
	}
}

func TestSessionOnAckClearsWindow(t *testing.T) {
	s, peer, p := newClientSession(t, nil)

	s.Write(1, []byte("data"))
	if st := s.Stats(); st.InFlight != 1 {
		t.Fatalf("InFlight after Write: got %d want 1", st.InFlight)
	}

	// ACK with next-expected==1 acknowledges seq 0.
	ack := frame.EncodeAck(frame.AckPayload{CumulativeAck: 1})
	dg := peerDatagram(peer, 0, frame.Frame{Type: frame.TypeAck, Payload: ack})
	if err := s.HandleInbound(dg, p); err != nil {
		t.Fatalf("HandleInbound: %v", err)
	}
	if st := s.Stats(); st.InFlight != 0 {
		t.Errorf("InFlight after ACK: got %d want 0", st.InFlight)
	}
}

func TestSessionPingPongRecordsPathRTT(t *testing.T) {
	s, peer, p := newClientSession(t, nil)

	tok := s.SendPing()
	time.Sleep(2 * time.Millisecond) // ensure a measurable, positive RTT

	pong := frame.Frame{Type: frame.TypePong, Payload: tok}
	if err := s.HandleInbound(peerDatagram(peer, 0, pong), p); err != nil {
		t.Fatalf("HandleInbound: %v", err)
	}

	if rtt := p.Stats().RTTp50; rtt <= 0 {
		t.Errorf("expected a positive RTT sample on the path, got %v", rtt)
	}
}

func TestSessionUnknownPongIgnored(t *testing.T) {
	s, peer, p := newClientSession(t, nil)
	// PONG for a token we never sent: must be ignored, no RTT recorded.
	pong := frame.Frame{Type: frame.TypePong, Payload: []byte("88888888")}
	if err := s.HandleInbound(peerDatagram(peer, 0, pong), p); err != nil {
		t.Fatalf("HandleInbound: %v", err)
	}
	if rtt := p.Stats().RTTp50; rtt != 0 {
		t.Errorf("unknown PONG should not record RTT, got %v", rtt)
	}
}

func TestSessionDropsUndecodableInbound(t *testing.T) {
	s, _, p := newClientSession(t, nil)
	garbage := make([]byte, 40) // valid length, but not a real sealed datagram
	for i := range garbage {
		garbage[i] = byte(i)
	}
	if err := s.HandleInbound(garbage, p); err == nil {
		t.Error("expected decode error for garbage datagram")
	}
	if s.Stats().DroppedIn != 1 {
		t.Errorf("DroppedIn: got %d want 1", s.Stats().DroppedIn)
	}
}

// TestServerManagerRoutesBySessionID verifies the router dispatches each
// datagram to the matching session, keeps sessions isolated, and serves cover
// (nil) for unknown ids.
func TestServerManagerRoutesBySessionID(t *testing.T) {
	keysA := handshakeKeys(t)
	keysB := handshakeKeys(t)

	mkServer := func(sid uint16, keys *crypto.SessionKeys, got chan<- []byte) *ServerSession {
		sealer, _ := crypto.NewSealer(keys.RxKey, crypto.DirServerToClient)
		opener, _ := crypto.NewOpener(keys.TxKey, crypto.DirClientToServer, 4096)
		return NewServerSession(ServerConfig{
			SessionID: sid, Sealer: sealer, Opener: opener,
			Deliver: func(_ uint16, d []byte) { got <- append([]byte(nil), d...) },
		})
	}

	gotA := make(chan []byte, 4)
	gotB := make(chan []byte, 4)

	mgr := NewServerManager()
	mgr.Register(0xAAAA, mkServer(0xAAAA, keysA, gotA))
	mgr.Register(0xBBBB, mkServer(0xBBBB, keysB, gotB))
	if mgr.Count() != 2 {
		t.Fatalf("session count: got %d want 2", mgr.Count())
	}

	aSealer, _ := crypto.NewSealer(keysA.TxKey, crypto.DirClientToServer)
	bSealer, _ := crypto.NewSealer(keysB.TxKey, crypto.DirClientToServer)
	dgA := frame.EncodeDatagram(aSealer, 0xAAAA, 0, frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte("for A")})
	dgB := frame.EncodeDatagram(bSealer, 0xBBBB, 0, frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte("for B")})

	mgr.HandleUpstream(dgA, 0xAAAA)
	mgr.HandleUpstream(dgB, 0xBBBB)

	if d := <-gotA; string(d) != "for A" {
		t.Errorf("session A delivered %q want \"for A\"", d)
	}
	if d := <-gotB; string(d) != "for B" {
		t.Errorf("session B delivered %q want \"for B\"", d)
	}
	if len(gotA) != 0 || len(gotB) != 0 {
		t.Errorf("cross-talk between sessions: leftover A=%d B=%d", len(gotA), len(gotB))
	}

	// Unknown session id routes nowhere (cover), no delivery, no panic.
	if out := mgr.HandleUpstream(dgA, 0xCCCC); out != nil {
		t.Error("unknown session id should not route (want nil downstream)")
	}

	// Remove drops routing.
	mgr.Remove(0xAAAA)
	if mgr.Get(0xAAAA) != nil || mgr.Count() != 1 {
		t.Errorf("after Remove: Get=%v Count=%d", mgr.Get(0xAAAA), mgr.Count())
	}
}

// TestSessionCoalescesAcks verifies the pull-hook coalesces acknowledgments: a
// burst of received DATA produces exactly one fresh cumulative ACK when the
// scheduler pulls, not one queued ACK per frame.
func TestSessionCoalescesAcks(t *testing.T) {
	keys := handshakeKeys(t)
	cSealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	cOpener, _ := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
	peerSealer, _ := crypto.NewSealer(keys.RxKey, crypto.DirServerToClient)         // craft DATA the client receives
	serverOpener, _ := crypto.NewOpener(keys.TxKey, crypto.DirClientToServer, 4096) // decode the client's upstream ACK

	e, p := newEngineWithPath(t)
	s := NewSession(Config{SessionID: 0xBEEF, Sealer: cSealer, Opener: cOpener, Engine: e, Zone: testZone})

	// Receive 10 in-order DATA frames.
	for i := 0; i < 10; i++ {
		dg := frame.EncodeDatagram(peerSealer, 0xBEEF, uint64(i),
			frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte{byte(i)}})
		if err := s.HandleInbound(dg, p); err != nil {
			t.Fatalf("HandleInbound %d: %v", i, err)
		}
	}

	// One pull yields a single ACK; a second yields nothing (coalesced).
	ctrl := s.pullControl()
	if ctrl == nil {
		t.Fatal("expected a coalesced ACK after receiving data")
	}
	if s.pullControl() != nil {
		t.Error("expected no further ACK — acks must coalesce to one per slot, not one per DATA")
	}

	// The single ACK reflects everything received in order (next-expected == 10).
	_, _, f, err := frame.DecodeDatagram(serverOpener, ctrl)
	if err != nil {
		t.Fatalf("decode ack datagram: %v", err)
	}
	if f.Type != frame.TypeAck {
		t.Fatalf("expected ACK frame, got type 0x%x", f.Type)
	}
	ack, err := frame.DecodeAck(f.Payload)
	if err != nil {
		t.Fatalf("decode ack payload: %v", err)
	}
	if ack.CumulativeAck != 10 {
		t.Errorf("coalesced ack cumulative: got %d want 10", ack.CumulativeAck)
	}
}

// TestSessionRecoveryProbesUnhealthyPaths verifies the §8.3 failover loop: an
// excluded path is probed out-of-band, and a successful response readmits it.
func TestSessionRecoveryProbesUnhealthyPaths(t *testing.T) {
	keys := handshakeKeys(t)
	sealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	opener, _ := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
	peerSealer, _ := crypto.NewSealer(keys.RxKey, crypto.DirServerToClient)

	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	e.AddPath("good", testZone, cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
	dead := e.AddPath("dead", testZone, cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)

	// Drive "dead" unhealthy via sustained failure.
	for i := 0; i < cfg.HealthFailLimit; i++ {
		dead.RecordResult(false)
	}
	if e.HealthyCount() != 1 {
		t.Fatalf("expected exactly one healthy path, got %d", e.HealthyCount())
	}

	probed := make(chan *path.Path, 8)
	sess := NewSession(Config{
		SessionID: 0xBEEF, Sealer: sealer, Opener: opener, Engine: e, Zone: testZone,
		WireSend: func(_ dns.Query, p *path.Path) error { probed <- p; return nil },
	})

	// Recovery must probe only the unhealthy path, out-of-band.
	sess.recoveryProbe()
	if len(probed) != 1 {
		t.Fatalf("expected exactly one recovery probe, got %d", len(probed))
	}
	if p := <-probed; p != dead {
		t.Errorf("recovery probe hit %s, want the unhealthy path", p.Resolver)
	}

	// A successful response on the dead path readmits it.
	ackDg := frame.EncodeDatagram(peerSealer, 0xBEEF, 0,
		frame.Frame{Type: frame.TypeAck, Payload: frame.EncodeAck(frame.AckPayload{})})
	if err := sess.HandleInbound(ackDg, dead); err != nil {
		t.Fatalf("HandleInbound: %v", err)
	}
	if e.HealthyCount() != 2 {
		t.Errorf("dead path should recover after a successful response, healthy=%d", e.HealthyCount())
	}
}

// TestSessionLoopbackEndToEnd runs two Sessions back-to-back over an in-memory
// wire and verifies a write is delivered in order and the sender's window drains
// once the ACK returns — exercising the full framing → Client.Send → scheduler →
// transmit → HandleInbound → ACK path.
func TestSessionLoopbackEndToEnd(t *testing.T) {
	keys := handshakeKeys(t)

	cSealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	cOpener, _ := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
	sSealer, _ := crypto.NewSealer(keys.RxKey, crypto.DirServerToClient)
	sOpener, _ := crypto.NewOpener(keys.TxKey, crypto.DirClientToServer, 4096)

	cEngine, cPath := newEngineWithPath(t)
	sEngine, sPath := newEngineWithPath(t)

	// Fast, cover-free, raw profile: quick timing and FQDNs we can decode as raw.
	prof := &dns.Profile{
		Name:              "loopback",
		RecordTypeWeights: map[uint16]float64{16: 1.0},
		QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []dns.Bucket{{Min: 4, Max: 4, Weight: 1.0}},
		IdleGapMs:         []dns.Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:    0.0,
		LabelEntropyMode:  "raw",
	}
	cCtrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	cCtrl.SetProfile(dns.LevelStandard, prof)
	sCtrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	sCtrl.SetProfile(dns.LevelStandard, prof)

	got := make(chan []byte, 16)

	var client, server *Session
	client = NewSession(Config{
		SessionID: 0xBEEF, Sealer: cSealer, Opener: cOpener, Engine: cEngine,
		Zone: testZone, Controller: cCtrl,
		WireSend: func(q dns.Query, _ *path.Path) error {
			dg, _, err := dns.DecodeFQDNMode(q.FQDN, testZone, "raw")
			if err != nil {
				return nil // malformed (shouldn't happen with raw) — drop
			}
			server.HandleInbound(dg, sPath)
			return nil
		},
	})
	server = NewSession(Config{
		SessionID: 0xBEEF, Sealer: sSealer, Opener: sOpener, Engine: sEngine,
		Zone: testZone, Controller: sCtrl,
		Deliver: func(_ uint16, data []byte) { got <- append([]byte(nil), data...) },
		WireSend: func(q dns.Query, _ *path.Path) error {
			dg, _, err := dns.DecodeFQDNMode(q.FQDN, testZone, "raw")
			if err != nil {
				return nil
			}
			client.HandleInbound(dg, cPath)
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)
	go server.Run(ctx)

	msg := []byte("hello over dns")
	client.Write(1, msg)

	select {
	case d := <-got:
		if !bytes.Equal(d, msg) {
			t.Fatalf("delivered %q want %q", d, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("data not delivered end to end")
	}

	// The ACK should flow back and drain the client's window.
	deadline := time.After(3 * time.Second)
	for client.Stats().InFlight != 0 {
		select {
		case <-deadline:
			t.Fatalf("client window did not drain: InFlight=%d", client.Stats().InFlight)
		case <-time.After(20 * time.Millisecond):
		}
	}

	_ = cPath
	_ = sEngine
}
