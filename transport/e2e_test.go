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

// TestEndToEndOverUDP runs a full client Session and ServerSession across the
// real miekg/dns wire (UDP loopback): a NK handshake, then bidirectional
// reliable data. Upstream rides in query names; downstream is pulled back in TXT
// responses on the client's polling queries.
func TestEndToEndOverUDP(t *testing.T) {
	keys := handshakeKeys(t)

	// ── Server-side transport: downstream sealer, upstream opener ──
	sSealer, _ := crypto.NewSealer(keys.RxKey, crypto.DirServerToClient)
	sOpener, _ := crypto.NewOpener(keys.TxKey, crypto.DirClientToServer, 4096)
	serverGot := make(chan []byte, 8)
	srv := NewServerSession(ServerConfig{
		SessionID: 0xBEEF, Sealer: sSealer, Opener: sOpener,
		Deliver: func(_ uint16, d []byte) { serverGot <- append([]byte(nil), d...) },
	})

	// Route through the session manager (single session here) so the routing path
	// is exercised end-to-end over the wire.
	mgr := NewServerManager()
	mgr.Register(0xBEEF, srv)

	// ── DNS wire server (rate limiter disabled: the test floods queries) ──
	zc := dns.DefaultZoneConfig()
	zc.Zone = testZone
	zc.MaxQueryRatePerMin = 0
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	wsrv := wire.NewServer(wire.ServerConfig{
		Zone: testZone, Mode: "raw", Handler: mgr.HandleUpstream, Mimic: dns.NewServerMimic(zc),
	})
	go func() { _ = wsrv.Serve(pc) }()
	select {
	case <-wsrv.Started():
	case <-time.After(2 * time.Second):
		t.Fatal("wire server did not start")
	}
	defer wsrv.Shutdown()

	// ── Client-side transport over the wire client adapter ──
	cSealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	cOpener, _ := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
	pcfg := path.DefaultConfig()
	cEngine := path.NewEngine(pcfg)
	cEngine.AddPath(addr, testZone, pcfg.WeightLoss, pcfg.WeightLatency, pcfg.WeightThroughput)

	clientGot := make(chan []byte, 8)
	var cli *Session
	wcli := wire.NewClient(wire.ClientConfig{
		Timeout: 2 * time.Second,
		Inbound: func(dg []byte, p *path.Path) { cli.HandleInbound(dg, p) },
	})

	// Fast, cover-free, raw profile: quick polling and decodable query names.
	prof := &dns.Profile{
		Name:              "e2e",
		RecordTypeWeights: map[uint16]float64{16: 1.0},
		QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []dns.Bucket{{Min: 4, Max: 4, Weight: 1.0}},
		IdleGapMs:         []dns.Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:    0.0,
		LabelEntropyMode:  "raw",
	}
	ctrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	ctrl.SetProfile(dns.LevelStandard, prof)

	cli = NewSession(Config{
		SessionID: 0xBEEF, Sealer: cSealer, Opener: cOpener, Engine: cEngine,
		Zone: testZone, Controller: ctrl,
		Deliver:  func(_ uint16, d []byte) { clientGot <- append([]byte(nil), d...) },
		WireSend: wcli.Send,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cli.Run(ctx)
	go srv.Run(ctx)

	// ── Client → Server ──
	up := []byte("hello server over real dns")
	cli.Write(1, up)
	select {
	case d := <-serverGot:
		if !bytes.Equal(d, up) {
			t.Fatalf("server upstream: got %q want %q", d, up)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("server did not receive upstream data over UDP")
	}
	waitDrain(t, "client", func() int { return cli.Stats().InFlight })

	// ── Server → Client (downstream, pulled on the client's polling queries) ──
	down := []byte("hello client over real dns")
	srv.Write(1, down)
	select {
	case d := <-clientGot:
		if !bytes.Equal(d, down) {
			t.Fatalf("client downstream: got %q want %q", d, down)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("client did not receive downstream data over UDP")
	}
	waitDrain(t, "server", func() int { return srv.Stats().InFlight })
}

func waitDrain(t *testing.T, who string, inFlight func() int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for inFlight() != 0 {
		select {
		case <-deadline:
			t.Fatalf("%s window did not drain: InFlight=%d", who, inFlight())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
