package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/path"
	"github.com/handofgod/transport"
	"github.com/handofgod/wire"
)

const testZone = "v.example.com"

// proxyHarness wires a real Hand of God server (Listener + wire.Server on UDP
// loopback) in front of a tunnelHandler, and a real client Session via
// transport.Dial. Tests drive the tunnel sub-protocol directly through the
// client session — no SOCKS5 layer — to keep this file focused on the server.
type proxyHarness struct {
	t       *testing.T
	wsrv    *wire.Server
	cli     *transport.Session
	handler *tunnelHandler
	cancel  context.CancelFunc

	mu         sync.Mutex
	recvByType map[byte][][]byte // accumulated client-delivered messages
	recvCond   *sync.Cond
}

func newProxyHarness(t *testing.T, allowDest string) *proxyHarness {
	t.Helper()

	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &proxyHarness{
		t:          t,
		cancel:     cancel,
		recvByType: make(map[byte][][]byte),
	}
	h.recvCond = sync.NewCond(&h.mu)

	h.handler = newTunnelHandler(allowDest, nil)

	var lis *transport.Listener
	lis = transport.NewListener(ctx, transport.ListenerConfig{
		ServerStatic: serverStatic,
		Caps:         0x04,
		Zone:         testZone,
		OnAccept:     h.handler.onAccept,
		OnData: func(sid, stream uint16, data []byte) {
			sess := lis.Manager().Get(sid)
			if sess == nil {
				return
			}
			h.handler.onData(sess, sid, stream, data)
		},
	})

	zc := dns.DefaultZoneConfig()
	zc.Zone = testZone
	zc.MaxQueryRatePerMin = 0
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	h.wsrv = wire.NewServer(wire.ServerConfig{
		Zone: testZone, Mode: "raw", Handler: lis.HandleUpstream, Mimic: dns.NewServerMimic(zc),
	})
	go func() { _ = h.wsrv.Serve(pc) }()
	select {
	case <-h.wsrv.Started():
	case <-time.After(2 * time.Second):
		t.Fatal("wire server did not start")
	}

	// Client side: real Dial over the wire, with a Deliver that funnels each
	// message into recvByType[msgType] so the tests can assert on it.
	wcli := wire.NewClient(wire.ClientConfig{Timeout: 2 * time.Second})
	pcfg := path.DefaultConfig()
	eng := path.NewEngine(pcfg)
	eng.AddPath(addr, testZone, pcfg.WeightLoss, pcfg.WeightLatency, pcfg.WeightThroughput)

	prof := &dns.Profile{
		Name:              "tunnel-test",
		RecordTypeWeights: map[uint16]float64{16: 1.0},
		QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []dns.Bucket{{Min: 4, Max: 4, Weight: 1.0}},
		IdleGapMs:         []dns.Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:    0.0,
		LabelEntropyMode:  "raw",
	}
	ctrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	ctrl.SetProfile(dns.LevelStandard, prof)

	deliver := func(_ uint16, data []byte) {
		if len(data) == 0 {
			return
		}
		h.mu.Lock()
		h.recvByType[data[0]] = append(h.recvByType[data[0]], append([]byte(nil), data[1:]...))
		h.recvCond.Broadcast()
		h.mu.Unlock()
	}

	cli, err := transport.Dial(transport.DialConfig{
		ServerStaticPub: serverStatic.Public,
		Caps:            0x04,
		Zone:            testZone,
		Mode:            "raw",
		Engine:          eng,
		Controller:      ctrl,
		RoundTrip:       wcli.RoundTrip,
		WireSend:        wcli.Send,
		Deliver:         deliver,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	wcli.SetInbound(func(dg []byte, p *path.Path) { cli.HandleInbound(dg, p) })
	go cli.Run(ctx)
	h.cli = cli
	return h
}

func (h *proxyHarness) cleanup() {
	h.cli.Close(0)
	_ = h.wsrv.Shutdown()
	h.handler.shutdown()
	h.cancel()
}

// waitMsg waits up to d for at least one message of type msgType to arrive.
// Returns the first such payload (the message minus its type byte).
func (h *proxyHarness) waitMsg(msgType byte, d time.Duration) ([]byte, error) {
	deadline := time.Now().Add(d)
	h.mu.Lock()
	defer h.mu.Unlock()
	for {
		if msgs := h.recvByType[msgType]; len(msgs) > 0 {
			out := msgs[0]
			h.recvByType[msgType] = msgs[1:]
			return out, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("timeout waiting for msg type")
		}
		// Sleep via a watchdog goroutine that broadcasts on the cond when the
		// deadline elapses — Cond has no native timeout.
		woken := make(chan struct{})
		go func() {
			time.Sleep(remaining)
			h.mu.Lock()
			h.recvCond.Broadcast()
			h.mu.Unlock()
			close(woken)
		}()
		h.recvCond.Wait()
		_ = woken
	}
}

// drainData accumulates 'D' messages until total received equals want bytes
// (or until d elapses).
func (h *proxyHarness) drainData(want int, d time.Duration) ([]byte, error) {
	var got bytes.Buffer
	deadline := time.Now().Add(d)
	for got.Len() < want {
		left := time.Until(deadline)
		if left <= 0 {
			return got.Bytes(), errors.New("timeout draining")
		}
		chunk, err := h.waitMsg(msgData, left)
		if err != nil {
			return got.Bytes(), err
		}
		got.Write(chunk)
	}
	return got.Bytes(), nil
}

// echoServer starts a TCP echo server on 127.0.0.1:<random> and returns its
// address. It closes when the test ends.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestTunnel_RoundTrip: the canonical e2e — CONNECT to a real echo, send data,
// receive identical data, F to half-close, observe the server-side F back.
func TestTunnel_RoundTrip(t *testing.T) {
	echo := echoServer(t)
	h := newProxyHarness(t, "")
	defer h.cleanup()

	// CONNECT
	h.cli.Write(1, append([]byte{msgConnect}, []byte(echo)...))
	if _, err := h.waitMsg(msgConnectOK, 8*time.Second); err != nil {
		t.Fatalf("expected CONNECT-OK: %v", err)
	}

	// Send payload
	payload := []byte("the quick brown fox jumps over the lazy dog")
	h.cli.Write(1, append([]byte{msgData}, payload...))

	got, err := h.drainData(len(payload), 8*time.Second)
	if err != nil {
		t.Fatalf("drain echo: %v (got %q)", err, got)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	// Half-close from our side; server-side echo socket sees EOF on Read so it
	// emits F back at us.
	h.cli.Write(1, []byte{msgFin})
	if _, err := h.waitMsg(msgFin, 8*time.Second); err != nil {
		t.Fatalf("expected F back after half-close: %v", err)
	}
}

// TestTunnel_BadAddress: malformed host:port → CONNECT-ERR with reason.
func TestTunnel_BadAddress(t *testing.T) {
	h := newProxyHarness(t, "")
	defer h.cleanup()

	h.cli.Write(1, append([]byte{msgConnect}, []byte("not a valid address")...))
	reason, err := h.waitMsg(msgConnectErr, 8*time.Second)
	if err != nil {
		t.Fatalf("expected CONNECT-ERR: %v", err)
	}
	if !bytes.Contains(reason, []byte("invalid")) {
		t.Fatalf("CONNECT-ERR reason %q does not mention 'invalid'", reason)
	}
}

// TestTunnel_AllowDest_Allowed: with -allow-dest set, the matching target
// connects normally.
func TestTunnel_AllowDest_Allowed(t *testing.T) {
	echo := echoServer(t)
	h := newProxyHarness(t, echo)
	defer h.cleanup()

	h.cli.Write(1, append([]byte{msgConnect}, []byte(echo)...))
	if _, err := h.waitMsg(msgConnectOK, 8*time.Second); err != nil {
		t.Fatalf("expected CONNECT-OK for allowed dest: %v", err)
	}
}

// TestTunnel_AllowDest_Disallowed: with -allow-dest set, a different target
// is rejected — even if it's reachable.
func TestTunnel_AllowDest_Disallowed(t *testing.T) {
	echo1 := echoServer(t)
	echo2 := echoServer(t)
	h := newProxyHarness(t, echo1)
	defer h.cleanup()

	// allow-dest = echo1; client tries echo2 → rejected
	h.cli.Write(1, append([]byte{msgConnect}, []byte(echo2)...))
	reason, err := h.waitMsg(msgConnectErr, 8*time.Second)
	if err != nil {
		t.Fatalf("expected CONNECT-ERR for disallowed dest: %v", err)
	}
	if !bytes.Contains(reason, []byte("not allowed")) {
		t.Fatalf("CONNECT-ERR reason %q does not mention 'not allowed'", reason)
	}
}

// TestTunnel_DialFailure: connecting to a refused port produces a CONNECT-ERR
// with the dialer's reason.
func TestTunnel_DialFailure(t *testing.T) {
	// Bind a listener just to get an ephemeral port, then close it so the port
	// is (very likely) refused on a re-dial. There is a tiny race here in
	// principle; in practice on loopback it is reliable.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	h := newProxyHarness(t, "")
	defer h.cleanup()

	h.cli.Write(1, append([]byte{msgConnect}, []byte(addr)...))
	reason, err := h.waitMsg(msgConnectErr, 8*time.Second)
	if err != nil {
		t.Fatalf("expected CONNECT-ERR for refused dial: %v", err)
	}
	if len(reason) == 0 {
		t.Fatal("CONNECT-ERR reason was empty")
	}
}
