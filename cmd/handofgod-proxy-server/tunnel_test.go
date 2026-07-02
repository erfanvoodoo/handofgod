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
	"github.com/handofgod/frame"
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

func newProxyHarness(t *testing.T, allowDest, zone, mode string) *proxyHarness {
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

	h.handler = newTunnelHandler(allowDest, zone, mode, nil)

	var lis *transport.Listener
	lis = transport.NewListener(ctx, transport.ListenerConfig{
		ServerStatic: serverStatic,
		Caps:         0x04,
		Zone:         zone,
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
	zc.Zone = zone
	zc.MaxQueryRatePerMin = 0
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	h.wsrv = wire.NewServer(wire.ServerConfig{
		Zone: zone, Mode: mode, Handler: lis.HandleUpstream, Mimic: dns.NewServerMimic(zc),
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
	eng.AddPath(addr, zone, pcfg.WeightLoss, pcfg.WeightLatency, pcfg.WeightThroughput)

	prof := &dns.Profile{
		Name:              "tunnel-test",
		RecordTypeWeights: map[uint16]float64{16: 1.0},
		QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []dns.Bucket{{Min: 4, Max: 4, Weight: 1.0}},
		IdleGapMs:         []dns.Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:    0.0,
		LabelEntropyMode:  mode,
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
		Zone:            zone,
		Mode:            mode,
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
	h := newProxyHarness(t, "", testZone, "raw")
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
	h := newProxyHarness(t, "", testZone, "raw")
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
	h := newProxyHarness(t, echo, testZone, "raw")
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
	h := newProxyHarness(t, echo1, testZone, "raw")
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

	h := newProxyHarness(t, "", testZone, "raw")
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

// TestMaxWritePayload_PerMode is the sanity check on chunk.go's math for
// every codec: each mode must return > 0, and a datagram of exactly that
// application size (plus frame.Overhead) must actually encode successfully
// via dns.EncodeFQDNMode. If this test fails, the derivation in chunk.go
// is wrong and either data is being silently dropped (too big) or bandwidth
// is being wasted (too small).
func TestMaxWritePayload_PerMode(t *testing.T) {
	for _, mode := range []string{"raw", "padded", "ngram"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			app := maxWritePayload(testZone, mode)
			if app <= 0 {
				t.Fatalf("maxWritePayload = %d, want > 0", app)
			}
			// Test the corresponding datagram size actually encodes.
			datagramSize := app + frame.Overhead
			datagram := make([]byte, datagramSize)
			for i := range datagram {
				datagram[i] = byte(i * 7)
			}
			fqdn, err := dns.EncodeFQDNMode(datagram, 0xBEEF, testZone, mode)
			if err != nil {
				t.Fatalf("datagram of size %d for mode=%s failed to encode: %v",
					datagramSize, mode, err)
			}
			// FQDN presentation form has trailing dot; max wire is 253.
			if len(fqdn) > 254 {
				t.Fatalf("encoded FQDN %d chars > 254 (max)", len(fqdn))
			}
			t.Logf("mode=%s app_payload=%d datagram=%d fqdn_len=%d",
				mode, app, datagramSize, len(fqdn))
		})
	}
}

// TestTunnel_LargeBlob is the regression test that would have caught the
// 16 KB silent-drop bug: a 5000-byte payload is echoed round-trip through
// the full UDP loopback + real TCP + tunnel handler stack. The harness must
// chunk its upstream 'D' messages (using maxWritePayload) because the client
// side is exercising the transport directly; the server-side chunking is
// what pipeRemoteToSession does when returning the echoed bytes. Byte-
// identical delivery proves nothing was dropped in either direction.
func TestTunnel_LargeBlob(t *testing.T) {
	echo := echoServer(t)
	h := newProxyHarness(t, "", testZone, "raw")
	defer h.cleanup()

	h.cli.Write(1, append([]byte{msgConnect}, []byte(echo)...))
	if _, err := h.waitMsg(msgConnectOK, 8*time.Second); err != nil {
		t.Fatalf("expected CONNECT-OK: %v", err)
	}

	// 5000 bytes > 4KB. Pattern is easy to eyeball if a chunk goes missing.
	const size = 5000
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Upstream: harness must chunk using the same math as production.
	chunk := maxWritePayload(testZone, "raw") - 1
	if chunk < 1 {
		t.Fatalf("harness chunk size = %d, unusable", chunk)
	}
	for off := 0; off < size; {
		end := off + chunk
		if end > size {
			end = size
		}
		msg := make([]byte, 1+(end-off))
		msg[0] = msgData
		copy(msg[1:], payload[off:end])
		h.cli.Write(1, msg)
		off = end
	}

	// Downstream: pipeRemoteToSession chunks internally; drainData
	// accumulates 'D' messages until size bytes arrive.
	got, err := h.drainData(size, 60*time.Second)
	if err != nil {
		t.Fatalf("drain: %v (got %d of %d bytes)", err, len(got), size)
	}
	if !bytes.Equal(got, payload) {
		// Show first mismatch for diagnosis without dumping 5 KB.
		for i := 0; i < size; i++ {
			if got[i] != payload[i] {
				t.Fatalf("mismatch at byte %d: got 0x%02x want 0x%02x (len %d)",
					i, got[i], payload[i], len(got))
			}
		}
		t.Fatalf("mismatch of length (got %d want %d)", len(got), size)
	}
}

// realZone is the production zone shape (17 chars, longer than testZone's 13).
// It exercises the zone-aware branch of maxWritePayload — where padded, in
// particular, must drop into a smaller 16-byte block than it does for the
// shorter example zone.
const realZone = "t.erfanvoodoo.com"

// TestTunnel_LargeBlob_RealZone runs the >4KB round-trip through the full
// UDP/TCP/tunnel stack under the ACTUAL deployment zone for ALL three
// entropy modes, and asserts:
//
//   - the derivation in chunk.go returns a valid FQDN (≤253) for that zone
//     when a datagram of exactly its computed size is encoded;
//   - the round-trip echo is byte-identical (no chunk dropped by dns.Client
//     mid-transfer would allow this — ARQ retransmits, so a bad chunk size
//     would loop forever and time out);
//   - the Session's DroppedOut counter is exactly 0 at the end (this is the
//     explicit assertion that no encoding-side drop happened, even one that
//     might have been silently retransmitted through).
//
// A regression that broke maxWritePayload's zone-awareness would show up here
// as a per-mode fqdn_len that exceeded 254 (caught by the first assertion),
// or as a stalled drainData that timed out (caught by the second), or as a
// non-zero DroppedOut (caught by the third).
func TestTunnel_LargeBlob_RealZone(t *testing.T) {
	for _, mode := range []string{"raw", "padded", "ngram"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			// Derivation check: encode a datagram of exactly the size the helper
			// says is safe, and log the actual FQDN length. If this is >253 we
			// have a math bug independent of anything the network does.
			app := maxWritePayload(realZone, mode)
			datagramSize := app + frame.Overhead
			datagram := make([]byte, datagramSize)
			for i := range datagram {
				datagram[i] = byte(i * 7)
			}
			fqdn, err := dns.EncodeFQDNMode(datagram, 0xBEEF, realZone, mode)
			if err != nil {
				t.Fatalf("mode=%s: derivation broken: %v", mode, err)
			}
			// DNS wire limit is 253 for the name proper (254 with trailing dot,
			// which is how dns/labels.go compares).
			if len(fqdn) > 254 {
				t.Fatalf("mode=%s: fqdn_len=%d exceeds 254", mode, len(fqdn))
			}
			t.Logf("zone=%q mode=%s app_payload=%d datagram=%d fqdn_len=%d",
				realZone, mode, app, datagramSize, len(fqdn))

			// Round-trip a 5000-byte blob.
			echo := echoServer(t)
			h := newProxyHarness(t, "", realZone, mode)
			defer h.cleanup()

			h.cli.Write(1, append([]byte{msgConnect}, []byte(echo)...))
			if _, err := h.waitMsg(msgConnectOK, 15*time.Second); err != nil {
				t.Fatalf("mode=%s: CONNECT-OK: %v", mode, err)
			}

			const size = 5000
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i)
			}

			// Upstream: chunk with the same helper the production client uses.
			chunk := maxWritePayload(realZone, mode) - 1
			if chunk < 1 {
				t.Fatalf("mode=%s: harness chunk size = %d, unusable", mode, chunk)
			}
			for off := 0; off < size; {
				end := off + chunk
				if end > size {
					end = size
				}
				msg := make([]byte, 1+(end-off))
				msg[0] = msgData
				copy(msg[1:], payload[off:end])
				h.cli.Write(1, msg)
				off = end
			}

			// Ngram at ~76 B/chunk needs ~66 chunks each way over the loopback
			// scheduler; give a generous window.
			got, err := h.drainData(size, 120*time.Second)
			if err != nil {
				t.Fatalf("mode=%s: drain: %v (got %d of %d bytes; DroppedOut=%d)",
					mode, err, len(got), size, h.cli.Stats().DroppedOut)
			}
			if !bytes.Equal(got, payload) {
				for i := 0; i < size; i++ {
					if got[i] != payload[i] {
						t.Fatalf("mode=%s mismatch at byte %d: got 0x%02x want 0x%02x",
							mode, i, got[i], payload[i])
					}
				}
				t.Fatalf("mode=%s length mismatch: got %d want %d", mode, len(got), size)
			}

			// The explicit assertion the reviewer asked for: no datagram was
			// ever rejected by dns.Client's encoding path.
			if dropped := h.cli.Stats().DroppedOut; dropped != 0 {
				t.Fatalf("mode=%s: DroppedOut=%d, want 0 (chunk size was wrong)",
					mode, dropped)
			}
			t.Logf("mode=%s: 5000 B round-trip OK, DroppedOut=0", mode)
		})
	}
}
