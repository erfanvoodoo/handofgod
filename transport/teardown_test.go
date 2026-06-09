package transport

import (
	"context"
	"testing"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/frame"
	"github.com/handofgod/path"
)

// TestClientCloseSendsSessionClose verifies Close emits exactly one SESSION_CLOSE
// (and is idempotent).
func TestClientCloseSendsSessionClose(t *testing.T) {
	keys := handshakeKeys(t)
	cSealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	cOpener, _ := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
	serverOpener, _ := crypto.NewOpener(keys.TxKey, crypto.DirClientToServer, 4096)

	eng, _ := newEngineWithPath(t)
	sent := make(chan []byte, 4)

	prof := &dns.Profile{
		Name:              "teardown",
		RecordTypeWeights: map[uint16]float64{16: 1.0},
		QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []dns.Bucket{{Min: 1, Max: 1, Weight: 1.0}},
		IdleGapMs:         []dns.Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		LabelEntropyMode:  "raw",
	}
	ctrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	ctrl.SetProfile(dns.LevelStandard, prof)

	sess := NewSession(Config{
		SessionID: 0xBEEF, Sealer: cSealer, Opener: cOpener, Engine: eng, Zone: testZone,
		Controller: ctrl,
		WireSend: func(q dns.Query, _ *path.Path) error {
			if dg, _, err := dns.DecodeFQDNMode(q.FQDN, testZone, "raw"); err == nil {
				sent <- dg
			}
			return nil
		},
	})

	sess.Close(frame.ErrCodeNormal)

	select {
	case dg := <-sent:
		_, _, f, err := frame.DecodeDatagram(serverOpener, dg)
		if err != nil {
			t.Fatalf("decode SESSION_CLOSE: %v", err)
		}
		if f.Type != frame.TypeSessionClose {
			t.Errorf("frame type: got 0x%x want SESSION_CLOSE", f.Type)
		}
		if len(f.Payload) != 1 || f.Payload[0] != frame.ErrCodeNormal {
			t.Errorf("close payload: got %v want [0]", f.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not send a SESSION_CLOSE")
	}

	// Idempotent: a second Close sends nothing more.
	sess.Close(frame.ErrCodeNormal)
	select {
	case <-sent:
		t.Error("second Close sent another SESSION_CLOSE")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestListenerEvictsOnSessionClose verifies an inbound SESSION_CLOSE immediately
// evicts the session from the server.
func TestListenerEvictsOnSessionClose(t *testing.T) {
	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lis := NewListener(ctx, ListenerConfig{ServerStatic: serverStatic, Caps: 0x04, Zone: testZone})

	sid, keys := directHandshake(t, lis, serverStatic)
	if lis.Manager().Count() != 1 {
		t.Fatalf("after handshake: count=%d want 1", lis.Manager().Count())
	}

	// Client sends SESSION_CLOSE (unreliable seq).
	cSealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
	closeDg := frame.EncodeDatagram(cSealer, sid, crypto.SeqUnreliableBit,
		frame.Frame{Type: frame.TypeSessionClose, Payload: []byte{frame.ErrCodeNormal}})
	lis.HandleUpstream(closeDg, sid)

	if lis.Manager().Count() != 0 {
		t.Errorf("session not evicted on SESSION_CLOSE: count=%d", lis.Manager().Count())
	}
}

// TestListenerReapsIdleSessions verifies the reaper evicts idle sessions but
// leaves fresh ones alone.
func TestListenerReapsIdleSessions(t *testing.T) {
	serverStatic, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Long ReapInterval so the background loop doesn't race the manual Reap calls.
	lis := NewListener(ctx, ListenerConfig{
		ServerStatic: serverStatic, Caps: 0x04, Zone: testZone, ReapInterval: time.Hour,
	})

	directHandshake(t, lis, serverStatic)
	if lis.Manager().Count() != 1 {
		t.Fatalf("after handshake: count=%d want 1", lis.Manager().Count())
	}

	// A fresh session survives a long idle timeout.
	if n := lis.Manager().Reap(time.Hour); n != 0 || lis.Manager().Count() != 1 {
		t.Fatalf("fresh session reaped: removed=%d count=%d", n, lis.Manager().Count())
	}

	// After sitting idle past the timeout, it is reaped.
	time.Sleep(5 * time.Millisecond)
	if n := lis.Manager().Reap(time.Millisecond); n != 1 || lis.Manager().Count() != 0 {
		t.Fatalf("idle session not reaped: removed=%d count=%d", n, lis.Manager().Count())
	}
}
