package transport

import (
	"testing"

	"github.com/handofgod/crypto"
	"github.com/handofgod/frame"
)

// TestClientRouterRoutesBySessionID verifies the client router dispatches each
// downstream datagram to the matching session by header id, with no cross-talk.
func TestClientRouterRoutesBySessionID(t *testing.T) {
	keysA := handshakeKeys(t)
	keysB := handshakeKeys(t)

	mkClient := func(sid uint16, keys *crypto.SessionKeys, got chan<- []byte) *Session {
		sealer, _ := crypto.NewSealer(keys.TxKey, crypto.DirClientToServer)
		opener, _ := crypto.NewOpener(keys.RxKey, crypto.DirServerToClient, 4096)
		eng, _ := newEngineWithPath(t)
		return NewSession(Config{
			SessionID: sid, Sealer: sealer, Opener: opener, Engine: eng, Zone: testZone,
			Deliver: func(_ uint16, d []byte) { got <- append([]byte(nil), d...) },
		})
	}

	gotA := make(chan []byte, 4)
	gotB := make(chan []byte, 4)

	router := NewClientRouter()
	router.Register(0xAAAA, mkClient(0xAAAA, keysA, gotA))
	router.Register(0xBBBB, mkClient(0xBBBB, keysB, gotB))
	if router.Count() != 2 {
		t.Fatalf("count=%d want 2", router.Count())
	}

	// Craft downstream DATA for each session (server→client sealers).
	aSrv, _ := crypto.NewSealer(keysA.RxKey, crypto.DirServerToClient)
	bSrv, _ := crypto.NewSealer(keysB.RxKey, crypto.DirServerToClient)
	dgA := frame.EncodeDatagram(aSrv, 0xAAAA, 0, frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte("to A")})
	dgB := frame.EncodeDatagram(bSrv, 0xBBBB, 0, frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte("to B")})

	router.Inbound(dgA, nil)
	router.Inbound(dgB, nil)

	if d := <-gotA; string(d) != "to A" {
		t.Errorf("session A delivered %q want \"to A\"", d)
	}
	if d := <-gotB; string(d) != "to B" {
		t.Errorf("session B delivered %q want \"to B\"", d)
	}
	if len(gotA) != 0 || len(gotB) != 0 {
		t.Errorf("cross-talk: leftover A=%d B=%d", len(gotA), len(gotB))
	}

	// Unknown session id is dropped (no panic, no delivery).
	dgUnknown := frame.EncodeDatagram(aSrv, 0xCCCC, 1, frame.Frame{Type: frame.TypeData, Payload: []byte("x")})
	router.Inbound(dgUnknown, nil)
	router.Inbound([]byte{0x01}, nil) // too short to parse → dropped

	router.Remove(0xAAAA)
	if router.Get(0xAAAA) != nil || router.Count() != 1 {
		t.Errorf("after Remove: Get=%v count=%d", router.Get(0xAAAA), router.Count())
	}
}
