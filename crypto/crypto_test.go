package crypto

import (
	"bytes"
	"testing"
)

func TestFullHandshake(t *testing.T) {
	// Server has a static key pair; its public key is pinned in the client.
	serverStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	const caps = uint16(0x04) // SACK
	const sessionID = uint16(0xBEEF)

	// Client builds INIT
	init, err := ClientInit(serverStatic.Public, caps)
	if err != nil {
		t.Fatal(err)
	}

	// Server processes INIT, builds RESP, derives keys
	respWire, serverKeys, clientHello, err := ServerProcessInit(serverStatic, init.Wire, sessionID, caps)
	if err != nil {
		t.Fatalf("server process init: %v", err)
	}
	if clientHello.Caps != caps {
		t.Errorf("caps mismatch: got %x want %x", clientHello.Caps, caps)
	}

	// Client processes RESP, derives keys
	gotSession, clientKeys, aead, err := ClientProcessResp(init.Ephemeral, serverStatic.Public, init.Hello, respWire)
	if err != nil {
		t.Fatalf("client process resp: %v", err)
	}
	if gotSession != sessionID {
		t.Errorf("session id: got %x want %x", gotSession, sessionID)
	}
	// Neither side advertised AES-GCM (caps=SACK only) → ChaCha20-Poly1305.
	if aead != AEADChaCha20Poly1305 {
		t.Errorf("negotiated AEAD: got %v want chacha20-poly1305", aead)
	}

	// Both sides MUST derive identical keys
	if clientKeys.TxKey != serverKeys.TxKey {
		t.Error("TxKey mismatch between client and server")
	}
	if clientKeys.RxKey != serverKeys.RxKey {
		t.Error("RxKey mismatch between client and server")
	}
}

func TestNegotiateAEAD(t *testing.T) {
	if got := NegotiateAEAD(CapAEADAESGCM, CapAEADAESGCM); got != AEADAES256GCM {
		t.Errorf("both advertise AES → %v want aes-256-gcm", got)
	}
	if got := NegotiateAEAD(CapAEADAESGCM, 0); got != AEADChaCha20Poly1305 {
		t.Errorf("one-sided AES → %v want chacha (fallback)", got)
	}
	if got := NegotiateAEAD(0x04, 0x04); got != AEADChaCha20Poly1305 {
		t.Errorf("neither advertises AES → %v want chacha", got)
	}
}

func TestAES256GCMRoundTrip(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	sealer, err := NewSealerAEAD(key, DirClientToServer, AEADAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := NewOpenerAEAD(key, DirClientToServer, 4096, AEADAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte{0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 7}
	plaintext := []byte("aes-256-gcm payload over hand of god")
	for seq := uint64(0); seq < 50; seq++ {
		ct := sealer.Seal(seq, plaintext, aad)
		pt, err := opener.Open(seq, ct, aad)
		if err != nil {
			t.Fatalf("seq %d: open failed: %v", seq, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("seq %d: plaintext mismatch", seq)
		}
	}
	// Replay is still rejected under AES-GCM.
	ct := sealer.Seal(100, plaintext, aad)
	if _, err := opener.Open(100, ct, aad); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := opener.Open(100, ct, aad); err != ErrReplay {
		t.Errorf("replay: got %v want ErrReplay", err)
	}
}

func TestAEADMismatchFails(t *testing.T) {
	// A datagram sealed with ChaCha20-Poly1305 must not open under AES-256-GCM.
	var key [KeySize]byte
	sealer, _ := NewSealerAEAD(key, DirClientToServer, AEADChaCha20Poly1305)
	opener, _ := NewOpenerAEAD(key, DirClientToServer, 4096, AEADAES256GCM)
	aad := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ct := sealer.Seal(1, []byte("hello"), aad)
	if _, err := opener.Open(1, ct, aad); err != ErrDecryptFailed {
		t.Errorf("cross-AEAD open: got %v want ErrDecryptFailed", err)
	}
}

func TestHandshakeRejectsWrongServerKey(t *testing.T) {
	realServer, _ := GenerateKeyPair()
	attacker, _ := GenerateKeyPair()

	// Client thinks it's talking to realServer
	init, err := ClientInit(realServer.Public, 0x04)
	if err != nil {
		t.Fatal(err)
	}

	// But the attacker (different static key) tries to process it
	_, _, _, err = ServerProcessInit(attacker, init.Wire, 1, 0x04)
	if err == nil {
		t.Fatal("expected handshake to fail with wrong server key, but it succeeded")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}

	sealer, err := NewSealer(key, DirClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := NewOpener(key, DirClientToServer, 4096)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	aad := []byte{0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 5}

	for seq := uint64(0); seq < 100; seq++ {
		ct := sealer.Seal(seq, plaintext, aad)
		pt, err := opener.Open(seq, ct, aad)
		if err != nil {
			t.Fatalf("seq %d: open failed: %v", seq, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("seq %d: plaintext mismatch", seq)
		}
	}
}

func TestReplayDetection(t *testing.T) {
	var key [KeySize]byte
	sealer, _ := NewSealer(key, DirServerToClient)
	opener, _ := NewOpener(key, DirServerToClient, 4096)

	aad := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ct := sealer.Seal(42, []byte("hello"), aad)

	// First open succeeds
	if _, err := opener.Open(42, ct, aad); err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	// Replay must be rejected
	if _, err := opener.Open(42, ct, aad); err != ErrReplay {
		t.Fatalf("expected ErrReplay on replay, got %v", err)
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	var key [KeySize]byte
	sealer, _ := NewSealer(key, DirClientToServer)
	opener, _ := NewOpener(key, DirClientToServer, 4096)

	aad := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ct := sealer.Seal(1, []byte("sensitive data"), aad)
	ct[0] ^= 0xFF // flip a bit

	if _, err := opener.Open(1, ct, aad); err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed on tampered ciphertext, got %v", err)
	}
}

func TestReplayWindowSliding(t *testing.T) {
	w := NewReplayWindow(4096)

	// Accept a spread of sequence numbers
	if !w.Accept(100) {
		t.Fatal("first accept failed")
	}
	if !w.Accept(105) {
		t.Fatal("forward accept failed")
	}
	if !w.Accept(103) {
		t.Fatal("in-window accept failed")
	}
	// Replays rejected
	if w.Accept(100) {
		t.Fatal("replay of 100 accepted")
	}
	if w.Accept(105) {
		t.Fatal("replay of 105 accepted")
	}
	// Big jump forward
	if !w.Accept(10000) {
		t.Fatal("big forward jump failed")
	}
	// Now 100 is way outside the window — rejected as too old
	if w.Accept(101) {
		t.Fatal("ancient seq 101 accepted after window moved to 10000")
	}
}
