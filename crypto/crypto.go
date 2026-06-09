// Package crypto implements Hand of God's cryptographic core:
//   - X25519 NK-pattern handshake (server static key pinned, client anonymous)
//   - HKDF-SHA256 key derivation
//   - ChaCha20-Poly1305 AEAD with sequence-derived nonces (no nonce on the wire)
//   - Sliding-window replay protection
//
// See PROTOCOL.md §3 for the wire-level specification.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the X25519 / AEAD key size.
	KeySize = 32
	// NonceSize is the ChaCha20-Poly1305 nonce size.
	NonceSize = chacha20poly1305.NonceSize // 12
	// TagSize is the Poly1305 authentication tag size.
	TagSize = 16

	// Direction constants for nonce derivation.
	DirClientToServer byte = 0x00
	DirServerToClient byte = 0x01
)

var (
	ErrHandshakeFailed = errors.New("handofgod/crypto: handshake authentication failed")
	ErrDecryptFailed   = errors.New("handofgod/crypto: AEAD open failed")
	ErrReplay          = errors.New("handofgod/crypto: replayed sequence number")
)

// KeyPair is an X25519 key pair.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair creates a fresh X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, err
	}
	// Clamp per RFC 7748 is handled internally by curve25519.X25519 / ScalarBaseMult.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// KeyPairFromPrivate reconstructs a key pair from a stored 32-byte private key,
// deriving the matching public key. Used to persist a server's static key so its
// pinned public key stays stable across restarts.
func KeyPairFromPrivate(priv [KeySize]byte) (*KeyPair, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	kp := &KeyPair{Private: priv}
	copy(kp.Public[:], pub)
	return kp, nil
}

// dh performs X25519 and returns the shared secret.
func dh(priv, pub [KeySize]byte) ([]byte, error) {
	return curve25519.X25519(priv[:], pub[:])
}

// hkdfDerive derives a key of the given length from ikm using HKDF-SHA256.
func hkdfDerive(salt, ikm, info []byte, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// makeNonce derives a 96-bit nonce from direction and sequence number.
// Layout: [direction:1][zero:3][seq:8 big-endian]. See PROTOCOL.md §3.3.
func makeNonce(direction byte, seq uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	nonce[0] = direction
	// bytes 1..3 stay zero
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

// ── Handshake ───────────────────────────────────────────────────────────────

// ClientHello is the plaintext of HANDSHAKE_INIT.
type ClientHello struct {
	Random [16]byte
	Caps   uint16
}

// ServerHello is the plaintext of HANDSHAKE_RESP.
type ServerHello struct {
	SessionID uint16
	Random    [16]byte
	Caps      uint16
}

// SessionKeys holds the derived directional keys for a session.
type SessionKeys struct {
	TxKey [KeySize]byte // client→server seal / server uses to open
	RxKey [KeySize]byte // server→client seal / client uses to open
}

// HandshakeInitResult is returned to the client after building message 1.
type HandshakeInitResult struct {
	Wire      []byte   // bytes to send
	Ephemeral *KeyPair // client ephemeral (needed to finish handshake)
	Hello     ClientHello
}

// ClientInit builds HANDSHAKE_INIT (message 1).
// serverStaticPub is the pinned server public key from the client config.
func ClientInit(serverStaticPub [KeySize]byte, caps uint16) (*HandshakeInitResult, error) {
	eph, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	var hello ClientHello
	if _, err := io.ReadFull(rand.Reader, hello.Random[:]); err != nil {
		return nil, err
	}
	hello.Caps = caps

	es, err := dh(eph.Private, serverStaticPub)
	if err != nil {
		return nil, err
	}
	k1, err := hkdfDerive([]byte("handofgod/v1/init"), es, nil, KeySize)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(k1)
	if err != nil {
		return nil, err
	}
	nonce := makeNonce(DirClientToServer, 0)
	plaintext := marshalClientHello(hello)
	ct := aead.Seal(nil, nonce[:], plaintext, eph.Public[:]) // aad = e_p

	wire := make([]byte, 0, 2+KeySize+len(ct))
	wire = append(wire, 0x01) // version
	wire = append(wire, 0x01) // msg_type HANDSHAKE_INIT
	wire = append(wire, eph.Public[:]...)
	wire = append(wire, ct...)

	return &HandshakeInitResult{Wire: wire, Ephemeral: eph, Hello: hello}, nil
}

// ServerProcessInit processes HANDSHAKE_INIT and builds HANDSHAKE_RESP (message 2).
// Returns the response wire bytes and the derived session keys.
func ServerProcessInit(
	serverStatic *KeyPair,
	wire []byte,
	sessionID uint16,
	serverCaps uint16,
) (respWire []byte, keys *SessionKeys, clientHello ClientHello, err error) {
	if len(wire) < 2+KeySize+TagSize {
		return nil, nil, clientHello, fmt.Errorf("handofgod/crypto: init too short")
	}
	if wire[0] != 0x01 || wire[1] != 0x01 {
		return nil, nil, clientHello, fmt.Errorf("handofgod/crypto: bad init header")
	}

	var clientEphPub [KeySize]byte
	copy(clientEphPub[:], wire[2:2+KeySize])
	ct1 := wire[2+KeySize:]

	// Recompute es = X25519(S_s, e_p)
	es, err := dh(serverStatic.Private, clientEphPub)
	if err != nil {
		return nil, nil, clientHello, err
	}
	k1, err := hkdfDerive([]byte("handofgod/v1/init"), es, nil, KeySize)
	if err != nil {
		return nil, nil, clientHello, err
	}
	aead1, err := chacha20poly1305.New(k1)
	if err != nil {
		return nil, nil, clientHello, err
	}
	nonce0 := makeNonce(DirClientToServer, 0)
	plaintext, err := aead1.Open(nil, nonce0[:], ct1, clientEphPub[:])
	if err != nil {
		return nil, nil, clientHello, ErrHandshakeFailed
	}
	clientHello, err = unmarshalClientHello(plaintext)
	if err != nil {
		return nil, nil, clientHello, err
	}

	// Server ephemeral
	serverEph, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, clientHello, err
	}
	ee, err := dh(serverEph.Private, clientEphPub)
	if err != nil {
		return nil, nil, clientHello, err
	}

	// k2 for sealing ServerHello
	k2ikm := append(append([]byte{}, es...), ee...)
	k2, err := hkdfDerive([]byte("handofgod/v1/resp"), k2ikm, nil, KeySize)
	if err != nil {
		return nil, nil, clientHello, err
	}
	aead2, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, nil, clientHello, err
	}

	var sh ServerHello
	sh.SessionID = sessionID
	if _, err := io.ReadFull(rand.Reader, sh.Random[:]); err != nil {
		return nil, nil, clientHello, err
	}
	sh.Caps = serverCaps

	nonceR := makeNonce(DirServerToClient, 0)
	ct2 := aead2.Seal(nil, nonceR[:], marshalServerHello(sh), serverEph.Public[:])

	respWire = make([]byte, 0, 2+KeySize+len(ct2))
	respWire = append(respWire, 0x01)
	respWire = append(respWire, 0x02) // HANDSHAKE_RESP
	respWire = append(respWire, serverEph.Public[:]...)
	respWire = append(respWire, ct2...)

	// Derive session keys
	keys, err = deriveSession(es, ee, clientHello.Random, sh.Random)
	if err != nil {
		return nil, nil, clientHello, err
	}

	return respWire, keys, clientHello, nil
}

// ClientProcessResp processes HANDSHAKE_RESP and derives the session keys. It
// also returns the negotiated session AEAD (from the client's and the server's
// advertised caps), since the server's caps aren't available to the caller
// otherwise. The handshake messages themselves always use ChaCha20-Poly1305; the
// negotiated AEAD applies only to post-handshake session traffic.
func ClientProcessResp(
	clientEph *KeyPair,
	serverStaticPub [KeySize]byte,
	clientHello ClientHello,
	wire []byte,
) (sessionID uint16, keys *SessionKeys, aead AEAD, err error) {
	if len(wire) < 2+KeySize+TagSize {
		return 0, nil, 0, fmt.Errorf("handofgod/crypto: resp too short")
	}
	if wire[0] != 0x01 || wire[1] != 0x02 {
		return 0, nil, 0, fmt.Errorf("handofgod/crypto: bad resp header")
	}

	var serverEphPub [KeySize]byte
	copy(serverEphPub[:], wire[2:2+KeySize])
	ct2 := wire[2+KeySize:]

	// es = X25519(e_s, S_p) — client side
	es, err := dh(clientEph.Private, serverStaticPub)
	if err != nil {
		return 0, nil, 0, err
	}
	// ee = X25519(e_s, f_p)
	ee, err := dh(clientEph.Private, serverEphPub)
	if err != nil {
		return 0, nil, 0, err
	}

	k2ikm := append(append([]byte{}, es...), ee...)
	k2, err := hkdfDerive([]byte("handofgod/v1/resp"), k2ikm, nil, KeySize)
	if err != nil {
		return 0, nil, 0, err
	}
	aead2, err := chacha20poly1305.New(k2)
	if err != nil {
		return 0, nil, 0, err
	}
	nonceR := makeNonce(DirServerToClient, 0)
	plaintext, err := aead2.Open(nil, nonceR[:], ct2, serverEphPub[:])
	if err != nil {
		return 0, nil, 0, ErrHandshakeFailed
	}
	sh, err := unmarshalServerHello(plaintext)
	if err != nil {
		return 0, nil, 0, err
	}

	keys, err = deriveSession(es, ee, clientHello.Random, sh.Random)
	if err != nil {
		return 0, nil, 0, err
	}
	return sh.SessionID, keys, NegotiateAEAD(clientHello.Caps, sh.Caps), nil
}

func deriveSession(es, ee []byte, clientRandom, serverRandom [16]byte) (*SessionKeys, error) {
	ikm := append(append([]byte{}, es...), ee...)
	info := append(append([]byte{}, clientRandom[:]...), serverRandom[:]...)
	secret, err := hkdfDerive([]byte("handofgod/v1/session"), ikm, info, 2*KeySize)
	if err != nil {
		return nil, err
	}
	keys := &SessionKeys{}
	copy(keys.TxKey[:], secret[:KeySize])
	copy(keys.RxKey[:], secret[KeySize:])
	return keys, nil
}

// ── Session AEAD ──────────────────────────────────────────────────────────────

// AEAD identifies the session's authenticated-encryption construction. Both have
// a 256-bit key, 96-bit nonce, and 128-bit tag, so framing is identical.
type AEAD uint8

const (
	// AEADChaCha20Poly1305 is the default and mandatory-to-implement AEAD.
	AEADChaCha20Poly1305 AEAD = iota
	// AEADAES256GCM is the optional, handshake-negotiated AEAD for platforms with
	// hardware AES (PROTOCOL.md §3.1).
	AEADAES256GCM
)

// CapAEADAESGCM is the §3.4 capability bit advertising AES-256-GCM support.
const CapAEADAESGCM uint16 = 1 << 0

// String returns the AEAD's mnemonic.
func (a AEAD) String() string {
	if a == AEADAES256GCM {
		return "aes-256-gcm"
	}
	return "chacha20-poly1305"
}

// NegotiateAEAD selects the session AEAD from both peers' capability bitfields:
// AES-256-GCM only if both advertise it, otherwise the ChaCha20-Poly1305 default.
func NegotiateAEAD(clientCaps, serverCaps uint16) AEAD {
	if clientCaps&CapAEADAESGCM != 0 && serverCaps&CapAEADAESGCM != 0 {
		return AEADAES256GCM
	}
	return AEADChaCha20Poly1305
}

// newAEAD builds the cipher.AEAD for the selected construction. AES-256-GCM uses
// the standard 12-byte nonce / 16-byte tag, matching ChaCha20-Poly1305 exactly.
func newAEAD(key [KeySize]byte, a AEAD) (cipher.AEAD, error) {
	if a == AEADAES256GCM {
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	return chacha20poly1305.New(key[:])
}

// Sealer encrypts outgoing frame bodies for one direction.
type Sealer struct {
	aead interface {
		Seal(dst, nonce, plaintext, aad []byte) []byte
	}
	direction byte
}

// SeqUnreliableBit marks a sequence number as belonging to the unreliable frame
// class (ACK/PING/PONG/…). Reliable (ARQ-tracked) frames use the low sequence
// space with this bit clear; unreliable frames set it. This keeps AEAD nonces
// globally unique (the bit is part of the nonce) while letting reliable DATA keep
// a contiguous sequence the receiver can deliver in order without stalling on an
// interleaved unreliable seq. See PROTOCOL.md §3.3 / §5.
const SeqUnreliableBit = uint64(1) << 63

// Opener decrypts incoming frame bodies for one direction, with replay protection.
// Reliable and unreliable sequence spaces (distinguished by SeqUnreliableBit) get
// independent replay windows so their disjoint, separately-contiguous ranges
// don't evict each other.
type Opener struct {
	aead interface {
		Open(dst, nonce, ciphertext, aad []byte) ([]byte, error)
	}
	direction byte
	replay    *ReplayWindow // reliable seq space (bit clear)
	replayU   *ReplayWindow // unreliable seq space (bit set)
}

// NewSealerAEAD creates a Sealer using the given AEAD construction.
func NewSealerAEAD(key [KeySize]byte, direction byte, a AEAD) (*Sealer, error) {
	ae, err := newAEAD(key, a)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: ae, direction: direction}, nil
}

// NewSealer creates a Sealer using the default ChaCha20-Poly1305 AEAD.
func NewSealer(key [KeySize]byte, direction byte) (*Sealer, error) {
	return NewSealerAEAD(key, direction, AEADChaCha20Poly1305)
}

// NewOpenerAEAD creates an Opener using the given AEAD construction.
func NewOpenerAEAD(key [KeySize]byte, direction byte, replayWindow uint64, a AEAD) (*Opener, error) {
	ae, err := newAEAD(key, a)
	if err != nil {
		return nil, err
	}
	return &Opener{
		aead:      ae,
		direction: direction,
		replay:    NewReplayWindow(replayWindow),
		replayU:   NewReplayWindow(replayWindow),
	}, nil
}

// NewOpener creates an Opener using the default ChaCha20-Poly1305 AEAD.
func NewOpener(key [KeySize]byte, direction byte, replayWindow uint64) (*Opener, error) {
	return NewOpenerAEAD(key, direction, replayWindow, AEADChaCha20Poly1305)
}

// Seal encrypts frameBody at the given sequence number.
// aad binds the datagram's session_id and seq (caller supplies the full aad).
func (s *Sealer) Seal(seq uint64, frameBody, aad []byte) []byte {
	nonce := makeNonce(s.direction, seq)
	return s.aead.Seal(nil, nonce[:], frameBody, aad)
}

// Open decrypts ciphertext at the given sequence number and checks for replay.
// The full seq (including SeqUnreliableBit) feeds the nonce; the bit also selects
// which replay window tracks it.
func (o *Opener) Open(seq uint64, ciphertext, aad []byte) ([]byte, error) {
	w := o.replay
	wseq := seq
	if seq&SeqUnreliableBit != 0 {
		w = o.replayU
		wseq = seq &^ SeqUnreliableBit
	}
	// Check replay window before decryption to avoid AEAD work on replayed packets.
	if !w.IsFresh(wseq) {
		return nil, ErrReplay
	}
	nonce := makeNonce(o.direction, seq)
	pt, err := o.aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	// Commit the sequence into the replay window only after successful auth.
	w.Accept(wseq)
	return pt, nil
}

// ── (de)serialization helpers ─────────────────────────────────────────────────

func marshalClientHello(h ClientHello) []byte {
	b := make([]byte, 18)
	copy(b[0:16], h.Random[:])
	binary.BigEndian.PutUint16(b[16:18], h.Caps)
	return b
}

func unmarshalClientHello(b []byte) (ClientHello, error) {
	var h ClientHello
	if len(b) < 18 {
		return h, fmt.Errorf("handofgod/crypto: short ClientHello")
	}
	copy(h.Random[:], b[0:16])
	h.Caps = binary.BigEndian.Uint16(b[16:18])
	return h, nil
}

func marshalServerHello(h ServerHello) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], h.SessionID)
	copy(b[2:18], h.Random[:])
	binary.BigEndian.PutUint16(b[18:20], h.Caps)
	return b
}

func unmarshalServerHello(b []byte) (ServerHello, error) {
	var h ServerHello
	if len(b) < 20 {
		return h, fmt.Errorf("handofgod/crypto: short ServerHello")
	}
	h.SessionID = binary.BigEndian.Uint16(b[0:2])
	copy(h.Random[:], b[2:18])
	h.Caps = binary.BigEndian.Uint16(b[18:20])
	return h, nil
}
