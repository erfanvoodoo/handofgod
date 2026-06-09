// Package frame implements Hand of God's datagram and frame encoding.
// See PROTOCOL.md §4 and §5.
//
// A datagram is the on-wire encrypted unit (one per DNS message):
//
//	[session_id:2][seq:8][ciphertext+tag:N]
//
// The ciphertext decrypts to a frame body:
//
//	[type:1][stream_id:2][payload:M]
package frame

import (
	"encoding/binary"
	"errors"

	"github.com/handofgod/crypto"
)

// Frame types — see PROTOCOL.md §5.
const (
	TypeHandshakeInit byte = 0x01
	TypeHandshakeResp byte = 0x02
	TypeData          byte = 0x10
	TypeAck           byte = 0x11
	TypeStreamOpen    byte = 0x20
	TypeStreamClose   byte = 0x21
	TypePing          byte = 0x30
	TypePong          byte = 0x31
	TypeMTUProbe      byte = 0x40
	TypeMTUAck        byte = 0x41
	TypeSessionClose  byte = 0x50
)

// Error codes — see PROTOCOL.md §9.
const (
	ErrCodeNormal   byte = 0x00
	ErrCodeProtocol byte = 0x01
	ErrCodeCrypto   byte = 0x02
	ErrCodeTimeout  byte = 0x03
	ErrCodeResource byte = 0x04
	ErrCodeVersion  byte = 0x05
)

const (
	// DatagramHeaderSize is the cleartext header: session_id(2) + seq(8).
	DatagramHeaderSize = 10
	// FrameHeaderSize is the encrypted frame header: type(1) + stream_id(2).
	FrameHeaderSize = 3
	// Overhead is the total per-datagram overhead: datagram header + AEAD tag + frame header.
	Overhead = DatagramHeaderSize + crypto.TagSize + FrameHeaderSize
)

var (
	ErrShortDatagram = errors.New("handofgod/frame: datagram too short")
	ErrShortFrame    = errors.New("handofgod/frame: frame body too short")
)

// Frame is a decoded frame body.
type Frame struct {
	Type     byte
	StreamID uint16
	Payload  []byte
}

// EncodeDatagram seals a frame into an on-wire datagram.
// sessionID and seq form the cleartext header and the AEAD aad.
func EncodeDatagram(sealer *crypto.Sealer, sessionID uint16, seq uint64, f Frame) []byte {
	// Build frame body: [type][stream_id][payload]
	body := make([]byte, FrameHeaderSize+len(f.Payload))
	body[0] = f.Type
	binary.BigEndian.PutUint16(body[1:3], f.StreamID)
	copy(body[3:], f.Payload)

	// Cleartext header doubles as AEAD aad
	header := make([]byte, DatagramHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], sessionID)
	binary.BigEndian.PutUint64(header[2:10], seq)

	ciphertext := sealer.Seal(seq, body, header)

	out := make([]byte, 0, DatagramHeaderSize+len(ciphertext))
	out = append(out, header...)
	out = append(out, ciphertext...)
	return out
}

// ParseDatagramHeader extracts the cleartext session_id and seq without decrypting.
// Used by the server to select the session key before opening.
func ParseDatagramHeader(datagram []byte) (sessionID uint16, seq uint64, err error) {
	if len(datagram) < DatagramHeaderSize+crypto.TagSize {
		return 0, 0, ErrShortDatagram
	}
	sessionID = binary.BigEndian.Uint16(datagram[0:2])
	seq = binary.BigEndian.Uint64(datagram[2:10])
	return sessionID, seq, nil
}

// DecodeDatagram opens a datagram and returns the decoded frame.
func DecodeDatagram(opener *crypto.Opener, datagram []byte) (sessionID uint16, seq uint64, f Frame, err error) {
	sessionID, seq, err = ParseDatagramHeader(datagram)
	if err != nil {
		return 0, 0, f, err
	}

	header := datagram[:DatagramHeaderSize]
	ciphertext := datagram[DatagramHeaderSize:]

	body, err := opener.Open(seq, ciphertext, header)
	if err != nil {
		return 0, 0, f, err
	}
	if len(body) < FrameHeaderSize {
		return 0, 0, f, ErrShortFrame
	}

	f.Type = body[0]
	f.StreamID = binary.BigEndian.Uint16(body[1:3])
	f.Payload = body[FrameHeaderSize:]
	return sessionID, seq, f, nil
}

// ── ACK payload (SACK) — PROTOCOL.md §6.2 ────────────────────────────────────

// SackRange is an inclusive range of received sequence numbers.
type SackRange struct {
	Start uint64
	End   uint64
}

// AckPayload is the decoded payload of an ACK frame.
type AckPayload struct {
	CumulativeAck uint64
	Ranges        []SackRange
}

// EncodeAck serializes an ACK payload.
func EncodeAck(a AckPayload) []byte {
	n := len(a.Ranges)
	if n > 255 {
		n = 255
		a.Ranges = a.Ranges[:255]
	}
	buf := make([]byte, 8+1+n*16)
	binary.BigEndian.PutUint64(buf[0:8], a.CumulativeAck)
	buf[8] = byte(n)
	off := 9
	for _, r := range a.Ranges {
		binary.BigEndian.PutUint64(buf[off:off+8], r.Start)
		binary.BigEndian.PutUint64(buf[off+8:off+16], r.End)
		off += 16
	}
	return buf
}

// DecodeAck parses an ACK payload.
func DecodeAck(payload []byte) (AckPayload, error) {
	var a AckPayload
	if len(payload) < 9 {
		return a, ErrShortFrame
	}
	a.CumulativeAck = binary.BigEndian.Uint64(payload[0:8])
	n := int(payload[8])
	off := 9
	if len(payload) < off+n*16 {
		return a, ErrShortFrame
	}
	a.Ranges = make([]SackRange, n)
	for i := 0; i < n; i++ {
		a.Ranges[i].Start = binary.BigEndian.Uint64(payload[off : off+8])
		a.Ranges[i].End = binary.BigEndian.Uint64(payload[off+8 : off+16])
		off += 16
	}
	return a, nil
}
