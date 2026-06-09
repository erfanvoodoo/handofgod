package frame

import (
	"bytes"
	"testing"

	"github.com/handofgod/crypto"
)

func newSealerOpener(t *testing.T) (*crypto.Sealer, *crypto.Opener) {
	t.Helper()
	var key [crypto.KeySize]byte
	for i := range key {
		key[i] = byte(i * 7)
	}
	s, err := crypto.NewSealer(key, crypto.DirClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	o, err := crypto.NewOpener(key, crypto.DirClientToServer, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return s, o
}

func TestDatagramRoundTrip(t *testing.T) {
	sealer, opener := newSealerOpener(t)

	orig := Frame{
		Type:     TypeData,
		StreamID: 0x1234,
		Payload:  []byte("hello over DNS"),
	}

	dg := EncodeDatagram(sealer, 0xBEEF, 7, orig)

	gotSession, gotSeq, gotFrame, err := DecodeDatagram(opener, dg)
	if err != nil {
		t.Fatal(err)
	}
	if gotSession != 0xBEEF {
		t.Errorf("session: got %x want BEEF", gotSession)
	}
	if gotSeq != 7 {
		t.Errorf("seq: got %d want 7", gotSeq)
	}
	if gotFrame.Type != orig.Type || gotFrame.StreamID != orig.StreamID {
		t.Errorf("frame header mismatch")
	}
	if !bytes.Equal(gotFrame.Payload, orig.Payload) {
		t.Errorf("payload: got %q want %q", gotFrame.Payload, orig.Payload)
	}
}

func TestParseHeaderWithoutDecrypt(t *testing.T) {
	sealer, _ := newSealerOpener(t)
	dg := EncodeDatagram(sealer, 0xABCD, 99, Frame{Type: TypePing, Payload: []byte("12345678")})

	sid, seq, err := ParseDatagramHeader(dg)
	if err != nil {
		t.Fatal(err)
	}
	if sid != 0xABCD || seq != 99 {
		t.Errorf("header parse: got sid=%x seq=%d", sid, seq)
	}
}

func TestOverheadConstant(t *testing.T) {
	sealer, _ := newSealerOpener(t)
	dg := EncodeDatagram(sealer, 1, 1, Frame{Type: TypeData, StreamID: 1, Payload: nil})
	// Empty payload datagram size should equal Overhead.
	if len(dg) != Overhead {
		t.Errorf("empty datagram size %d != Overhead constant %d", len(dg), Overhead)
	}
}

func TestAckRoundTrip(t *testing.T) {
	a := AckPayload{
		CumulativeAck: 1000,
		Ranges: []SackRange{
			{Start: 1005, End: 1010},
			{Start: 1015, End: 1015},
		},
	}
	encoded := EncodeAck(a)
	decoded, err := DecodeAck(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CumulativeAck != a.CumulativeAck {
		t.Errorf("cumulative ack mismatch")
	}
	if len(decoded.Ranges) != 2 {
		t.Fatalf("range count: got %d want 2", len(decoded.Ranges))
	}
	if decoded.Ranges[0] != a.Ranges[0] || decoded.Ranges[1] != a.Ranges[1] {
		t.Errorf("ranges mismatch: %+v", decoded.Ranges)
	}
}
