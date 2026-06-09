package dns

import (
	"bytes"
	"strings"
	"testing"
)

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	return b
}

// TestLabelCodecsRoundTrip verifies every entropy mode is a clean bijection
// across a spread of payload sizes and byte values.
func TestLabelCodecsRoundTrip(t *testing.T) {
	modes := []string{"raw", "padded", "ngram"}
	payloads := [][]byte{
		{0x00},
		{0xff},
		{0xde, 0xad, 0xbe, 0xef},
		seqBytes(1),
		seqBytes(15),
		seqBytes(16),
		seqBytes(17),
		seqBytes(40),
	}
	for _, mode := range modes {
		codec := CodecFor(mode)
		for _, p := range payloads {
			labels, err := codec.EncodeLabels(p)
			if err != nil {
				t.Fatalf("mode=%s len=%d encode: %v", mode, len(p), err)
			}
			for _, l := range labels {
				if len(l) == 0 || len(l) > maxLabelLen {
					t.Errorf("mode=%s: bad label length %d", mode, len(l))
				}
			}
			got, err := codec.DecodeLabels(labels)
			if err != nil {
				t.Fatalf("mode=%s len=%d decode: %v", mode, len(p), err)
			}
			if !bytes.Equal(got, p) {
				t.Errorf("mode=%s: round-trip mismatch got %x want %x", mode, got, p)
			}
		}
	}
}

// TestPaddedHidesExactSize verifies the padded codec quantizes length to a
// block, so two payloads in the same block produce equal-length output but a
// payload in the next block grows.
func TestPaddedHidesExactSize(t *testing.T) {
	c := CodecFor("padded")
	encLen := func(n int) int {
		labels, err := c.EncodeLabels(make([]byte, n))
		if err != nil {
			t.Fatalf("encode len %d: %v", n, err)
		}
		return len(strings.Join(labels, ""))
	}
	// 2+4=6 and 2+12=14 both pad to the first 16-byte block.
	if a, b := encLen(4), encLen(12); a != b {
		t.Errorf("padded length leaks size within a block: %d vs %d", a, b)
	}
	// 2+20=22 rolls into the next block and must be longer.
	if small, big := encLen(4), encLen(20); big <= small {
		t.Errorf("padded did not grow across block boundary: %d vs %d", small, big)
	}
}

// TestNgramProducesWordLikeLabels verifies ngram output is all letters and
// survives DNS case randomization.
func TestNgramProducesWordLikeLabels(t *testing.T) {
	c := CodecFor("ngram")
	payload := seqBytes(30)
	labels, err := c.EncodeLabels(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range labels {
		for i := 0; i < len(l); i++ {
			if l[i] < 'a' || l[i] > 'z' {
				t.Fatalf("ngram label has non-letter %q in %q", l[i], l)
			}
		}
	}
	// Resolvers may randomize case (0x20 encoding); decode must normalize.
	upper := make([]string, len(labels))
	for i, l := range labels {
		upper[i] = strings.ToUpper(l)
	}
	got, err := c.DecodeLabels(upper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("ngram did not survive uppercase case-mangling")
	}
}

func TestNgramRejectsMalformedInput(t *testing.T) {
	c := CodecFor("ngram")
	// Odd length can never be a valid 2-char-per-byte stream.
	if _, err := c.DecodeLabels([]string{"abc"}); err == nil {
		t.Error("expected error for odd-length ngram input")
	}
	// 'e' is a vowel; the start context 'e' only admits consonants first, so a
	// leading 'e' is unreachable and must be rejected.
	if _, err := c.DecodeLabels([]string{"ee"}); err == nil {
		t.Error("expected error for unreachable ngram char")
	}
}

// TestEncodeFQDNMode_RoundTrip exercises full FQDN assembly+disassembly for
// every mode, including the session ID and zone.
func TestEncodeFQDNMode_RoundTrip(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	const zone = "v.example.com"
	for _, mode := range []string{"raw", "padded", "ngram"} {
		fqdn, err := EncodeFQDNMode(payload, 0x0a3f, zone, mode)
		if err != nil {
			t.Fatalf("mode=%s encode: %v", mode, err)
		}
		if !strings.HasSuffix(fqdn, "."+zone+".") {
			t.Errorf("mode=%s: bad suffix %s", mode, fqdn)
		}
		for _, l := range strings.Split(strings.TrimSuffix(fqdn, "."), ".") {
			if len(l) > maxLabelLen {
				t.Errorf("mode=%s: label too long: %s", mode, l)
			}
		}
		gotP, gotSID, err := DecodeFQDNMode(fqdn, zone, mode)
		if err != nil {
			t.Fatalf("mode=%s decode: %v", mode, err)
		}
		if gotSID != 0x0a3f {
			t.Errorf("mode=%s sid: got %x want 0a3f", mode, gotSID)
		}
		if !bytes.Equal(gotP, payload) {
			t.Errorf("mode=%s payload mismatch: got %x", mode, gotP)
		}
	}
}

// TestEncodeFQDN_RawMatchesMode confirms the 2-arg API is exactly the "raw"
// special case, so legacy callers are unaffected by the Phase 3 refactor.
func TestEncodeFQDN_RawMatchesMode(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	a, err := EncodeFQDN(payload, 0x1234, "v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeFQDNMode(payload, 0x1234, "v.example.com", "raw")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("raw mode mismatch: %q vs %q", a, b)
	}
}

// TestNgramCapacityLimit confirms the name-length limit still fires for ngram,
// whose 2-chars-per-byte expansion lowers per-query capacity.
func TestNgramCapacityLimit(t *testing.T) {
	if _, err := EncodeFQDNMode(make([]byte, 130), 0x0001, "v.example.com", "ngram"); err != ErrPayloadTooLarge {
		t.Errorf("expected ErrPayloadTooLarge for oversize ngram payload, got %v", err)
	}
}
