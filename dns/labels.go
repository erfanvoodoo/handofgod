package dns

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// labels.go implements Hand of God's Phase 3 "advanced encoding strategies": the
// label-entropy engine that transforms a Hand of God datagram into the data-label
// portion of a query FQDN according to a profile's LabelEntropyMode.
//
// All codecs are bijective: DecodeLabels(EncodeLabels(p)) == p. The mode is a
// deployment/profile setting known to both endpoints (it is not carried on the
// wire), so the resolver-side decoder is told which mode to use.
//
//	raw    — straight base32hex. Fastest, highest density, most fingerprintable
//	         (a single high-entropy blob is the classic DNS-tunnel tell).
//	padded — base32hex with a length-prefixed, block-padded body so the query
//	         length only leaks payload size at block granularity, not exactly.
//	ngram  — order-1 Markov character coding: each payload nibble selects from a
//	         context-dependent 16-letter candidate set, producing pronounceable,
//	         word-like labels instead of a high-entropy blob. Reversible because
//	         the candidate sets are fixed and the selection is a plain base-16
//	         digit. See PROTOCOL.md §13.

// LabelCodec encodes/decodes a payload to/from the variable data labels of a
// Hand of God FQDN. Implementations are bijective.
type LabelCodec interface {
	// Mode returns the LabelEntropyMode name this codec implements.
	Mode() string
	// EncodeLabels turns a payload into one or more DNS-safe data labels
	// (each ≤63 chars).
	EncodeLabels(payload []byte) ([]string, error)
	// DecodeLabels reverses EncodeLabels, recovering the original payload.
	DecodeLabels(labels []string) ([]byte, error)
}

// CodecFor returns the LabelCodec for a LabelEntropyMode name. Unknown or empty
// modes fall back to raw.
func CodecFor(mode string) LabelCodec {
	switch mode {
	case "padded":
		return paddedCodec{block: 16}
	case "ngram":
		return ngramCodec{}
	case "raw", "":
		return rawCodec{}
	default:
		return rawCodec{}
	}
}

// ── raw ─────────────────────────────────────────────────────────────────────

type rawCodec struct{}

func (rawCodec) Mode() string { return "raw" }

func (rawCodec) EncodeLabels(payload []byte) ([]string, error) {
	enc := strings.ToLower(base32Encoding.EncodeToString(payload))
	return splitLabels(enc, maxLabelLen), nil
}

func (rawCodec) DecodeLabels(labels []string) ([]byte, error) {
	enc := strings.ToUpper(strings.Join(labels, ""))
	out, err := base32Encoding.DecodeString(enc)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	return out, nil
}

// ── padded ──────────────────────────────────────────────────────────────────

type paddedCodec struct{ block int }

func (paddedCodec) Mode() string { return "padded" }

// EncodeLabels frames the payload as [len:2][payload][random pad] rounded up to
// a multiple of block bytes, then base32hex-encodes it. Because the byte length
// is quantized, the resulting label length only reveals the payload size to
// block granularity.
func (p paddedCodec) EncodeLabels(payload []byte) ([]string, error) {
	if len(payload) > 0xffff {
		return nil, ErrPayloadTooLarge
	}
	block := p.block
	if block <= 0 {
		block = 16
	}
	total := 2 + len(payload)
	padded := ((total + block - 1) / block) * block
	buf := make([]byte, padded)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(payload)))
	copy(buf[2:], payload)
	if padded > total {
		if _, err := rand.Read(buf[total:]); err != nil {
			return nil, err
		}
	}
	enc := strings.ToLower(base32Encoding.EncodeToString(buf))
	return splitLabels(enc, maxLabelLen), nil
}

func (paddedCodec) DecodeLabels(labels []string) ([]byte, error) {
	enc := strings.ToUpper(strings.Join(labels, ""))
	buf, err := base32Encoding.DecodeString(enc)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	if len(buf) < 2 {
		return nil, ErrInvalidEncoding
	}
	n := int(binary.BigEndian.Uint16(buf[0:2]))
	if 2+n > len(buf) {
		return nil, ErrInvalidEncoding
	}
	out := make([]byte, n)
	copy(out, buf[2:2+n])
	return out, nil
}

// ── ngram ───────────────────────────────────────────────────────────────────

// The order-1 Markov model is encoded as fixed candidate sets: given the
// previous output letter (the "context"), the next letter is chosen from a
// 16-entry candidate list by a 4-bit payload nibble. The sets are built from a
// frequency-ordered vowel/consonant split so output reads like real words:
// a vowel is always followed by a consonant; a consonant is followed by a vowel
// or a common consonant.
const (
	ngramVowels     = "eaoiu"                 // 5, frequency-ish order
	ngramConsonants = "tnrshdlcmpfgbvwykjqxz" // 21, frequency-ish order
	ngramStartCtx   = 'e'                     // fixed seed context (a vowel)
)

// ngramCandidates returns the 16-letter candidate set for a context letter.
// Both endpoints derive these identically, so the mapping is a stable bijection
// between a 4-bit index and a letter within each context.
func ngramCandidates(ctx byte) string {
	if isNgramVowel(ctx) {
		// After a vowel: 16 consonants (always pronounceable).
		return ngramConsonants[:16]
	}
	// After a consonant: 5 vowels + 11 common consonants = 16.
	return ngramVowels + ngramConsonants[:11]
}

func isNgramVowel(c byte) bool {
	for i := 0; i < len(ngramVowels); i++ {
		if ngramVowels[i] == c {
			return true
		}
	}
	return false
}

func ngramIndex(cands string, c byte) int {
	for i := 0; i < len(cands); i++ {
		if cands[i] == c {
			return i
		}
	}
	return -1
}

type ngramCodec struct{}

func (ngramCodec) Mode() string { return "ngram" }

// EncodeLabels emits two letters per payload byte (one per nibble), walking the
// Markov candidate sets. Output is all lowercase a–z, so every label is DNS-safe
// and word-like.
func (ngramCodec) EncodeLabels(payload []byte) ([]string, error) {
	var sb strings.Builder
	sb.Grow(len(payload) * 2)
	ctx := byte(ngramStartCtx)
	for _, b := range payload {
		hi := b >> 4
		lo := b & 0x0f
		cands := ngramCandidates(ctx)
		ch := cands[hi]
		sb.WriteByte(ch)
		ctx = ch
		cands = ngramCandidates(ctx)
		ch = cands[lo]
		sb.WriteByte(ch)
		ctx = ch
	}
	return splitLabels(sb.String(), maxLabelLen), nil
}

func (ngramCodec) DecodeLabels(labels []string) ([]byte, error) {
	// DNS is case-insensitive (resolvers may randomize case): normalize first.
	s := strings.ToLower(strings.Join(labels, ""))
	if len(s)%2 != 0 {
		return nil, ErrInvalidEncoding
	}
	out := make([]byte, 0, len(s)/2)
	ctx := byte(ngramStartCtx)
	for i := 0; i < len(s); i += 2 {
		hi := ngramIndex(ngramCandidates(ctx), s[i])
		if hi < 0 {
			return nil, ErrInvalidEncoding
		}
		ctx = s[i]
		lo := ngramIndex(ngramCandidates(ctx), s[i+1])
		if lo < 0 {
			return nil, ErrInvalidEncoding
		}
		ctx = s[i+1]
		out = append(out, byte(hi<<4|lo))
	}
	return out, nil
}

// ── FQDN assembly (mode-aware) ────────────────────────────────────────────────

// EncodeFQDNMode encodes a payload into a query FQDN using the given
// LabelEntropyMode. The structure is <data_labels>.<session_hex>.<zone>. The
// 2-arg EncodeFQDN is the "raw" special case.
func EncodeFQDNMode(payload []byte, sessionID uint16, zone, mode string) (string, error) {
	if len(zone) == 0 {
		zone = "example.com"
	}
	zone = strings.TrimSuffix(zone, ".")

	labels, err := CodecFor(mode).EncodeLabels(payload)
	if err != nil {
		return "", err
	}

	sessionLabel := hexUint16(sessionID)

	parts := make([]string, 0, len(labels)+2)
	parts = append(parts, labels...)
	parts = append(parts, sessionLabel)
	parts = append(parts, zone)
	fqdn := strings.Join(parts, ".") + "."

	if len(fqdn) > maxNameLen+1 { // +1 for trailing dot
		return "", ErrPayloadTooLarge
	}
	return fqdn, nil
}

// DecodeFQDNMode reverses EncodeFQDNMode. mode must match the mode used to
// encode (a deployment/profile setting, not carried on the wire).
func DecodeFQDNMode(fqdn, zone, mode string) (payload []byte, sessionID uint16, err error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	if !strings.HasSuffix(fqdn, "."+zone) && fqdn != zone {
		return nil, 0, ErrInvalidFQDN
	}

	prefix := strings.TrimSuffix(fqdn, "."+zone)
	if prefix == fqdn {
		return nil, 0, ErrInvalidFQDN
	}

	parts := strings.Split(prefix, ".")
	if len(parts) < 2 {
		return nil, 0, ErrInvalidFQDN
	}

	sessLabel := parts[len(parts)-1]
	dataLabels := parts[:len(parts)-1]

	sid, err := parseHexUint16(sessLabel)
	if err != nil {
		return nil, 0, ErrInvalidFQDN
	}

	payload, err = CodecFor(mode).DecodeLabels(dataLabels)
	if err != nil {
		return nil, 0, err
	}
	return payload, sid, nil
}

// EncodeFQDN encodes a payload into a query FQDN using the raw label codec.
// It is preserved for callers that don't select a stealth mode; see
// EncodeFQDNMode for profile-driven encoding.
func EncodeFQDN(payload []byte, sessionID uint16, zone string) (string, error) {
	return EncodeFQDNMode(payload, sessionID, zone, "raw")
}

// DecodeFQDN reverses EncodeFQDN (raw codec). See DecodeFQDNMode.
func DecodeFQDN(fqdn, zone string) (payload []byte, sessionID uint16, err error) {
	return DecodeFQDNMode(fqdn, zone, "raw")
}
