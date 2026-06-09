package dns

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
)

// base32Encoding is the standard base32 without padding, using hex alphabet
// (0-9A-V) which produces lowercase-safe, DNS-label-safe characters.
var base32Encoding = base32.HexEncoding.WithPadding(base32.NoPadding)

// Label constraints per RFC 1035.
const (
	maxLabelLen = 63
	maxNameLen  = 253
)

var (
	ErrPayloadTooLarge = errors.New("handofgod/dns: payload too large for label encoding")
	ErrInvalidEncoding = errors.New("handofgod/dns: invalid label encoding")
	ErrInvalidFQDN     = errors.New("handofgod/dns: invalid FQDN structure")
)

// EncodeFQDN / DecodeFQDN and the mode-aware EncodeFQDNMode / DecodeFQDNMode,
// together with the label-entropy codecs (raw / padded / ngram), live in
// labels.go. The FQDN structure is:
//
//	<data_labels>.<session_hex>.<zone>
//
// where data_labels are produced by the active LabelEntropyMode codec,
// session_hex is the 4-char hex session ID, and zone is the operator's zone.

// EncodeTXTValues encodes a response payload into one or more TXT strings.
// DNS TXT strings are limited to 255 bytes each; we use 200 to stay
// comfortably under any resolver that trims to 255.
func EncodeTXTValues(payload []byte) [][]byte {
	const chunkSize = 200
	var out [][]byte
	for len(payload) > 0 {
		n := chunkSize
		if n > len(payload) {
			n = len(payload)
		}
		chunk := make([]byte, n)
		copy(chunk, payload[:n])
		out = append(out, chunk)
		payload = payload[n:]
	}
	return out
}

// DecodeTXTValues concatenates TXT record strings back into the original payload.
func DecodeTXTValues(values [][]byte) []byte {
	var out []byte
	for _, v := range values {
		out = append(out, v...)
	}
	return out
}

// EncodeHTTPSParams encodes a payload into an HTTPS/SVCB SvcParam value.
// We use private SvcParam key 65280 (0xFF00) which is in the reserved range.
// Format: key(2) + len(2) + payload.
func EncodeHTTPSParams(payload []byte) []byte {
	const privateKey = 0xFF00
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(out[0:2], privateKey)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	copy(out[4:], payload)
	return out
}

// DecodeHTTPSParams extracts payload from an HTTPS/SVCB SvcParam value.
func DecodeHTTPSParams(data []byte) ([]byte, error) {
	const privateKey = 0xFF00
	if len(data) < 4 {
		return nil, ErrInvalidEncoding
	}
	if binary.BigEndian.Uint16(data[0:2]) != privateKey {
		return nil, ErrInvalidEncoding
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+length {
		return nil, ErrInvalidEncoding
	}
	out := make([]byte, length)
	copy(out, data[4:4+length])
	return out, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func splitLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > 0 {
		n := maxLen
		if n > len(s) {
			n = len(s)
		}
		labels = append(labels, s[:n])
		s = s[n:]
	}
	return labels
}

func hexUint16(v uint16) string {
	const hex = "0123456789abcdef"
	return string([]byte{
		hex[v>>12&0xf],
		hex[v>>8&0xf],
		hex[v>>4&0xf],
		hex[v>>0&0xf],
	})
}

func parseHexUint16(s string) (uint16, error) {
	if len(s) != 4 {
		return 0, errors.New("expected 4 hex chars")
	}
	var v uint16
	for _, c := range []byte(s) {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, errors.New("invalid hex char")
		}
		v = v<<4 | uint16(d)
	}
	return v, nil
}
