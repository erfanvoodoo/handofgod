package main

import (
	"strings"

	"github.com/handofgod/frame"
)

// maxWritePayload returns the largest application-payload chunk that can be
// safely passed to (Server)Session.Write for a given zone and label-entropy
// mode. Writes exceeding this size are silently dropped by dns.Client's
// handleSlot when EncodeFQDNMode returns ErrPayloadTooLarge (see dns/client.go:
// stats.Dropped++). Callers MUST pre-chunk before Write.
//
// The math walks EncodeFQDNMode's constraint backward. The FQDN is:
//
//	<data_chars>.<sess:4>.<zone>.
//	len(fqdn) = data_chars + labelCount(data_chars) + 6 + len(zone)  ≤ 254
//
// (dots: K between data labels + 1 before sess + 1 before zone + 1 trailing =
// K+2 = labelCount + 2; plus 4 for the sess hex; total non-data = K+6+len(zone).)
//
// From the maximum permitted data_chars we invert each codec's byte→char rule
// to derive the maximum datagram size, then subtract frame.Overhead to get the
// application payload, then trim a safety margin.
//
// This function is duplicated (verbatim) in cmd/handofgod-proxy-client/chunk.go
// so the two binaries stay independent of each other and of any shared
// helper package. Keep them in sync.
func maxWritePayload(zone, mode string) int {
	const safetyMargin = 8
	zone = strings.TrimSuffix(zone, ".")
	z := len(zone)
	// Search datagram sizes from a generous upper bound down; return the first
	// (largest) that fits the FQDN length constraint under this codec's char
	// expansion.
	for datagramBytes := 250; datagramBytes >= 1; datagramBytes-- {
		chars := encodedChars(datagramBytes, mode)
		if chars <= 0 {
			continue
		}
		labels := (chars + 62) / 63 // ceil(chars / maxLabelLen)
		if labels == 0 {
			labels = 1
		}
		if chars+labels+6+z <= 254 {
			payload := datagramBytes - frame.Overhead - safetyMargin
			if payload < 1 {
				return 1
			}
			return payload
		}
	}
	return 1
}

// encodedChars mirrors CodecFor(mode).EncodeLabels' output length for an input
// of datagramBytes. Returns 0 if the codec would produce empty output (i.e. the
// datagram is too small for that codec's minimum framing).
func encodedChars(datagramBytes int, mode string) int {
	switch mode {
	case "ngram":
		// ngram: 2 chars per byte (see dns/labels.go ngramCodec.EncodeLabels).
		return datagramBytes * 2
	case "padded":
		// padded: input is (datagramBytes + 2) rounded up to next multiple of
		// 16 bytes, then base32hex encoded (see dns/labels.go paddedCodec).
		padded := ((datagramBytes + 2 + 15) / 16) * 16
		return (padded*8 + 4) / 5
	default: // "raw" and unknown fall back to raw per dns/labels.go CodecFor
		// raw: base32hex without padding — chars = (bytes*8 + 4) / 5.
		return (datagramBytes*8 + 4) / 5
	}
}
