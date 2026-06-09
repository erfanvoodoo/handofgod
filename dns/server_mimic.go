package dns

import (
	"math/rand"
	"strings"
	"sync"
	"time"
)

// ServerMimicry makes Hand of God's authoritative server behave like a normal
// DNS nameserver, not a tunnel endpoint.
//
// This addresses the server-side fingerprint gap identified in the design:
// a Hand of God server receiving an abnormally high query volume, with unusual
// query/response size ratios, for a subdomain that only appears in
// tunneling-shaped traffic — is itself a fingerprint.
//
// ServerMimicry implements:
//   1. Cover response generation — plausible non-tunnel responses for
//      queries that do not carry valid Hand of God payloads.
//   2. Volume normalization — query rate tracking with a circuit breaker
//      that rejects tunnel queries (forces genuine responses) when the
//      rate would exceed normal authoritative server behavior.
//   3. Legitimate zone data — the server appears to serve a real zone
//      with SOA, NS, and A records for plausible subdomains.
//   4. Response timing variance — real authoritative servers have
//      processing jitter; Hand of God adds calibrated jitter to avoid the
//      uniform-sub-millisecond response time that identifies in-process
//      handlers.

// ZoneConfig defines the cover identity Hand of God's authoritative server presents.
type ZoneConfig struct {
	// Zone is the authoritative zone, e.g. "v.example.com".
	Zone string
	// CoverA is the A record returned for the zone apex and unknown subdomains.
	CoverA string // e.g. "93.184.216.34"
	// CoverAAAA is the AAAA record (optional).
	CoverAAAA string
	// NSHosts are the nameserver hostnames to present in NS/SOA records.
	NSHosts []string
	// SOAEmail is the SOA RNAME field (use dots, not @).
	SOAEmail string
	// MaxQueryRatePerMin is the per-minute query rate ceiling before the
	// circuit breaker activates. Normal small-domain authoritative servers
	// receive 10–200 queries/minute. Tunnel traffic is several orders higher.
	// Set to 0 to disable rate-based circuit breaking.
	MaxQueryRatePerMin int
}

// DefaultZoneConfig returns a plausible zone configuration.
func DefaultZoneConfig() ZoneConfig {
	return ZoneConfig{
		Zone:               "v.example.com",
		CoverA:             "93.184.216.34",
		CoverAAAA:          "2606:2800:220:1:248:1893:25c8:1946",
		NSHosts:            []string{"ns1.example.com.", "ns2.example.com."},
		SOAEmail:           "hostmaster.example.com.",
		MaxQueryRatePerMin: 300,
	}
}

// CoverResponseType classifies what kind of cover response to generate.
type CoverResponseType int

const (
	CoverResponseA CoverResponseType = iota
	CoverResponseAAAA
	CoverResponseTXT
	CoverResponseCNAME
	CoverResponseHTTPS
	CoverResponseNXDOMAIN
	CoverResponseSOA
)

// CoverResponse is a neutral cover response descriptor. The wire adapter
// maps this to a concrete DNS message.
type CoverResponse struct {
	Type  CoverResponseType
	FQDN  string
	Value []byte // serialization depends on type
}

// ServerMimic generates cover responses and enforces rate limits. Safe for
// concurrent use: a DNS server invokes these methods from many goroutines (miekg
// dispatches one per query).
type ServerMimic struct {
	cfg ZoneConfig

	// mu guards the mutable state below (rng and queryTimes). cfg is immutable
	// after construction, so CoverResponseFor and its helpers need no lock.
	mu  sync.Mutex
	rng *rand.Rand

	// Rate tracking — circular counter for the past 60 seconds.
	queryTimes []time.Time
}

// NewServerMimic creates a ServerMimic for the given zone.
func NewServerMimic(cfg ZoneConfig) *ServerMimic {
	return &ServerMimic{
		cfg:        cfg,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
		queryTimes: make([]time.Time, 0, 512),
	}
}

// ShouldAcceptTunnelQuery returns true if Hand of God should process this query
// as a tunnel query. Returns false when the rate circuit breaker fires,
// in which case the caller should respond with a cover response instead.
func (m *ServerMimic) ShouldAcceptTunnelQuery() bool {
	if m.cfg.MaxQueryRatePerMin <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Prune old entries.
	i := 0
	for i < len(m.queryTimes) && m.queryTimes[i].Before(cutoff) {
		i++
	}
	m.queryTimes = append(m.queryTimes[i:], now)

	return len(m.queryTimes) <= m.cfg.MaxQueryRatePerMin
}

// CoverResponseFor generates a plausible cover response for the given query FQDN
// and type. Used when a query arrives that is not a valid Hand of God datagram
// (e.g., a censor probe, a random internet query, or a circuit-broken query).
func (m *ServerMimic) CoverResponseFor(fqdn string, qtype RecordType) CoverResponse {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone := strings.TrimSuffix(m.cfg.Zone, ".")

	// SOA queries get a real SOA.
	if qtype == TypeNS {
		return m.soaResponse(fqdn)
	}

	// If the query is outside our zone, NXDOMAIN.
	if !strings.HasSuffix(fqdn, "."+zone) && fqdn != zone {
		return CoverResponse{Type: CoverResponseNXDOMAIN, FQDN: fqdn + "."}
	}

	// Vary the response by record type to match normal authoritative behavior.
	switch qtype {
	case TypeA:
		return CoverResponse{
			Type:  CoverResponseA,
			FQDN:  fqdn + ".",
			Value: m.coverAValue(),
		}
	case TypeAAAA:
		if m.cfg.CoverAAAA != "" {
			return CoverResponse{
				Type:  CoverResponseAAAA,
				FQDN:  fqdn + ".",
				Value: []byte(m.cfg.CoverAAAA),
			}
		}
		return CoverResponse{Type: CoverResponseNXDOMAIN, FQDN: fqdn + "."}
	case TypeTXT:
		return CoverResponse{
			Type:  CoverResponseTXT,
			FQDN:  fqdn + ".",
			Value: m.coverTXTValue(fqdn),
		}
	case TypeCNAME:
		return CoverResponse{
			Type:  CoverResponseCNAME,
			FQDN:  fqdn + ".",
			Value: []byte(zone + "."),
		}
	case TypeHTTPS:
		return CoverResponse{
			Type:  CoverResponseHTTPS,
			FQDN:  fqdn + ".",
			Value: m.coverHTTPSValue(),
		}
	default:
		return CoverResponse{Type: CoverResponseNXDOMAIN, FQDN: fqdn + "."}
	}
}

// ResponseJitter returns a duration to sleep before sending a cover response,
// to mimic real authoritative server processing variance.
// Real authoritative servers: 0.5ms–8ms, with occasional spikes to 20ms.
func (m *ServerMimic) ResponseJitter() time.Duration {
	// Weighted: 70% fast (0.5–3ms), 25% medium (3–8ms), 5% slow (8–20ms).
	m.mu.Lock()
	roll := m.rng.Float64()
	var ms float64
	switch {
	case roll < 0.70:
		ms = 0.5 + m.rng.Float64()*2.5
	case roll < 0.95:
		ms = 3.0 + m.rng.Float64()*5.0
	default:
		ms = 8.0 + m.rng.Float64()*12.0
	}
	m.mu.Unlock()
	return time.Duration(ms * float64(time.Millisecond))
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (m *ServerMimic) coverAValue() []byte {
	return []byte(m.cfg.CoverA)
}

// coverTXTValue returns a plausible TXT record for the subdomain.
// Real zones often have SPF, verification tokens, or status strings.
func (m *ServerMimic) coverTXTValue(fqdn string) []byte {
	templates := []string{
		"v=spf1 include:" + m.cfg.Zone + " ~all",
		"google-site-verification=placeholder",
		"ms=placeholder",
		"status=ok",
	}
	// Select deterministically from the FQDN so repeated probes for the same name
	// get the same answer, as a real authoritative server would. Drawing from the
	// RNG here would return different TXT data for identical queries — itself a
	// tunnel fingerprint. FNV-1a over the query name keeps it stable per name.
	var h uint32 = 2166136261 // FNV-1a offset basis
	for i := 0; i < len(fqdn); i++ {
		h ^= uint32(fqdn[i])
		h *= 16777619
	}
	return []byte(templates[int(h%uint32(len(templates)))])
}

// coverHTTPSValue returns a minimal HTTPS/SVCB record value pointing to the zone.
func (m *ServerMimic) coverHTTPSValue() []byte {
	// HTTPS record format: priority(2) + target + params.
	// We return a minimal ECH-capable HTTPS record stub.
	return []byte("\x00\x01" + m.cfg.Zone + ".")
}

func (m *ServerMimic) soaResponse(fqdn string) CoverResponse {
	// SOA value is textual for the neutral adapter.
	ns := "ns1." + m.cfg.Zone + "."
	if len(m.cfg.NSHosts) > 0 {
		ns = m.cfg.NSHosts[0]
	}
	soa := ns + " " + m.cfg.SOAEmail + " 2024010100 3600 900 604800 300"
	return CoverResponse{
		Type:  CoverResponseSOA,
		FQDN:  fqdn + ".",
		Value: []byte(soa),
	}
}
