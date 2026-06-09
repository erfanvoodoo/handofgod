// Package dns implements Hand of God's DNS encoding and stealth layer.
//
// Architecture:
//
//	Hand of God frame bytes
//	     ↓
//	[encode/]   — splits payload into DNS-safe chunks, encodes to labels/values
//	     ↓
//	[record.go] — neutral record representation (no net dependency)
//	     ↓
//	[adapter]   — thin wire layer (miekg/dns at integration time)
//	     ↓
//	UDP/53 wire
//
// The stealth layer sits between encode and record: it selects record types,
// shapes label entropy, and schedules query timing to match a target profile.
// See PROTOCOL.md §10 and §11.
package dns

// RecordType is a DNS record type value.
type RecordType uint16

const (
	TypeA     RecordType = 1
	TypeNS    RecordType = 2
	TypeCNAME RecordType = 5
	TypeTXT   RecordType = 16
	TypeAAAA  RecordType = 28
	TypeHTTPS RecordType = 65
)

// String returns the mnemonic for a record type.
func (t RecordType) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeHTTPS:
		return "HTTPS"
	default:
		return "UNKNOWN"
	}
}

// PayloadCapacity returns the maximum Hand of God payload bytes this record type
// can carry per query/response pair (upstream / downstream respectively).
// This is payload capacity AFTER framing; values are conservative.
//
// Asymmetry: upstream (query) capacity is limited by subdomain label length
// constraints; downstream (response) capacity is limited by response record
// content limits.
func (t RecordType) UpstreamCapacity() int {
	switch t {
	case TypeTXT:
		// TXT QNAME: up to 63 chars per label × 3 labels ≈ 180 bytes; base32hex
		// encoding expands 5→8, so ~112 raw bytes upstream.
		return 112
	case TypeA:
		// A QNAME: encode data in subdomain labels; same label budget as TXT query.
		// Practical: 2 data labels × 56 chars base32hex = 70 raw bytes.
		return 70
	case TypeAAAA:
		return 70
	case TypeCNAME:
		return 70
	case TypeHTTPS:
		return 112
	default:
		return 40
	}
}

func (t RecordType) DownstreamCapacity() int {
	switch t {
	case TypeTXT:
		// TXT RDATA: up to 255 bytes per string, multiple strings → ~500 raw bytes.
		return 500
	case TypeHTTPS:
		// HTTPS SVCB params can carry ~480 bytes of arbitrary params.
		return 480
	case TypeCNAME:
		// CNAME target is a domain name, ~180 bytes usable.
		return 180
	case TypeA:
		// A record is 4 bytes — only useful for tiny responses or cover.
		return 4
	case TypeAAAA:
		// AAAA is 16 bytes.
		return 16
	default:
		return 40
	}
}

// IsCoverOnly returns true for record types whose capacity is too small to
// carry real payload and are used only for timing/pattern cover.
func (t RecordType) IsCoverOnly() bool {
	return t == TypeA || t == TypeAAAA
}

// Query is a neutral representation of a DNS query Hand of God would send.
// The wire adapter maps this to a concrete DNS message.
type Query struct {
	// FQDN is the full query name, e.g. "a4bc.d.example.com."
	FQDN string
	// Type is the record type being queried.
	Type RecordType
	// SessionID ties the query to a Hand of God session (carried in FQDN).
	SessionID uint16
	// Seq is the Hand of God sequence number (carried in FQDN).
	Seq uint64
	// IsCover is true when this query carries no real payload (timing filler).
	IsCover bool
}

// Response is a neutral representation of a DNS response Hand of God receives.
type Response struct {
	// FQDN echoes the query name.
	FQDN string
	// Type echoes the record type.
	Type RecordType
	// Values holds the response record values (TXT strings, CNAME target, etc.)
	Values [][]byte
	// IsCover is true when this response is known to carry no real payload.
	IsCover bool
}
