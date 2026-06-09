package dns

import (
	"encoding/json"
	"math/rand"
	"os"
	"time"
)

// Profile defines the statistical target for DNS traffic shaping.
// A profile is derived from real traffic captures and describes what
// "normal" DNS traffic looks like for a given usage pattern.
//
// Profiles are JSON files and can be hot-swapped without restarting Hand of God.
// This is the DNS equivalent of ShapeCraft's traffic profiles.
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`

	// RecordTypeWeights is the normalized weight distribution for query types.
	// Keys are record type values (1=A, 16=TXT, 28=AAAA, 65=HTTPS, 5=CNAME).
	// The weights must sum to 1.0. Queries are drawn from this distribution.
	RecordTypeWeights map[uint16]float64 `json:"record_type_weights"`

	// QueryIntervalMs defines the inter-query interval distribution in milliseconds.
	// Bucket ranges are [BucketMin, BucketMax) with associated Weight.
	QueryIntervalMs []Bucket `json:"query_interval_ms"`

	// BurstSize defines how many queries arrive in a burst (bursty DNS behavior).
	// Real DNS is bursty around page loads/app starts, not a flat stream.
	BurstSize []Bucket `json:"burst_size"`

	// IdleGapMs defines the distribution of gaps between bursts.
	IdleGapMs []Bucket `json:"idle_gap_ms"`

	// CoverQueryRate is the fraction of queries that should be cover (0.0–1.0).
	// Cover queries carry no payload but maintain timing characteristics.
	CoverQueryRate float64 `json:"cover_query_rate"`

	// LabelEntropyMode controls how data labels are constructed. The active
	// codec is resolved via CodecFor (see labels.go).
	// "raw"    - straight base32hex (fast, dense, fingerprint-able)
	// "padded" - length-prefixed, block-padded base32hex (hides exact size)
	// "ngram"  - order-1 Markov shaping into word-like labels (high stealth)
	LabelEntropyMode string `json:"label_entropy_mode"`
}

// Bucket is a histogram bucket for sampling distributions.
type Bucket struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Weight float64 `json:"weight"`
}

// Sample draws a value uniformly from the bucket range [Min, Max).
func (b Bucket) Sample(r *rand.Rand) float64 {
	if b.Max <= b.Min {
		return b.Min
	}
	return b.Min + r.Float64()*(b.Max-b.Min)
}

// ── Built-in profiles ────────────────────────────────────────────────────────

// ProfileStandardDNS models typical stub-resolver traffic: A and AAAA dominated,
// occasional TXT (SPF/DKIM lookups), short bursts around connections.
var ProfileStandardDNS = Profile{
	Name:        "standard_dns",
	Description: "Typical stub-resolver traffic mix (A/AAAA dominant)",
	RecordTypeWeights: map[uint16]float64{
		1:  0.52, // A
		28: 0.32, // AAAA
		16: 0.08, // TXT
		65: 0.05, // HTTPS
		5:  0.03, // CNAME
	},
	QueryIntervalMs: []Bucket{
		{Min: 0, Max: 5, Weight: 0.30},    // rapid burst
		{Min: 5, Max: 50, Weight: 0.25},   // fast follow-up
		{Min: 50, Max: 200, Weight: 0.20}, // normal spacing
		{Min: 200, Max: 1000, Weight: 0.15},
		{Min: 1000, Max: 5000, Weight: 0.10},
	},
	BurstSize: []Bucket{
		{Min: 1, Max: 3, Weight: 0.50},
		{Min: 3, Max: 6, Weight: 0.30},
		{Min: 6, Max: 12, Weight: 0.20},
	},
	IdleGapMs: []Bucket{
		{Min: 1000, Max: 5000, Weight: 0.40},
		{Min: 5000, Max: 30000, Weight: 0.35},
		{Min: 30000, Max: 120000, Weight: 0.25},
	},
	CoverQueryRate:   0.15,
	LabelEntropyMode: "padded",
}

// ProfileDoHMix models DNS-over-HTTPS gateway traffic: heavier TXT and HTTPS,
// longer inter-query gaps, bigger bursts.
var ProfileDoHMix = Profile{
	Name:        "doh_mix",
	Description: "DoH gateway traffic (TXT/HTTPS enriched, used by modern browsers)",
	RecordTypeWeights: map[uint16]float64{
		1:  0.38,
		28: 0.28,
		16: 0.14,
		65: 0.15,
		5:  0.05,
	},
	QueryIntervalMs: []Bucket{
		{Min: 0, Max: 10, Weight: 0.20},
		{Min: 10, Max: 100, Weight: 0.30},
		{Min: 100, Max: 500, Weight: 0.30},
		{Min: 500, Max: 2000, Weight: 0.20},
	},
	BurstSize: []Bucket{
		{Min: 1, Max: 4, Weight: 0.40},
		{Min: 4, Max: 10, Weight: 0.40},
		{Min: 10, Max: 20, Weight: 0.20},
	},
	IdleGapMs: []Bucket{
		{Min: 2000, Max: 10000, Weight: 0.45},
		{Min: 10000, Max: 60000, Weight: 0.40},
		{Min: 60000, Max: 300000, Weight: 0.15},
	},
	CoverQueryRate:   0.20,
	LabelEntropyMode: "padded",
}

// ProfileHighStealth is the throughput-killing, maximum-stealth profile.
// Uses n-gram label shaping (Phase 3), cover-heavy, very human-like timing.
// Switch to this only when active filtering is detected.
var ProfileHighStealth = Profile{
	Name:        "high_stealth",
	Description: "Maximum stealth: n-gram labels, heavy cover, human timing (low throughput)",
	RecordTypeWeights: map[uint16]float64{
		1:  0.55,
		28: 0.30,
		16: 0.08,
		65: 0.04,
		5:  0.03,
	},
	QueryIntervalMs: []Bucket{
		{Min: 50, Max: 200, Weight: 0.35},
		{Min: 200, Max: 800, Weight: 0.35},
		{Min: 800, Max: 3000, Weight: 0.20},
		{Min: 3000, Max: 8000, Weight: 0.10},
	},
	BurstSize: []Bucket{
		{Min: 1, Max: 2, Weight: 0.65},
		{Min: 2, Max: 4, Weight: 0.30},
		{Min: 4, Max: 6, Weight: 0.05},
	},
	IdleGapMs: []Bucket{
		{Min: 5000, Max: 20000, Weight: 0.40},
		{Min: 20000, Max: 120000, Weight: 0.40},
		{Min: 120000, Max: 600000, Weight: 0.20},
	},
	CoverQueryRate:   0.40,
	LabelEntropyMode: "ngram", // word-like Markov labels (see labels.go)
}

// BuiltinProfiles is the map of name → profile for all bundled profiles.
var BuiltinProfiles = map[string]*Profile{
	"standard_dns": &ProfileStandardDNS,
	"doh_mix":      &ProfileDoHMix,
	"high_stealth": &ProfileHighStealth,
}

// LoadProfile reads a profile from a JSON file. Falls back to ProfileStandardDNS
// if the file cannot be read or parsed.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ── Sampler ───────────────────────────────────────────────────────────────────

// Sampler provides stateful sampling from a Profile, including record type
// rotation and timing decisions. Create one per session.
type Sampler struct {
	profile *Profile
	rng     *rand.Rand

	// weightedTypes holds the expanded type distribution for efficient sampling.
	typeSlots []RecordType
}

// NewSampler creates a Sampler for the given profile.
func NewSampler(p *Profile) *Sampler {
	s := &Sampler{
		profile: p,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	s.buildTypeSlots()
	return s
}

// buildTypeSlots constructs a 1000-slot lookup table for O(1) weighted type sampling.
func (s *Sampler) buildTypeSlots() {
	const slots = 1000
	s.typeSlots = make([]RecordType, 0, slots)
	for typeVal, weight := range s.profile.RecordTypeWeights {
		count := int(weight * float64(slots))
		for i := 0; i < count; i++ {
			s.typeSlots = append(s.typeSlots, RecordType(typeVal))
		}
	}
	// Fill any remaining slots (rounding) with A records.
	for len(s.typeSlots) < slots {
		s.typeSlots = append(s.typeSlots, TypeA)
	}
	// Shuffle to avoid clustering.
	s.rng.Shuffle(len(s.typeSlots), func(i, j int) {
		s.typeSlots[i], s.typeSlots[j] = s.typeSlots[j], s.typeSlots[i]
	})
}

// NextQueryType samples a record type from the profile distribution.
// For queries that need to carry real payload, if the sampled type is
// cover-only and payloadRequired is true, the next non-cover-only type
// is returned instead.
func (s *Sampler) NextQueryType(payloadRequired bool) RecordType {
	idx := s.rng.Intn(len(s.typeSlots))
	t := s.typeSlots[idx]
	if payloadRequired && t.IsCoverOnly() {
		// Fall back to TXT which has the highest upstream capacity.
		return TypeTXT
	}
	return t
}

// NextQueryInterval samples the inter-query delay from the profile.
func (s *Sampler) NextQueryInterval() time.Duration {
	ms := sampleBuckets(s.rng, s.profile.QueryIntervalMs)
	return time.Duration(ms * float64(time.Millisecond))
}

// NextBurstSize samples how many queries to send in the current burst.
func (s *Sampler) NextBurstSize() int {
	n := int(sampleBuckets(s.rng, s.profile.BurstSize))
	if n < 1 {
		n = 1
	}
	return n
}

// NextIdleGap samples the idle gap between bursts.
func (s *Sampler) NextIdleGap() time.Duration {
	ms := sampleBuckets(s.rng, s.profile.IdleGapMs)
	return time.Duration(ms * float64(time.Millisecond))
}

// IsCoverQuery returns true if this query slot should be a cover (non-payload) query.
func (s *Sampler) IsCoverQuery() bool {
	return s.rng.Float64() < s.profile.CoverQueryRate
}

// LabelEntropyMode returns the active label encoding strategy ("raw", "padded",
// or "ngram"). An unset mode defaults to "raw". The returned name is accepted
// directly by CodecFor.
func (s *Sampler) LabelEntropyMode() string {
	if s.profile.LabelEntropyMode == "" {
		return "raw"
	}
	return s.profile.LabelEntropyMode
}

// ── helpers ───────────────────────────────────────────────────────────────────

// sampleBuckets performs weighted bucket sampling. Returns a value uniformly
// sampled from the selected bucket.
func sampleBuckets(rng *rand.Rand, buckets []Bucket) float64 {
	if len(buckets) == 0 {
		return 0
	}
	// Compute total weight.
	var total float64
	for _, b := range buckets {
		total += b.Weight
	}
	if total <= 0 {
		return buckets[0].Sample(rng)
	}

	roll := rng.Float64() * total
	var cum float64
	for _, b := range buckets {
		cum += b.Weight
		if roll < cum {
			return b.Sample(rng)
		}
	}
	// Shouldn't reach here; return last bucket.
	return buckets[len(buckets)-1].Sample(rng)
}
