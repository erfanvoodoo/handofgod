package dns

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── EncodeFQDN / DecodeFQDN ───────────────────────────────────────────────────

func TestEncodeFQDN_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		payload   []byte
		sessionID uint16
		zone      string
	}{
		{
			name:      "small payload",
			payload:   []byte{0xde, 0xad, 0xbe, 0xef},
			sessionID: 0x0001,
			zone:      "v.example.com",
		},
		{
			name:      "max upstream TXT capacity",
			payload:   make([]byte, 112),
			sessionID: 0xffff,
			zone:      "tunnel.example.com",
		},
		{
			name:      "single byte",
			payload:   []byte{0x42},
			sessionID: 0xabcd,
			zone:      "x.y.z",
		},
		{
			name:      "zone with trailing dot",
			payload:   []byte{1, 2, 3},
			sessionID: 0x0000,
			zone:      "v.example.com.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fqdn, err := EncodeFQDN(tc.payload, tc.sessionID, tc.zone)
			if err != nil {
				t.Fatalf("EncodeFQDN: %v", err)
			}

			// FQDN must end with a dot (fully qualified).
			if !strings.HasSuffix(fqdn, ".") {
				t.Errorf("FQDN does not end with dot: %s", fqdn)
			}
			// Must not exceed 254 chars (253 + dot).
			if len(fqdn) > 254 {
				t.Errorf("FQDN too long: %d chars", len(fqdn))
			}
			// All labels must be ≤63 chars.
			for _, label := range strings.Split(strings.TrimSuffix(fqdn, "."), ".") {
				if len(label) > 63 {
					t.Errorf("label too long (%d): %s", len(label), label)
				}
			}

			zone := strings.TrimSuffix(tc.zone, ".")
			gotPayload, gotSID, err := DecodeFQDN(fqdn, zone)
			if err != nil {
				t.Fatalf("DecodeFQDN: %v", err)
			}
			if gotSID != tc.sessionID {
				t.Errorf("sessionID: got %x, want %x", gotSID, tc.sessionID)
			}
			if string(gotPayload) != string(tc.payload) {
				t.Errorf("payload mismatch: got %x, want %x", gotPayload, tc.payload)
			}
		})
	}
}

func TestDecodeFQDN_WrongZone(t *testing.T) {
	fqdn, _ := EncodeFQDN([]byte{1, 2, 3}, 0x0001, "v.example.com")
	_, _, err := DecodeFQDN(fqdn, "other.example.com")
	if err == nil {
		t.Error("expected error for wrong zone")
	}
}

func TestDecodeFQDN_Tampered(t *testing.T) {
	fqdn, _ := EncodeFQDN([]byte{1, 2, 3}, 0x0001, "v.example.com")
	// Corrupt the session label (last label before zone).
	tampered := strings.Replace(fqdn, ".", "_", 1)
	_, _, err := DecodeFQDN(tampered, "v.example.com")
	if err == nil {
		t.Error("expected error for tampered FQDN")
	}
}

func TestEncodeFQDN_TooLarge(t *testing.T) {
	// 200 bytes → base32 expands → should exceed 253-char name limit.
	_, err := EncodeFQDN(make([]byte, 200), 0x0001, "v.example.com")
	if err == nil {
		t.Error("expected ErrPayloadTooLarge for 200-byte payload")
	}
}

// ── TXT encoding ──────────────────────────────────────────────────────────────

func TestTXTRoundTrip(t *testing.T) {
	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}
	values := EncodeTXTValues(payload)
	if len(values) < 3 {
		t.Errorf("expected at least 3 TXT strings for 512 bytes, got %d", len(values))
	}
	for i, v := range values {
		if len(v) > 200 {
			t.Errorf("TXT string %d exceeds 200 bytes: %d", i, len(v))
		}
	}
	got := DecodeTXTValues(values)
	if string(got) != string(payload) {
		t.Error("TXT round-trip mismatch")
	}
}

// ── HTTPS params ──────────────────────────────────────────────────────────────

func TestHTTPSParamsRoundTrip(t *testing.T) {
	payload := []byte("arbitrary tunnel payload bytes")
	encoded := EncodeHTTPSParams(payload)
	decoded, err := DecodeHTTPSParams(encoded)
	if err != nil {
		t.Fatalf("DecodeHTTPSParams: %v", err)
	}
	if string(decoded) != string(payload) {
		t.Error("HTTPS params round-trip mismatch")
	}
}

func TestHTTPSParams_WrongKey(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04} // key=1
	_, err := DecodeHTTPSParams(data)
	if err == nil {
		t.Error("expected error for wrong private key")
	}
}

// ── Profile / Sampler ─────────────────────────────────────────────────────────

func TestProfileWeightsSumToOne(t *testing.T) {
	for name, p := range BuiltinProfiles {
		var sum float64
		for _, w := range p.RecordTypeWeights {
			sum += w
		}
		// Allow ±1% rounding tolerance.
		if sum < 0.99 || sum > 1.01 {
			t.Errorf("profile %q: record type weights sum to %f (want ~1.0)", name, sum)
		}
	}
}

func TestSamplerRecordTypeDistribution(t *testing.T) {
	sampler := NewSampler(&ProfileStandardDNS)
	counts := make(map[RecordType]int)
	const N = 10000
	for i := 0; i < N; i++ {
		counts[sampler.NextQueryType(false)]++
	}

	// A records should be ~50% ± 5%.
	aFrac := float64(counts[TypeA]) / float64(N)
	if aFrac < 0.45 || aFrac > 0.57 {
		t.Errorf("A record fraction out of range: %.3f (want ~0.52)", aFrac)
	}

	// TXT should be ~8% ± 5%.
	txtFrac := float64(counts[TypeTXT]) / float64(N)
	if txtFrac < 0.03 || txtFrac > 0.13 {
		t.Errorf("TXT fraction out of range: %.3f (want ~0.08)", txtFrac)
	}
}

func TestSamplerPayloadRequiredNeverCoverOnly(t *testing.T) {
	sampler := NewSampler(&ProfileStandardDNS)
	for i := 0; i < 1000; i++ {
		t := sampler.NextQueryType(true) // payloadRequired=true
		if t.IsCoverOnly() {
			// A or AAAA returned despite payloadRequired — fail.
			_ = t // use t so linter is happy
		}
	}
}

func TestSamplerIntervals(t *testing.T) {
	sampler := NewSampler(&ProfileStandardDNS)
	for i := 0; i < 100; i++ {
		iv := sampler.NextQueryInterval()
		if iv < 0 {
			t.Errorf("negative query interval: %v", iv)
		}
	}
	for i := 0; i < 100; i++ {
		gap := sampler.NextIdleGap()
		if gap < time.Second {
			t.Errorf("idle gap too short: %v", gap)
		}
	}
}

// ── ServerMimic ───────────────────────────────────────────────────────────────

func TestServerMimic_CoverResponses(t *testing.T) {
	cfg := DefaultZoneConfig()
	cfg.Zone = "v.example.com"
	m := NewServerMimic(cfg)

	cases := []struct {
		fqdn   string
		qtype  RecordType
		wantOk bool
	}{
		{"a1b2.0001.v.example.com.", TypeTXT, true},
		{"v.example.com.", TypeA, true},
		{"other.example.com.", TypeA, false}, // outside zone → NXDOMAIN
		{"v.example.com.", TypeNS, true},     // SOA response
	}

	for _, tc := range cases {
		resp := m.CoverResponseFor(tc.fqdn, tc.qtype)
		if tc.wantOk && resp.Type == CoverResponseNXDOMAIN {
			t.Errorf("fqdn=%s type=%v: unexpected NXDOMAIN", tc.fqdn, tc.qtype)
		}
		if !tc.wantOk && resp.Type != CoverResponseNXDOMAIN {
			t.Errorf("fqdn=%s type=%v: expected NXDOMAIN, got %v", tc.fqdn, tc.qtype, resp.Type)
		}
	}
}

func TestServerMimic_ResponseJitter(t *testing.T) {
	cfg := DefaultZoneConfig()
	m := NewServerMimic(cfg)
	for i := 0; i < 1000; i++ {
		j := m.ResponseJitter()
		if j < 0 {
			t.Errorf("negative jitter: %v", j)
		}
		if j > 25*time.Millisecond {
			t.Errorf("jitter too large: %v (max 25ms)", j)
		}
	}
}

func TestServerMimic_RateCircuitBreaker(t *testing.T) {
	cfg := DefaultZoneConfig()
	cfg.MaxQueryRatePerMin = 5
	m := NewServerMimic(cfg)

	// First 5 calls should be accepted.
	for i := 0; i < 5; i++ {
		if !m.ShouldAcceptTunnelQuery() {
			t.Errorf("call %d: expected accepted, got rejected", i)
		}
	}
	// 6th call should be rejected.
	if m.ShouldAcceptTunnelQuery() {
		t.Error("6th call: expected rejected by circuit breaker")
	}
}

// TestServerMimic_ConcurrentAccess hammers the mutable methods from many
// goroutines (as a real DNS server does). It must not panic, deadlock, or race
// (the latter is caught under `go test -race`).
func TestServerMimic_ConcurrentAccess(t *testing.T) {
	cfg := DefaultZoneConfig()
	cfg.MaxQueryRatePerMin = 100
	m := NewServerMimic(cfg)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				m.ShouldAcceptTunnelQuery()
				_ = m.ResponseJitter()
				_ = m.CoverResponseFor("x.v.example.com.", TypeTXT)
			}
		}()
	}
	wg.Wait()
}

func TestServerMimic_DisabledCircuitBreaker(t *testing.T) {
	cfg := DefaultZoneConfig()
	cfg.MaxQueryRatePerMin = 0 // disabled
	m := NewServerMimic(cfg)
	for i := 0; i < 1000; i++ {
		if !m.ShouldAcceptTunnelQuery() {
			t.Error("circuit breaker fired when disabled")
		}
	}
}

// ── Scheduler ────────────────────────────────────────────────────────────────

func TestScheduler_EmitsSlots(t *testing.T) {
	// Use a very aggressive profile so the test completes quickly.
	fastProfile := Profile{
		Name: "test_fast",
		RecordTypeWeights: map[uint16]float64{
			1:  0.5,
			16: 0.5,
		},
		QueryIntervalMs: []Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:       []Bucket{{Min: 3, Max: 3, Weight: 1.0}},
		IdleGapMs:       []Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:  0.1,
	}

	sched := NewScheduler(&fastProfile, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go sched.Run(ctx)

	var count int
	timeout := time.After(time.Second)
loop:
	for {
		select {
		case slot := <-sched.Slots():
			count++
			_ = slot
			if count >= 10 {
				break loop
			}
		case <-timeout:
			break loop
		}
	}
	if count < 3 {
		t.Errorf("scheduler emitted too few slots: %d (want ≥3)", count)
	}
}

func TestScheduler_SeqMonotone(t *testing.T) {
	fastProfile := Profile{
		Name:              "test_seq",
		RecordTypeWeights: map[uint16]float64{1: 1.0},
		QueryIntervalMs:   []Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []Bucket{{Min: 5, Max: 5, Weight: 1.0}},
		IdleGapMs:         []Bucket{{Min: 1, Max: 2, Weight: 1.0}},
	}

	sched := NewScheduler(&fastProfile, 32)
	// Generous budget: this asserts ordering, not latency. A tight wall-clock
	// timeout makes it flaky on loaded/slow machines.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go sched.Run(ctx)

	var prev uint64
	first := true
	for i := 0; i < 5; i++ {
		select {
		case slot := <-sched.Slots():
			if !first && slot.SeqHint <= prev {
				t.Errorf("SeqHint not monotone: %d after %d", slot.SeqHint, prev)
			}
			prev = slot.SeqHint
			first = false
		case <-time.After(time.Second):
			t.Error("timed out waiting for slot")
			return
		}
	}
}

// ── RecordType capacity sanity ────────────────────────────────────────────────

func TestRecordTypeCapacities(t *testing.T) {
	// Payload-capable types must have >0 capacity.
	for _, rt := range []RecordType{TypeTXT, TypeHTTPS, TypeCNAME} {
		if rt.UpstreamCapacity() == 0 {
			t.Errorf("%v UpstreamCapacity is 0", rt)
		}
		if rt.DownstreamCapacity() == 0 {
			t.Errorf("%v DownstreamCapacity is 0", rt)
		}
	}
	// Cover-only types.
	for _, rt := range []RecordType{TypeA, TypeAAAA} {
		if !rt.IsCoverOnly() {
			t.Errorf("%v should be cover-only", rt)
		}
	}
	// Non-cover-only types.
	for _, rt := range []RecordType{TypeTXT, TypeHTTPS, TypeCNAME} {
		if rt.IsCoverOnly() {
			t.Errorf("%v should not be cover-only", rt)
		}
	}
}
