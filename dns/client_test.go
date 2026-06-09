package dns

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// fastProfile is an aggressive profile so timing-driven tests finish quickly.
func fastProfile(mode string, coverRate float64) *Profile {
	return &Profile{
		Name:              "test_fast",
		RecordTypeWeights: map[uint16]float64{16: 1.0}, // TXT only
		QueryIntervalMs:   []Bucket{{Min: 0, Max: 1, Weight: 1.0}},
		BurstSize:         []Bucket{{Min: 4, Max: 4, Weight: 1.0}},
		IdleGapMs:         []Bucket{{Min: 1, Max: 2, Weight: 1.0}},
		CoverQueryRate:    coverRate,
		LabelEntropyMode:  mode,
	}
}

// nonBlockingSink returns a transmit func that never blocks (drops when full).
func nonBlockingSink(ch chan Query) func(Query) error {
	return func(q Query) error {
		select {
		case ch <- q:
		default:
		}
		return nil
	}
}

// TestClientDeliversPayloadEndToEnd sends a datagram through the full path and
// confirms a non-cover query is emitted whose FQDN decodes back to the original
// datagram and session ID.
func TestClientDeliversPayloadEndToEnd(t *testing.T) {
	const zone = "v.example.com"
	ctrl := NewAdaptiveController(DefaultAdaptiveConfig())
	ctrl.SetProfile(LevelStandard, fastProfile("raw", 0.0)) // no cover, raw so we can decode

	got := make(chan Query, 256)
	c := NewClient(ClientConfig{
		SessionID:  0x1234,
		Zone:       zone,
		Controller: ctrl,
		Transmit:   nonBlockingSink(got),
	})

	datagram := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	if !c.Send(datagram) {
		t.Fatal("Send returned false")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case q := <-got:
			if q.IsCover {
				continue
			}
			payload, sid, err := DecodeFQDNMode(q.FQDN, zone, "raw")
			if err != nil {
				t.Fatalf("decode payload query: %v", err)
			}
			if sid != 0x1234 {
				t.Fatalf("session id: got %x want 1234", sid)
			}
			if !bytes.Equal(payload, datagram) {
				t.Fatalf("payload mismatch: got %x want %x", payload, datagram)
			}
			if q.Type != TypeTXT {
				t.Errorf("payload record type: got %v want TXT", q.Type)
			}
			return // success
		case <-deadline:
			t.Fatal("no payload query observed within deadline")
		}
	}
}

// TestClientEmitsCoverWhenIdle verifies that with nothing queued every emitted
// query is cover.
func TestClientEmitsCoverWhenIdle(t *testing.T) {
	ctrl := NewAdaptiveController(DefaultAdaptiveConfig())
	ctrl.SetProfile(LevelStandard, fastProfile("ngram", 0.0))

	got := make(chan Query, 256)
	c := NewClient(ClientConfig{
		SessionID:  0x0001,
		Zone:       "v.example.com",
		Controller: ctrl,
		Transmit:   nonBlockingSink(got),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	deadline := time.After(2 * time.Second)
	seen := 0
	for seen < 5 {
		select {
		case q := <-got:
			if !q.IsCover {
				t.Fatalf("expected cover query while idle, got payload: %s", q.FQDN)
			}
			seen++
		case <-deadline:
			t.Fatalf("expected >=5 cover queries, saw %d", seen)
		}
	}
}

// TestClientAdaptationSwapsProfile checks that feeding adverse conditions moves
// the client (and its scheduler) to the high-stealth profile, and that recovery
// is hysteretic.
func TestClientAdaptationSwapsProfile(t *testing.T) {
	cfg := DefaultAdaptiveConfig()
	cfg.DowngradeRuns = 2
	c := NewClient(ClientConfig{
		SessionID:  0x0001,
		Zone:       "v.example.com",
		Controller: NewAdaptiveController(cfg),
	})

	if st := c.Stats(); st.Level != "standard" {
		t.Fatalf("initial level: got %q want standard", st.Level)
	}

	c.UpdateConditions(Conditions{Blackout: true})
	st := c.Stats()
	if st.Level != "max" || st.Profile != "high_stealth" {
		t.Errorf("after blackout: level=%q profile=%q want max/high_stealth", st.Level, st.Profile)
	}

	// One good sample is not enough to relax (DowngradeRuns=2).
	c.UpdateConditions(Conditions{})
	if st := c.Stats(); st.Level != "max" {
		t.Errorf("after 1 good sample: got %q want still max", st.Level)
	}
	// Second good sample steps down one level.
	c.UpdateConditions(Conditions{})
	if st := c.Stats(); st.Level != "elevated" {
		t.Errorf("after 2 good samples: got %q want elevated", st.Level)
	}
}

// TestClientQueueBound confirms the queue is bounded and overflow is counted.
func TestClientQueueBound(t *testing.T) {
	c := NewClient(ClientConfig{MaxQueue: 2})
	if !c.Send([]byte{1}) || !c.Send([]byte{2}) {
		t.Fatal("first two sends should succeed")
	}
	if c.Send([]byte{3}) {
		t.Error("third send should be dropped (queue full)")
	}
	if st := c.Stats(); st.Dropped != 1 || st.Queued != 2 {
		t.Errorf("stats: dropped=%d queued=%d want 1/2", st.Dropped, st.Queued)
	}
}

// TestClientSendCopiesBuffer ensures Send does not retain the caller's slice.
func TestClientSendCopiesBuffer(t *testing.T) {
	c := NewClient(ClientConfig{MaxQueue: 4})
	buf := []byte{1, 2, 3}
	c.Send(buf)
	buf[0] = 0xff // mutate after Send
	got := c.dequeue()
	if got == nil || got[0] != 1 {
		t.Errorf("Send did not copy buffer: got %v", got)
	}
}
