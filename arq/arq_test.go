package arq

import (
	"math/rand"
	"testing"
	"time"

	"github.com/handofgod/frame"
)

func dataFrame(n int) frame.Frame {
	return frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte{byte(n)}}
}

func TestReceiverInOrderDelivery(t *testing.T) {
	r := NewReceiver()
	var delivered []frame.Frame
	for seq := uint64(0); seq < 5; seq++ {
		delivered = append(delivered, r.Accept(seq, dataFrame(int(seq)))...)
	}
	if len(delivered) != 5 {
		t.Fatalf("delivered %d want 5", len(delivered))
	}
	for i, f := range delivered {
		if f.Payload[0] != byte(i) {
			t.Errorf("out of order at %d: got %d", i, f.Payload[0])
		}
	}
}

func TestReceiverReordering(t *testing.T) {
	r := NewReceiver()

	// Deliver out of order: 2, 0, 1, 4, 3
	if out := r.Accept(2, dataFrame(2)); len(out) != 0 {
		t.Fatal("seq 2 should buffer, not deliver")
	}
	if out := r.Accept(0, dataFrame(0)); len(out) != 1 || out[0].Payload[0] != 0 {
		t.Fatal("seq 0 should deliver immediately")
	}
	out := r.Accept(1, dataFrame(1))
	// Now 1 AND the buffered 2 should both flush
	if len(out) != 2 || out[0].Payload[0] != 1 || out[1].Payload[0] != 2 {
		t.Fatalf("seq 1 should flush 1,2; got %d frames", len(out))
	}
}

func TestReceiverDeduplication(t *testing.T) {
	r := NewReceiver()
	r.Accept(0, dataFrame(0))

	// Re-deliver seq 0 (simulates multi-path duplicate) — must be dropped
	if out := r.Accept(0, dataFrame(0)); len(out) != 0 {
		t.Fatal("duplicate seq 0 should be dropped")
	}
	// Duplicate of a buffered (out-of-order) seq
	r.Accept(5, dataFrame(5))
	if out := r.Accept(5, dataFrame(5)); len(out) != 0 {
		t.Fatal("duplicate buffered seq 5 should be dropped")
	}

	if r.Stats().Duplicates != 2 {
		t.Errorf("duplicate count: got %d want 2", r.Stats().Duplicates)
	}
}

func TestSenderRetransmit(t *testing.T) {
	s := NewSender(100, 50*time.Millisecond, time.Second)
	s.Next(dataFrame(0))
	s.Next(dataFrame(1))

	now := time.Now()
	// Nothing due immediately
	if due := s.DueForRetransmit(now); len(due) != 0 {
		t.Fatal("nothing should be due immediately")
	}
	// After RTO, both due
	later := now.Add(100 * time.Millisecond)
	due := s.DueForRetransmit(later)
	if len(due) != 2 {
		t.Fatalf("expected 2 due, got %d", len(due))
	}
	if s.Stats().Retransmitted != 2 {
		t.Errorf("retransmit count: got %d", s.Stats().Retransmitted)
	}
}

func TestSenderAckClearsWindow(t *testing.T) {
	s := NewSender(100, 50*time.Millisecond, time.Second)
	for i := 0; i < 5; i++ {
		s.Next(dataFrame(i))
	}
	if s.Stats().InFlight != 5 {
		t.Fatalf("in flight: got %d want 5", s.Stats().InFlight)
	}
	// Ack seqs 0,1,2 (next-expected == 3), plus SACK range 4-4
	s.OnAck(frame.AckPayload{
		CumulativeAck: 3,
		Ranges:        []frame.SackRange{{Start: 4, End: 4}},
	}, time.Now())

	// Seqs 0,1,2,4 acked → only seq 3 remains
	if s.Stats().InFlight != 1 {
		t.Errorf("in flight after ack: got %d want 1", s.Stats().InFlight)
	}
}

func TestReceiverBuildAck(t *testing.T) {
	r := NewReceiver()
	r.Accept(0, dataFrame(0))
	r.Accept(1, dataFrame(1))
	// Gap at 2, then 3,4 arrive out of order
	r.Accept(3, dataFrame(3))
	r.Accept(4, dataFrame(4))

	ack := r.BuildAck()
	// Next-expected semantics: 0 and 1 delivered, gap at 2 → CumulativeAck == 2.
	if ack.CumulativeAck != 2 {
		t.Errorf("cumulative ack: got %d want 2", ack.CumulativeAck)
	}
	if len(ack.Ranges) != 1 {
		t.Fatalf("ranges: got %d want 1", len(ack.Ranges))
	}
	if ack.Ranges[0].Start != 3 || ack.Ranges[0].End != 4 {
		t.Errorf("sack range: got %+v want {3,4}", ack.Ranges[0])
	}
}

// TestLostFirstFrameNotFalselyAcked is a regression test for the cumulative-ack
// ambiguity bug: when seq 0 is lost but later seqs arrive, the receiver must not
// produce an ACK that the sender reads as acknowledging seq 0. Otherwise seq 0 is
// dropped from the send buffer, never retransmitted, and the stream deadlocks.
func TestLostFirstFrameNotFalselyAcked(t *testing.T) {
	sender := NewSender(100, 50*time.Millisecond, time.Second)
	receiver := NewReceiver()

	f0, f1, f2 := dataFrame(0), dataFrame(1), dataFrame(2)
	seq0 := sender.Next(f0)
	seq1 := sender.Next(f1)
	seq2 := sender.Next(f2)

	// seq 0 is lost; 1 and 2 reach the receiver (buffered out of order).
	receiver.Accept(seq1, f1)
	receiver.Accept(seq2, f2)

	// The ACK reflects "nothing delivered in order yet" plus SACK for 1,2.
	ack := receiver.BuildAck()
	if ack.CumulativeAck != 0 {
		t.Fatalf("cumulative ack: got %d want 0 (nothing delivered in order)", ack.CumulativeAck)
	}
	sender.OnAck(ack, time.Now())

	// seq 0 must NOT have been acked — only 1 and 2 (via SACK) are gone.
	if st := sender.Stats(); st.InFlight != 1 {
		t.Fatalf("expected only seq 0 in flight, got InFlight=%d", st.InFlight)
	}

	// And seq 0 must become due for retransmission after the RTO.
	due := sender.DueForRetransmit(time.Now().Add(100 * time.Millisecond))
	if len(due) != 1 || due[0].Seq != seq0 {
		t.Fatalf("expected seq 0 to be retransmitted, got %+v", due)
	}
}

func TestRTOEstimator(t *testing.T) {
	e := NewRTOEstimator(100*time.Millisecond, 4*time.Second)
	// First sample seeds
	rto := e.Sample(200 * time.Millisecond)
	// RTO = SRTT + 4*RTTVAR = 200 + 4*100 = 600ms
	if rto < 500*time.Millisecond || rto > 700*time.Millisecond {
		t.Errorf("first RTO out of expected range: %v", rto)
	}
	// Converges toward steady state with consistent samples
	for i := 0; i < 50; i++ {
		e.Sample(200 * time.Millisecond)
	}
	if e.SRTT() < 180*time.Millisecond || e.SRTT() > 220*time.Millisecond {
		t.Errorf("SRTT did not converge to ~200ms: %v", e.SRTT())
	}
}

// TestLossySimulation runs a full sender↔receiver loop over a simulated lossy,
// reordering, duplicating channel and verifies all data is delivered in order.
func TestLossySimulation(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	sender := NewSender(1024, 20*time.Millisecond, 500*time.Millisecond)
	receiver := NewReceiver()

	const total = 2000
	// Queue all frames
	type wire struct {
		seq   uint64
		frame frame.Frame
	}
	var inFlight []wire

	send := func(seq uint64, f frame.Frame) {
		// 30% loss, plus duplication on some paths (multipath simulation)
		paths := 3
		for p := 0; p < paths; p++ {
			if rng.Float64() < 0.30 {
				continue // lost on this path
			}
			inFlight = append(inFlight, wire{seq, f})
		}
	}

	produced := 0
	now := time.Now()
	delivered := 0
	var lastPayloads []byte

	for delivered < total {
		// Produce new frames while window allows
		for produced < total && sender.CanSend() {
			f := frame.Frame{Type: frame.TypeData, StreamID: 1, Payload: []byte{byte(produced % 251)}}
			seq := sender.Next(f)
			send(seq, f)
			produced++
		}

		// Shuffle in-flight to simulate reordering
		rng.Shuffle(len(inFlight), func(i, j int) { inFlight[i], inFlight[j] = inFlight[j], inFlight[i] })

		// Deliver current in-flight to receiver
		batch := inFlight
		inFlight = nil
		for _, w := range batch {
			out := receiver.Accept(w.seq, w.frame)
			for _, f := range out {
				lastPayloads = append(lastPayloads, f.Payload[0])
				delivered++
			}
		}

		// Receiver acks; sender processes
		ack := receiver.BuildAck()
		sender.OnAck(ack, now)

		// Time advances; retransmit due frames
		now = now.Add(25 * time.Millisecond)
		for _, item := range sender.DueForRetransmit(now) {
			send(item.Seq, item.Frame)
		}
	}

	if delivered != total {
		t.Fatalf("delivered %d want %d", delivered, total)
	}
	// Verify in-order correctness
	for i := 0; i < total; i++ {
		if lastPayloads[i] != byte(i%251) {
			t.Fatalf("data corruption at %d: got %d want %d", i, lastPayloads[i], i%251)
		}
	}
	t.Logf("delivered %d frames over 30%%-loss 3-path channel; retransmits=%d duplicates=%d",
		total, sender.Stats().Retransmitted, receiver.Stats().Duplicates)
}
