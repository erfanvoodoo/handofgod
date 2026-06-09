// Package arq implements Hand of God's reliability layer over an unreliable,
// reordering, duplicating substrate (DNS). See PROTOCOL.md §6.
//
// Sender: sliding window of unacked frames, RFC 6298 adaptive RTO,
// exponential backoff retransmission, SACK-driven gap filling.
//
// Receiver: reorder buffer, duplicate suppression (critical for multi-path
// duplication safety), in-order delivery, cumulative + selective ACK generation.
package arq

import (
	"sort"
	"sync"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/frame"
)

// ── Adaptive RTO (RFC 6298) ──────────────────────────────────────────────────

// RTOEstimator computes the retransmission timeout from RTT samples.
type RTOEstimator struct {
	srtt   time.Duration
	rttvar time.Duration
	min    time.Duration
	max    time.Duration
	seeded bool
}

// NewRTOEstimator creates an estimator with the given bounds.
func NewRTOEstimator(min, max time.Duration) *RTOEstimator {
	return &RTOEstimator{min: min, max: max}
}

// Sample incorporates a new RTT measurement and returns the updated RTO.
func (e *RTOEstimator) Sample(rtt time.Duration) time.Duration {
	if !e.seeded {
		e.srtt = rtt
		e.rttvar = rtt / 2
		e.seeded = true
	} else {
		diff := e.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		// RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R|
		e.rttvar = (3*e.rttvar + diff) / 4
		// SRTT = 7/8 SRTT + 1/8 R
		e.srtt = (7*e.srtt + rtt) / 8
	}
	return e.RTO()
}

// RTO returns the current retransmission timeout, clamped to [min, max].
func (e *RTOEstimator) RTO() time.Duration {
	if !e.seeded {
		return e.min
	}
	rto := e.srtt + 4*e.rttvar
	if rto < e.min {
		return e.min
	}
	if rto > e.max {
		return e.max
	}
	return rto
}

// SRTT exposes the smoothed RTT (for metrics).
func (e *RTOEstimator) SRTT() time.Duration { return e.srtt }

// ── Sender ────────────────────────────────────────────────────────────────────

type unacked struct {
	seq         uint64
	frame       frame.Frame
	sentAt      time.Time
	retransmits int
}

// SenderStats reports sender-side reliability metrics.
type SenderStats struct {
	Sent          uint64
	Retransmitted uint64
	InFlight      int
}

// Sender manages the send window and retransmissions for one direction.
// Safe for concurrent use.
type Sender struct {
	mu           sync.Mutex
	window       int
	nextSeq      uint64 // reliable (ARQ-tracked) sequence space; stays contiguous
	nextUnrelSeq uint64 // unreliable sequence space (ACK/PING/PONG)
	buf          map[uint64]*unacked
	rto          *RTOEstimator
	stats        SenderStats
}

// NewSender creates a sender with the given window size and RTO bounds.
func NewSender(windowSize int, minRTO, maxRTO time.Duration) *Sender {
	return &Sender{
		window: windowSize,
		buf:    make(map[uint64]*unacked),
		rto:    NewRTOEstimator(minRTO, maxRTO),
	}
}

// CanSend reports whether the window has room for another frame.
func (s *Sender) CanSend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf) < s.window
}

// Next assigns the next sequence number to a reliable frame and tracks it.
// Returns the assigned seq. Caller transmits the frame on the chosen path(s).
func (s *Sender) Next(f frame.Frame) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.nextSeq
	s.nextSeq++
	s.buf[seq] = &unacked{seq: seq, frame: f, sentAt: time.Now()}
	s.stats.Sent++
	return seq
}

// NextUnreliableSeq allocates the next sequence number for an unreliable frame
// (ACK, PING/PONG, MTU, SESSION_CLOSE). It uses a separate counter tagged with
// crypto.SeqUnreliableBit: the high bit keeps AEAD nonces distinct from the
// reliable space (no nonce reuse), while leaving the reliable space contiguous so
// the receiver can deliver DATA in order without stalling on an interleaved
// unreliable seq. Unreliable frames are not buffered for retransmission.
func (s *Sender) NextUnreliableSeq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.nextUnrelSeq | crypto.SeqUnreliableBit
	s.nextUnrelSeq++
	return seq
}

// OnAck processes a received ACK, removing acknowledged frames and sampling RTT.
func (s *Sender) OnAck(ack frame.AckPayload, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acked := func(seq uint64) {
		if u, ok := s.buf[seq]; ok {
			// Only sample RTT from frames that were never retransmitted (Karn's algorithm)
			if u.retransmits == 0 {
				s.rto.Sample(now.Sub(u.sentAt))
			}
			delete(s.buf, seq)
		}
	}

	// Cumulative ack uses "next expected" semantics: everything strictly below
	// CumulativeAck has been received in order. CumulativeAck == 0 therefore
	// means "nothing received yet" and acknowledges nothing — crucial so that a
	// lost seq 0 is not falsely acked while later seqs arrive.
	for seq := range s.buf {
		if seq < ack.CumulativeAck {
			acked(seq)
		}
	}
	// Selective ranges
	for _, r := range ack.Ranges {
		for seq := r.Start; seq <= r.End; seq++ {
			acked(seq)
		}
	}
}

// DueForRetransmit returns frames whose RTO has expired, marking them retransmitted
// with exponential backoff. Caller re-sends the returned frames.
func (s *Sender) DueForRetransmit(now time.Time) []RetransmitItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	baseRTO := s.rto.RTO()
	var due []RetransmitItem
	for _, u := range s.buf {
		// Exponential backoff: effective RTO doubles per prior retransmit, capped.
		// Cap the shift to 20 to prevent int64 overflow (2^20 * MinRTO >> MaxRTO).
		backoff := u.retransmits
		if backoff > 20 {
			backoff = 20
		}
		effective := baseRTO << uint(backoff)
		if effective > s.rto.max {
			effective = s.rto.max
		}
		if now.Sub(u.sentAt) >= effective {
			u.sentAt = now
			u.retransmits++
			s.stats.Retransmitted++
			due = append(due, RetransmitItem{Seq: u.seq, Frame: u.frame})
		}
	}
	// Deterministic order helps testing and fairness
	sort.Slice(due, func(i, j int) bool { return due[i].Seq < due[j].Seq })
	return due
}

// RetransmitItem is a frame that needs re-sending.
type RetransmitItem struct {
	Seq   uint64
	Frame frame.Frame
}

// Stats returns a snapshot of sender statistics.
func (s *Sender) Stats() SenderStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.InFlight = len(s.buf)
	return st
}

// CurrentRTO returns the current retransmission timeout (for metrics/tuning).
func (s *Sender) CurrentRTO() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rto.RTO()
}

// ── Receiver ────────────────────────────────────────────────────────────────

// ReceiverStats reports receiver-side reliability metrics.
type ReceiverStats struct {
	Delivered  uint64
	Duplicates uint64 // dropped duplicate frames (multi-path copies + retransmits)
	Buffered   int
}

// Receiver reorders, deduplicates, and delivers frames in order.
// Safe for concurrent use.
type Receiver struct {
	mu          sync.Mutex
	nextDeliver uint64 // next seq expected for in-order delivery
	buffer      map[uint64]frame.Frame
	highestSeen uint64
	stats       ReceiverStats
}

// NewReceiver creates a receiver starting at sequence 0.
func NewReceiver() *Receiver {
	return &Receiver{
		buffer: make(map[uint64]frame.Frame),
	}
}

// Accept ingests a received frame at seq. Returns any frames now deliverable
// in order (possibly empty). Duplicates are silently dropped.
//
// This is where multi-path duplication is made safe: the same seq arriving via
// multiple resolver paths is delivered exactly once.
func (r *Receiver) Accept(seq uint64, f frame.Frame) []frame.Frame {
	r.mu.Lock()
	defer r.mu.Unlock()

	if seq > r.highestSeen {
		r.highestSeen = seq
	}

	// Duplicate suppression: seq < nextDeliver means already delivered;
	// seq already in buffer means a duplicate multi-path copy arrived.
	if seq < r.nextDeliver {
		r.stats.Duplicates++
		return nil
	}
	if _, buffered := r.buffer[seq]; buffered {
		r.stats.Duplicates++
		return nil
	}

	r.buffer[seq] = f

	// Drain contiguous in-order run
	var out []frame.Frame
	for {
		f, ok := r.buffer[r.nextDeliver]
		if !ok {
			break
		}
		out = append(out, f)
		delete(r.buffer, r.nextDeliver)
		r.stats.Delivered++
		r.nextDeliver++
	}

	return out
}

// BuildAck constructs the current cumulative + selective acknowledgment.
func (r *Receiver) BuildAck() frame.AckPayload {
	r.mu.Lock()
	defer r.mu.Unlock()

	ack := frame.AckPayload{}
	// Cumulative ack uses "next expected" semantics: it is the lowest seq not yet
	// delivered in order, i.e. the peer has received everything strictly below it.
	// This makes 0 unambiguous ("nothing delivered yet") rather than colliding with
	// "seq 0 delivered", which would let the sender falsely ack a lost seq 0.
	ack.CumulativeAck = r.nextDeliver

	// Build SACK ranges from buffered (out-of-order) seqs.
	if len(r.buffer) > 0 {
		seqs := make([]uint64, 0, len(r.buffer))
		for s := range r.buffer {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

		start := seqs[0]
		prev := seqs[0]
		for _, s := range seqs[1:] {
			if s == prev+1 {
				prev = s
				continue
			}
			ack.Ranges = append(ack.Ranges, frame.SackRange{Start: start, End: prev})
			start = s
			prev = s
		}
		ack.Ranges = append(ack.Ranges, frame.SackRange{Start: start, End: prev})
	}

	return ack
}

// Stats returns a snapshot of receiver statistics.
func (r *Receiver) Stats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stats
	st.Buffered = len(r.buffer)
	return st
}
