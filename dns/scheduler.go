package dns

import (
	"context"
	"sync"
	"time"
)

// Scheduler drives the query timing loop according to a Profile's burst+idle
// model. It is the DNS equivalent of ShapeCraft's inter-packet interval engine.
//
// The scheduler operates in cycles:
//   1. Determine burst size N from the profile.
//   2. Issue N send slots with intra-burst inter-query delays.
//   3. Sleep for an idle gap sampled from the profile.
//   4. Repeat.
//
// Each send slot carries a SendSlot describing whether to send payload or cover.
// The caller decides what bytes go into each slot; the scheduler only controls
// when the slot fires.

// SendSlot is emitted by the Scheduler on its channel for each query opportunity.
type SendSlot struct {
	// IsCover is true when the scheduler requests a cover (non-payload) query.
	// The caller should send a randomly-chosen cover query if no payload is queued.
	IsCover bool
	// SuggestedType is the record type sampled from the profile distribution.
	SuggestedType RecordType
	// EntropyMode is the active label-entropy mode for this slot ("raw",
	// "padded", "ngram"); the caller passes it to EncodeFQDNMode.
	EntropyMode string
	// SeqHint is a monotone counter the scheduler increments per slot.
	SeqHint uint64
}

// Scheduler drives send slots at profile-shaped timing. Its active profile can
// be swapped at runtime via SetProfile (e.g. by an AdaptiveController); the swap
// takes effect at the next burst boundary. Safe for concurrent use.
type Scheduler struct {
	mu      sync.Mutex
	sampler *Sampler
	ch      chan SendSlot
	seq     uint64
}

// NewScheduler creates a Scheduler for the given profile.
// bufSize is the channel buffer; 16 is a reasonable default.
func NewScheduler(p *Profile, bufSize int) *Scheduler {
	if bufSize < 1 {
		bufSize = 16
	}
	return &Scheduler{
		sampler: NewSampler(p),
		ch:      make(chan SendSlot, bufSize),
	}
}

// SetProfile swaps the profile driving the scheduler. It rebuilds the sampler
// only when the profile actually changes, so it is cheap to call on every
// conditions update. The new profile takes effect at the next burst.
func (s *Scheduler) SetProfile(p *Profile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sampler != nil && s.sampler.profile == p {
		return
	}
	s.sampler = NewSampler(p)
}

// currentSampler returns the active sampler under lock. Only the Run goroutine
// calls the returned sampler's (non-thread-safe) Next* methods, and SetProfile
// only ever replaces the pointer, so a single sampler is never used concurrently.
func (s *Scheduler) currentSampler() *Sampler {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sampler
}

// Slots returns the channel on which send slots are emitted.
// The caller reads from this channel and sends a query for each slot.
func (s *Scheduler) Slots() <-chan SendSlot {
	return s.ch
}

// Run starts the scheduling loop. It returns when ctx is cancelled.
// Run should be called in a goroutine.
func (s *Scheduler) Run(ctx context.Context) {
	for {
		// Snapshot the active sampler for this burst so a mid-burst profile swap
		// doesn't change shape partway through.
		smp := s.currentSampler()

		// 1. Sample burst size.
		burstN := smp.NextBurstSize()

		// 2. Emit burst slots with intra-burst delays.
		for i := 0; i < burstN; i++ {
			if ctx.Err() != nil {
				return
			}

			isCover := smp.IsCoverQuery()
			qtype := smp.NextQueryType(!isCover)

			slot := SendSlot{
				IsCover:       isCover,
				SuggestedType: qtype,
				EntropyMode:   smp.LabelEntropyMode(),
				SeqHint:       s.seq,
			}
			s.seq++

			select {
			case s.ch <- slot:
			case <-ctx.Done():
				return
			}

			// Intra-burst delay (only between burst items, not after last).
			if i < burstN-1 {
				delay := smp.NextQueryInterval()
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
		}

		// 3. Idle gap between bursts.
		idle := smp.NextIdleGap()
		select {
		case <-time.After(idle):
		case <-ctx.Done():
			return
		}
	}
}
