package crypto

// ReplayWindow implements a sliding-window replay detector over sequence numbers,
// modeled on the IPsec/DTLS anti-replay window (RFC 6347 §4.1.2.6).
//
// It accepts each sequence number at most once. Sequence numbers far below the
// current window are rejected as replays; numbers within or ahead of the window
// are accepted and recorded.
//
// Not safe for concurrent use; callers serialize per-direction Open calls.
type ReplayWindow struct {
	size    uint64
	bitmap  []uint64 // bit i (across words) tracks (highest - i)
	highest uint64
	seen    bool
}

// NewReplayWindow creates a window tracking the given number of sequence numbers.
func NewReplayWindow(size uint64) *ReplayWindow {
	if size < 64 {
		size = 64
	}
	words := (size + 63) / 64
	return &ReplayWindow{
		size:   words * 64,
		bitmap: make([]uint64, words),
	}
}

// IsFresh returns true if seq has not yet been seen and is within/ahead of the
// window, without recording it. Use this to check before the AEAD operation;
// call Accept after successful authentication to commit the sequence.
func (w *ReplayWindow) IsFresh(seq uint64) bool {
	if !w.seen {
		return true
	}
	if seq > w.highest {
		return true
	}
	diff := w.highest - seq
	if diff >= w.size {
		return false
	}
	return !w.get(diff)
}

// Accept records seq as seen and returns true if it was fresh (not a replay).
// Returns false for replays or too-old sequences.
func (w *ReplayWindow) Accept(seq uint64) bool {
	if !w.seen {
		w.seen = true
		w.highest = seq
		w.set(0)
		return true
	}

	if seq > w.highest {
		// Advance the window forward by (seq - highest).
		shift := seq - w.highest
		w.shiftLeft(shift)
		w.highest = seq
		w.set(0)
		return true
	}

	// seq <= highest: how far back?
	diff := w.highest - seq
	if diff >= w.size {
		return false // too old — outside the window, treat as replay
	}
	if w.get(diff) {
		return false // already seen
	}
	w.set(diff)
	return true
}

// bit position `pos` means sequence (highest - pos).
func (w *ReplayWindow) get(pos uint64) bool {
	word := pos / 64
	bit := pos % 64
	if word >= uint64(len(w.bitmap)) {
		return false
	}
	return w.bitmap[word]&(1<<bit) != 0
}

func (w *ReplayWindow) set(pos uint64) {
	word := pos / 64
	bit := pos % 64
	if word >= uint64(len(w.bitmap)) {
		return
	}
	w.bitmap[word] |= 1 << bit
}

// shiftLeft moves the window forward by n positions (new highest is more recent).
// Bits representing older sequences shift toward higher positions and fall off.
func (w *ReplayWindow) shiftLeft(n uint64) {
	if n >= w.size {
		// Entire window invalidated
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		return
	}
	wordShift := n / 64
	bitShift := n % 64

	if wordShift > 0 {
		for i := len(w.bitmap) - 1; i >= 0; i-- {
			if uint64(i) >= wordShift {
				w.bitmap[i] = w.bitmap[i-int(wordShift)]
			} else {
				w.bitmap[i] = 0
			}
		}
	}
	if bitShift > 0 {
		var carry uint64
		for i := 0; i < len(w.bitmap); i++ {
			newCarry := w.bitmap[i] >> (64 - bitShift)
			w.bitmap[i] = (w.bitmap[i] << bitShift) | carry
			carry = newCarry
		}
	}
}
