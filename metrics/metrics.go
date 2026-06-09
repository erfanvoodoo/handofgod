// Package metrics provides Hand of God's observability layer.
//
// Per PROTOCOL.md and the design priority of "measure first", every reliability
// and path decision is observable. The headline metric is "stealth cost":
// goodput under a stealth profile divided by goodput in raw mode. This is what
// makes the bandwidth-vs-detectability tradeoff tunable with evidence rather
// than guesswork.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Collector aggregates Hand of God's runtime metrics. Safe for concurrent use.
type Collector struct {
	startTime time.Time

	// Byte counters (atomic)
	goodputBytes    uint64 // useful application bytes delivered
	wireBytes       uint64 // total bytes put on the wire (incl. retransmit/dup/overhead)
	retransmitBytes uint64 // bytes spent on retransmissions
	duplicateBytes  uint64 // bytes spent on multi-path duplication

	// Frame counters (atomic)
	framesSent          uint64
	framesRetransmitted uint64
	framesDuplicated    uint64
	framesDelivered     uint64
	framesDropped       uint64

	// Baseline goodput for stealth-cost calculation
	mu             sync.Mutex
	rawGoodputBps  float64 // measured goodput in raw (non-stealth) mode
	currentProfile string
}

// New creates a metrics collector.
func New() *Collector {
	return &Collector{startTime: time.Now()}
}

// AddGoodput records useful application bytes delivered to the peer application.
func (c *Collector) AddGoodput(n int) { atomic.AddUint64(&c.goodputBytes, uint64(n)) }

// AddWire records raw bytes transmitted on the wire.
func (c *Collector) AddWire(n int) { atomic.AddUint64(&c.wireBytes, uint64(n)) }

// AddRetransmit records bytes spent retransmitting.
func (c *Collector) AddRetransmit(n int) {
	atomic.AddUint64(&c.retransmitBytes, uint64(n))
	atomic.AddUint64(&c.framesRetransmitted, 1)
}

// AddDuplicate records bytes spent on multi-path duplicate copies.
func (c *Collector) AddDuplicate(n int) {
	atomic.AddUint64(&c.duplicateBytes, uint64(n))
	atomic.AddUint64(&c.framesDuplicated, 1)
}

// IncSent increments the sent-frame counter.
func (c *Collector) IncSent() { atomic.AddUint64(&c.framesSent, 1) }

// IncDelivered increments the delivered-frame counter.
func (c *Collector) IncDelivered() { atomic.AddUint64(&c.framesDelivered, 1) }

// IncDropped increments the dropped-frame counter.
func (c *Collector) IncDropped() { atomic.AddUint64(&c.framesDropped, 1) }

// Snapshot is a point-in-time view of all metrics.
type Snapshot struct {
	Uptime              time.Duration
	GoodputBps          float64 // useful bytes/sec
	WireBps             float64 // total wire bytes/sec
	Efficiency          float64 // goodput / wire (1.0 = no overhead)
	RetransmitRatio     float64 // retransmit frames / sent frames
	DuplicationWaste    float64 // duplicate bytes / wire bytes
	FramesSent          uint64
	FramesDelivered     uint64
	FramesRetransmitted uint64
	FramesDuplicated    uint64
	FramesDropped       uint64
	StealthCost         float64 // current goodput / raw-mode goodput (1.0 = no cost)
	CurrentProfile      string
}

// Snapshot computes the current metrics.
func (c *Collector) Snapshot() Snapshot {
	uptime := time.Since(c.startTime)
	secs := uptime.Seconds()
	if secs <= 0 {
		secs = 1
	}

	goodput := atomic.LoadUint64(&c.goodputBytes)
	wire := atomic.LoadUint64(&c.wireBytes)
	retransmit := atomic.LoadUint64(&c.retransmitBytes)
	dup := atomic.LoadUint64(&c.duplicateBytes)
	sent := atomic.LoadUint64(&c.framesSent)
	retransFrames := atomic.LoadUint64(&c.framesRetransmitted)

	goodputBps := float64(goodput) / secs

	s := Snapshot{
		Uptime:              uptime,
		GoodputBps:          goodputBps,
		WireBps:             float64(wire) / secs,
		FramesSent:          sent,
		FramesDelivered:     atomic.LoadUint64(&c.framesDelivered),
		FramesRetransmitted: retransFrames,
		FramesDuplicated:    atomic.LoadUint64(&c.framesDuplicated),
		FramesDropped:       atomic.LoadUint64(&c.framesDropped),
	}

	if wire > 0 {
		s.Efficiency = float64(goodput) / float64(wire)
		s.DuplicationWaste = float64(dup) / float64(wire)
	}
	if sent > 0 {
		s.RetransmitRatio = float64(retransFrames) / float64(sent)
	}
	_ = retransmit // retained for future per-retransmit-byte reporting

	c.mu.Lock()
	s.CurrentProfile = c.currentProfile
	if c.rawGoodputBps > 0 {
		s.StealthCost = goodputBps / c.rawGoodputBps
	} else {
		s.StealthCost = 1.0
	}
	c.mu.Unlock()

	return s
}

// SetRawBaseline records the goodput measured in raw (non-stealth) mode.
// Call this once after a calibration run with no stealth profile active.
// Subsequent stealth-mode goodput is divided by this to yield stealth cost.
func (c *Collector) SetRawBaseline(bps float64) {
	c.mu.Lock()
	c.rawGoodputBps = bps
	c.mu.Unlock()
}

// SetProfile records the currently active stealth profile name.
func (c *Collector) SetProfile(name string) {
	c.mu.Lock()
	c.currentProfile = name
	c.mu.Unlock()
}
