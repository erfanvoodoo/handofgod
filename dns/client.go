package dns

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// client.go is the end-to-end DNS-side send path. It is the seam between the
// Hand of God transport (which produces opaque, already-encrypted datagrams) and the
// wire: it accepts datagrams, schedules them onto profile-shaped DNS queries,
// fills idle slots with cover traffic, encodes each query with the active label
// entropy mode, and adapts the active stealth profile to observed conditions.
//
// The Client owns the wiring between the three Phase 2–3 pieces that were until
// now standalone:
//
//	AdaptiveController   picks the Profile from observed Conditions
//	      │ SetProfile
//	      ▼
//	Scheduler + Sampler  emit timing slots (record type + entropy mode) per Profile
//	      │ Slots()
//	      ▼
//	Client.handleSlot    dequeues a datagram (or makes cover) → EncodeFQDNMode → transmit
//
// client.go itself imports no transport packages: datagrams arrive as []byte
// via Send, and the actual wire send is an injected callback, so the same Client
// works over a real resolver, a test sink, or a Phase 4 adapter. The optional
// path-driven adaptation bridge (Client.ObserveEngine) lives in pathbridge.go,
// isolating the one place dns touches the path engine.

// Query/transmit contract: datagrams handed to Send must already fit the path's
// usable DNS payload size (see path.Engine.SmallestMTU). A datagram that cannot
// be encoded within the 253-char name limit for the active mode is dropped and
// counted, not silently truncated.

// ClientStats is a snapshot of the send path's activity.
type ClientStats struct {
	PayloadSent uint64 // queries carrying a real datagram
	CoverSent   uint64 // cover queries (idle/forced)
	Dropped     uint64 // datagrams dropped (queue full or un-encodable)
	TxErrors    uint64 // transmit callback returned an error
	Queued      int    // datagrams currently queued
	Profile     string // active profile name
	Level       string // active stealth level
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// SessionID is the Hand of God session this client carries.
	SessionID uint16
	// Zone is the authoritative zone queries are sent under.
	Zone string
	// Transmit is the wire sink: it sends one neutral Query. Required in
	// production; defaults to a discard sink if nil (useful for measurement).
	Transmit func(Query) error
	// Controller selects the active profile from conditions. Defaults to a fresh
	// controller with DefaultAdaptiveConfig (starting at standard).
	Controller *AdaptiveController
	// SlotBuffer is the scheduler's slot channel buffer (default 16).
	SlotBuffer int
	// MaxQueue bounds the outbound datagram queue (default 1024). Send drops and
	// counts when full.
	MaxQueue int
	// ControlSource, if set, is consulted on a slot that has no queued data, before
	// falling back to cover: it returns a ready-to-send control datagram (e.g. a
	// coalesced ACK) or nil. This lets the transport piggyback control frames onto
	// scheduler slots instead of queuing one per event — see the ACK-coalescing
	// path in transport. Called from the Run goroutine.
	ControlSource func() []byte
}

// Client drives the DNS send path end to end. Safe for concurrent use: Send and
// UpdateConditions may be called from any goroutine while Run executes.
type Client struct {
	sessionID  uint16
	zone       string
	transmit   func(Query) error
	controller *AdaptiveController
	scheduler  *Scheduler
	maxQueue   int
	control    func() []byte // optional control-frame source, pulled per slot

	mu    sync.Mutex
	queue [][]byte
	stats ClientStats

	rng *rand.Rand // only touched by the Run goroutine (handleSlot)
}

// NewClient creates a Client and its scheduler, seeded from the controller's
// current profile.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Controller == nil {
		cfg.Controller = NewAdaptiveController(DefaultAdaptiveConfig())
	}
	if cfg.MaxQueue <= 0 {
		cfg.MaxQueue = 1024
	}
	if cfg.SlotBuffer <= 0 {
		cfg.SlotBuffer = 16
	}
	if cfg.Zone == "" {
		cfg.Zone = "example.com"
	}
	if cfg.Transmit == nil {
		cfg.Transmit = func(Query) error { return nil }
	}
	return &Client{
		sessionID:  cfg.SessionID,
		zone:       cfg.Zone,
		transmit:   cfg.Transmit,
		controller: cfg.Controller,
		scheduler:  NewScheduler(cfg.Controller.Current(), cfg.SlotBuffer),
		maxQueue:   cfg.MaxQueue,
		control:    cfg.ControlSource,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Send queues an opaque Hand of God datagram for transmission. Returns false if the
// queue is full (the datagram is dropped and counted).
func (c *Client) Send(datagram []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) >= c.maxQueue {
		c.stats.Dropped++
		return false
	}
	d := make([]byte, len(datagram)) // copy: caller may reuse the buffer
	copy(d, datagram)
	c.queue = append(c.queue, d)
	return true
}

// UpdateConditions folds a new conditions sample into the adaptive controller
// and applies the resulting profile to the scheduler. The transport calls this
// as it learns path loss/latency. Returns the now-active profile.
func (c *Client) UpdateConditions(cond Conditions) *Profile {
	p := c.controller.Observe(cond)
	c.scheduler.SetProfile(p)
	return p
}

// Run starts the scheduler and consumes its slots until ctx is cancelled. Run
// blocks; call it in a goroutine.
func (c *Client) Run(ctx context.Context) {
	go c.scheduler.Run(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case slot := <-c.scheduler.Slots():
			c.handleSlot(slot)
		}
	}
}

// handleSlot turns one timing slot into exactly one transmitted query. Priority
// per slot: queued payload data, then a pending control frame (e.g. a coalesced
// ACK pulled from ControlSource), then cover.
func (c *Client) handleSlot(slot SendSlot) {
	var datagram []byte
	if !slot.IsCover {
		datagram = c.dequeue()
	}

	// No queued data: pull a pending control frame (ACK) rather than waste the
	// slot on cover. The transport rebuilds it fresh, so it's never stale or
	// duplicated — this is what coalesces per-DATA acks into one per slot.
	if datagram == nil && c.control != nil {
		datagram = c.control()
	}

	// Idle slot: emit a structurally identical cover query so cover and payload
	// are indistinguishable on the wire.
	if datagram == nil {
		c.send(c.coverQuery(slot), false)
		return
	}

	rtype := slot.SuggestedType
	if rtype.IsCoverOnly() { // defensive: payload needs a carrying record type
		rtype = TypeTXT
	}
	fqdn, err := EncodeFQDNMode(datagram, c.sessionID, c.zone, slot.EntropyMode)
	if err != nil {
		// Datagram too large for this mode/name limit — see MTU contract above.
		c.mu.Lock()
		c.stats.Dropped++
		c.mu.Unlock()
		return
	}
	c.send(Query{
		FQDN:      fqdn,
		Type:      rtype,
		SessionID: c.sessionID,
		IsCover:   false,
	}, true)
}

// send transmits a query and records the outcome.
func (c *Client) send(q Query, payload bool) {
	err := c.transmit(q)
	c.mu.Lock()
	switch {
	case err != nil:
		c.stats.TxErrors++
	case payload:
		c.stats.PayloadSent++
	default:
		c.stats.CoverSent++
	}
	c.mu.Unlock()
}

// coverQuery builds a cover query that mirrors the structure of a payload query:
// random bytes encoded with the same active mode, under this session's id.
//
// The session id (not a random one) matters for two reasons: it makes cover and
// payload queries structurally identical (same session label), and it lets cover
// queries double as downstream polls — a multi-session server routes by session
// id, so only queries carrying this id can pull this session's buffered
// downstream off its responses. The random body fails AEAD open server-side and
// is dropped, but the response still carries any pending downstream.
func (c *Client) coverQuery(slot SendSlot) Query {
	n := 12 + c.rng.Intn(24) // 12..35 bytes
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(c.rng.Intn(256))
	}
	fqdn, err := EncodeFQDNMode(buf, c.sessionID, c.zone, slot.EntropyMode)
	if err != nil {
		// Shouldn't happen for these sizes; fall back to a minimal cover name.
		fqdn, _ = EncodeFQDNMode(buf[:8], c.sessionID, c.zone, slot.EntropyMode)
	}
	return Query{
		FQDN:      fqdn,
		Type:      slot.SuggestedType,
		SessionID: c.sessionID,
		IsCover:   true,
	}
}

func (c *Client) dequeue() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		return nil
	}
	d := c.queue[0]
	c.queue = c.queue[1:]
	return d
}

// Stats returns a snapshot of the send path's activity and current posture.
func (c *Client) Stats() ClientStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.stats
	st.Queued = len(c.queue)
	st.Profile = c.controller.Current().Name
	st.Level = c.controller.Level().String()
	return st
}
