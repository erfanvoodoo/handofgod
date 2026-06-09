package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/handofgod/arq"
	"github.com/handofgod/crypto"
	"github.com/handofgod/frame"
)

// server_session.go is the authoritative-side transport. Unlike the client
// Session it never initiates queries: DNS downstream is strictly pull-based — the
// server can only put bytes on the wire by attaching them to a response. So a
// ServerSession processes each upstream datagram, buffers any sealed downstream
// datagram, and drains exactly one downstream per inbound query.
//
// HandleUpstream satisfies wire.UpstreamFunc, making a ServerSession droppable
// straight into wire.Server as its Handler.

// maxDownstreamQueue bounds buffered downstream datagrams. Reliable frames over
// the cap are dropped (oldest first) and recovered by retransmission; unreliable
// ones (ACK/PONG) are regenerated.
const maxDownstreamQueue = 4096

// ServerConfig configures a ServerSession.
type ServerConfig struct {
	SessionID uint16
	// Sealer is the server→client (downstream) AEAD; Opener is client→server
	// (upstream). Built by the caller from the handshake keys.
	Sealer *crypto.Sealer
	Opener *crypto.Opener
	// Deliver receives in-order application stream data from the client.
	Deliver func(streamID uint16, data []byte)

	WindowSize     int
	MinRTO, MaxRTO time.Duration
}

// ServerStats is a snapshot of a ServerSession.
type ServerStats struct {
	InFlight         int    // unacked downstream reliable frames
	Delivered        uint64 // upstream frames delivered in order
	DownstreamQueued int    // sealed downstream datagrams awaiting a carrier query
	DroppedIn        uint64 // undecodable upstream datagrams (cover/corrupt/replay)
}

// ServerSession is one session's authoritative-side transport engine.
type ServerSession struct {
	cfg      ServerConfig
	sender   *arq.Sender   // downstream (server→client) reliable
	receiver *arq.Receiver // upstream (client→server)

	// recvMu serializes upstream processing; miekg dispatches each query on its
	// own goroutine, and crypto.Opener/in-order delivery require serialization.
	recvMu sync.Mutex

	mu         sync.Mutex
	dataQ      [][]byte // sealed downstream datagrams awaiting a carrier query
	ackPending bool
	preferAck  bool // alternate ack/data so neither starves the other

	onClose func() // set by the Listener; called when the peer sends SESSION_CLOSE

	stop      chan struct{} // closed by Close to stop Run
	closeOnce sync.Once

	lastActivity int64  // UnixNano of the last inbound query (atomic)
	droppedIn    uint64 // atomic
}

// NewServerSession builds an authoritative-side session.
func NewServerSession(cfg ServerConfig) *ServerSession {
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 1024
	}
	if cfg.MinRTO <= 0 {
		cfg.MinRTO = 200 * time.Millisecond
	}
	if cfg.MaxRTO <= 0 {
		cfg.MaxRTO = 4 * time.Second
	}
	return &ServerSession{
		cfg:          cfg,
		sender:       arq.NewSender(cfg.WindowSize, cfg.MinRTO, cfg.MaxRTO),
		receiver:     arq.NewReceiver(),
		stop:         make(chan struct{}),
		lastActivity: time.Now().UnixNano(),
	}
}

// HandleUpstream processes one upstream datagram and returns at most one
// downstream datagram to piggyback on the response (nil if none). It satisfies
// wire.UpstreamFunc. The sessionID argument (decoded from the query name) is
// advisory; a multi-session server routes on it to the right ServerSession.
func (s *ServerSession) HandleUpstream(datagram []byte, _ uint16) []byte {
	atomic.StoreInt64(&s.lastActivity, time.Now().UnixNano())
	s.recvMu.Lock()
	closing := s.processUpstream(datagram)
	s.recvMu.Unlock()
	if closing && s.onClose != nil {
		s.onClose() // peer asked to tear down → let the Listener evict us
	}
	return s.drainDownstream()
}

// processUpstream returns true if the peer sent SESSION_CLOSE.
func (s *ServerSession) processUpstream(datagram []byte) (closing bool) {
	_, seq, f, err := frame.DecodeDatagram(s.cfg.Opener, datagram)
	if err != nil {
		atomic.AddUint64(&s.droppedIn, 1)
		return false
	}
	switch f.Type {
	case frame.TypeData, frame.TypeStreamOpen, frame.TypeStreamClose:
		delivered := s.receiver.Accept(seq, f)
		if s.cfg.Deliver != nil {
			for _, df := range delivered {
				if df.Type == frame.TypeData {
					s.cfg.Deliver(df.StreamID, df.Payload)
				}
			}
		}
		s.mu.Lock()
		s.ackPending = true
		s.mu.Unlock()
	case frame.TypeAck:
		if ack, e := frame.DecodeAck(f.Payload); e == nil {
			s.sender.OnAck(ack, time.Now())
		}
	case frame.TypePing:
		s.enqueue(s.sealUnreliable(frame.Frame{Type: frame.TypePong, Payload: append([]byte(nil), f.Payload...)}))
	case frame.TypeSessionClose:
		return true
	}
	return false
}

// Write queues downstream application data as a reliable DATA frame; it goes out
// when the next inbound query provides a carrier.
func (s *ServerSession) Write(streamID uint16, data []byte) {
	f := frame.Frame{Type: frame.TypeData, StreamID: streamID, Payload: data}
	seq := s.sender.Next(f)
	s.enqueue(frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, seq, f))
}

func (s *ServerSession) enqueue(dg []byte) {
	s.mu.Lock()
	if len(s.dataQ) >= maxDownstreamQueue {
		s.dataQ = s.dataQ[1:] // drop oldest; reliable frames are re-queued on RTO
	}
	s.dataQ = append(s.dataQ, dg)
	s.mu.Unlock()
}

// drainDownstream returns the next downstream datagram for a response, balancing
// queued data against a pending ACK so neither direction starves.
func (s *ServerSession) drainDownstream() []byte {
	s.mu.Lock()
	haveData := len(s.dataQ) > 0
	sendAck := false
	switch {
	case s.ackPending && (!haveData || s.preferAck):
		s.ackPending = false
		s.preferAck = false
		sendAck = true
	case haveData:
		s.preferAck = true // next carrier prefers a pending ack
		dg := s.dataQ[0]
		s.dataQ = s.dataQ[1:]
		s.mu.Unlock()
		return dg
	case s.ackPending:
		s.ackPending = false
		sendAck = true
	}
	s.mu.Unlock()

	if sendAck {
		return s.buildAck()
	}
	return nil
}

func (s *ServerSession) buildAck() []byte {
	ack := s.receiver.BuildAck()
	return s.sealUnreliable(frame.Frame{Type: frame.TypeAck, Payload: frame.EncodeAck(ack)})
}

func (s *ServerSession) sealUnreliable(f frame.Frame) []byte {
	seq := s.sender.NextUnreliableSeq()
	return frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, seq, f)
}

// PumpRetransmits re-queues downstream reliable frames whose RTO has expired.
func (s *ServerSession) PumpRetransmits(now time.Time) int {
	due := s.sender.DueForRetransmit(now)
	for _, item := range due {
		s.enqueue(frame.EncodeDatagram(s.cfg.Sealer, s.cfg.SessionID, item.Seq, item.Frame))
	}
	return len(due)
}

// Run drives downstream retransmission timing until ctx is cancelled or the
// session is Closed (e.g. evicted by the reaper or torn down by the peer).
func (s *ServerSession) Run(ctx context.Context) {
	t := time.NewTicker(retransmitInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case now := <-t.C:
			s.PumpRetransmits(now)
		}
	}
}

// Close stops the session's Run loop. Idempotent.
func (s *ServerSession) Close() {
	s.closeOnce.Do(func() { close(s.stop) })
}

// IdleFor reports how long since the last inbound query for this session.
func (s *ServerSession) IdleFor() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&s.lastActivity)))
}

// setOnClose registers the eviction hook invoked when the peer sends
// SESSION_CLOSE. Set by the Listener before the session goes live.
func (s *ServerSession) setOnClose(fn func()) { s.onClose = fn }

// Stats returns a snapshot of the server session.
func (s *ServerSession) Stats() ServerStats {
	s.mu.Lock()
	q := len(s.dataQ)
	s.mu.Unlock()
	return ServerStats{
		InFlight:         s.sender.Stats().InFlight,
		Delivered:        s.receiver.Stats().Delivered,
		DownstreamQueued: q,
		DroppedIn:        atomic.LoadUint64(&s.droppedIn),
	}
}
