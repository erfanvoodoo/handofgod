package main

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/handofgod/transport"
)

// Sub-protocol carried over a single Hand of God stream. The transport delivers
// each Write/Deliver as one discrete message, so the first byte tags the kind
// and the remainder is the payload — no length prefixing needed.
//
//	'C' + "host:port"    client → server   CONNECT (exactly once, first message)
//	'O'                  server → client   CONNECT-OK
//	'E' + reason         server → client   CONNECT-ERR (textual reason; no trailer)
//	'D' + bytes          both              forwarded TCP bytes
//	'F'                  both              sender has no more data (half-close)
//
// One SOCKS5 connection ↔ one Hand of God session ↔ one stream. Tunnels are
// keyed by (sessionID, streamID) so streams in different sessions never collide.
const (
	msgConnect    byte = 'C'
	msgConnectOK  byte = 'O'
	msgConnectErr byte = 'E'
	msgData       byte = 'D'
	msgFin        byte = 'F'
)

const (
	dialTimeout       = 10 * time.Second
	remoteReadBufSize = 16 * 1024
	sweepInterval     = 1 * time.Minute
	tunnelIdleTimeout = 30 * time.Minute
)

type tunnelKey struct {
	sid    uint16
	stream uint16
}

// tunnel is one in-flight forwarded TCP connection. All mutable state is
// guarded by mu; the remote-read goroutine takes a stable snapshot at start
// and only touches lastActivity / tx-side flags under the lock thereafter.
type tunnel struct {
	key  tunnelKey
	sess *transport.ServerSession

	mu           sync.Mutex
	conn         net.Conn // remote TCP; nil before CONNECT-OK
	dialing      bool     // CONNECT received, dial in progress
	dialed       bool     // CONNECT response already sent
	txFin        bool     // we (server side) sent F downstream
	rxFin        bool     // peer (client side) sent F upstream
	closed       bool     // teardown already ran (idempotent)
	lastActivity time.Time
}

// tunnelHandler owns the (sid,stream) → tunnel map and the dial allow-list.
// It is safe for concurrent use; the Listener may invoke onData from any
// goroutine.
type tunnelHandler struct {
	mu        sync.Mutex
	tunnels   map[tunnelKey]*tunnel
	allowDest string
	logf      func(format string, a ...any)
	stop      chan struct{}
	stopOnce  sync.Once

	// zone and mode are the deployment-fixed settings needed to compute the
	// per-Write app-payload ceiling (chunk.go: maxWritePayload). Larger writes
	// are silently dropped by dns.Client, so the read loops must pre-chunk.
	zone      string
	mode      string
	chunkSize int // maxWritePayload(zone, mode) minus 1 for the 'D' type byte
}

func newTunnelHandler(allowDest, zone, mode string, logf func(string, ...any)) *tunnelHandler {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	chunk := maxWritePayload(zone, mode) - 1 // reserve 1 byte for the 'D' prefix
	if chunk < 1 {
		chunk = 1
	}
	h := &tunnelHandler{
		tunnels:   make(map[tunnelKey]*tunnel),
		allowDest: allowDest,
		logf:      logf,
		stop:      make(chan struct{}),
		zone:      zone,
		mode:      mode,
		chunkSize: chunk,
	}
	go h.sweepLoop()
	return h
}

// shutdown stops the sweeper and tears down every active tunnel. Idempotent.
func (h *tunnelHandler) shutdown() {
	h.stopOnce.Do(func() { close(h.stop) })
	h.mu.Lock()
	all := make([]*tunnel, 0, len(h.tunnels))
	for _, t := range h.tunnels {
		all = append(all, t)
	}
	h.mu.Unlock()
	for _, t := range all {
		h.teardown(t)
	}
}

// onAccept logs the new session; tunnels are created lazily on first stream data.
func (h *tunnelHandler) onAccept(_ *transport.ServerSession, sid uint16) {
	h.logf("session %04x accepted", sid)
}

// onData routes one upstream message for (sid, streamID) to its tunnel.
func (h *tunnelHandler) onData(sess *transport.ServerSession, sid, streamID uint16, data []byte) {
	if len(data) == 0 {
		return
	}
	key := tunnelKey{sid: sid, stream: streamID}

	h.mu.Lock()
	tun, ok := h.tunnels[key]
	if !ok {
		tun = &tunnel{key: key, sess: sess, lastActivity: time.Now()}
		h.tunnels[key] = tun
	}
	h.mu.Unlock()

	tun.mu.Lock()
	tun.lastActivity = time.Now()
	tun.mu.Unlock()

	switch data[0] {
	case msgConnect:
		go h.dispatchConnect(tun, string(data[1:]))
	case msgData:
		h.dispatchData(tun, data[1:])
	case msgFin:
		h.dispatchFin(tun)
	default:
		// Unknown message — silently drop (forward-compat).
	}
}

// dispatchConnect validates the target and dials it. Runs on its own goroutine
// so the upstream pump is not blocked by the dial.
func (h *tunnelHandler) dispatchConnect(tun *tunnel, hostPort string) {
	tun.mu.Lock()
	if tun.dialed || tun.dialing {
		tun.mu.Unlock()
		return // duplicate CONNECT; ignore
	}
	tun.dialing = true
	tun.mu.Unlock()

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil || host == "" || port == "" {
		h.completeConnect(tun, nil, "invalid host:port")
		return
	}
	if h.allowDest != "" && hostPort != h.allowDest {
		h.completeConnect(tun, nil, "destination not allowed")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, dialErr := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if dialErr != nil {
		h.completeConnect(tun, nil, dialErr.Error())
		return
	}
	h.completeConnect(tun, conn, "")
}

func (h *tunnelHandler) completeConnect(tun *tunnel, conn net.Conn, errMsg string) {
	tun.mu.Lock()
	tun.dialing = false
	tun.dialed = true
	if conn != nil {
		tun.conn = conn
	}
	tun.mu.Unlock()

	if conn == nil {
		// CONNECT-ERR rides downstream on the next client query; the client tears
		// the session down on receipt. Drop our map entry now — no more state for
		// this tunnel to hold.
		reply := append([]byte{msgConnectErr}, []byte(errMsg)...)
		tun.sess.Write(tun.key.stream, reply)
		h.remove(tun.key)
		h.logf("tunnel %v: connect failed: %s", tun.key, errMsg)
		return
	}

	tun.sess.Write(tun.key.stream, []byte{msgConnectOK})
	h.logf("tunnel %v: connected to %s", tun.key, conn.RemoteAddr())
	go h.pipeRemoteToSession(tun)
}

// dispatchData forwards client→remote bytes. If CONNECT hasn't completed,
// the bytes are dropped — reliable protocols (HTTP, TLS) never send data
// before the SOCKS reply, so this is fine in practice.
func (h *tunnelHandler) dispatchData(tun *tunnel, payload []byte) {
	tun.mu.Lock()
	conn := tun.conn
	closed := tun.closed
	tun.mu.Unlock()
	if conn == nil || closed {
		return
	}
	if _, err := conn.Write(payload); err != nil {
		h.teardown(tun)
	}
}

// dispatchFin records the peer's EOF and half-closes the remote write side
// so the upstream service sees end-of-stream. If both directions are now
// EOF'd, tear the tunnel down.
func (h *tunnelHandler) dispatchFin(tun *tunnel) {
	tun.mu.Lock()
	tun.rxFin = true
	conn := tun.conn
	both := tun.txFin
	tun.mu.Unlock()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	if both {
		h.teardown(tun)
	}
}

// pipeRemoteToSession reads from the remote TCP socket and Writes chunks
// downstream as 'D' messages. Each read is split into slices of at most
// h.chunkSize bytes so no single Write exceeds dns.Client's per-mode payload
// ceiling (see chunk.go). ARQ reassembles in seq order on the client, and
// sender.Next assigns seqs in call order, so ordering is preserved. On
// EOF/error it sends a single 'F' marker.
func (h *tunnelHandler) pipeRemoteToSession(tun *tunnel) {
	tun.mu.Lock()
	conn := tun.conn
	tun.mu.Unlock()
	if conn == nil {
		return
	}

	buf := make([]byte, remoteReadBufSize)
	for {
		n, err := conn.Read(buf)
		// Emit each read as one or more D chunks, each ≤ h.chunkSize bytes.
		for off := 0; off < n; {
			end := off + h.chunkSize
			if end > n {
				end = n
			}
			msg := make([]byte, 1+(end-off))
			msg[0] = msgData
			copy(msg[1:], buf[off:end])
			tun.mu.Lock()
			tun.lastActivity = time.Now()
			closed := tun.closed
			tun.mu.Unlock()
			if closed {
				return
			}
			tun.sess.Write(tun.key.stream, msg)
			off = end
		}
		if err != nil {
			tun.mu.Lock()
			tun.txFin = true
			both := tun.rxFin
			closed := tun.closed
			tun.mu.Unlock()
			if !closed {
				tun.sess.Write(tun.key.stream, []byte{msgFin})
			}
			if both {
				h.teardown(tun)
			}
			return
		}
	}
}

// teardown closes the remote socket and removes the tunnel from the map.
// Safe to call multiple times.
func (h *tunnelHandler) teardown(tun *tunnel) {
	tun.mu.Lock()
	if tun.closed {
		tun.mu.Unlock()
		return
	}
	tun.closed = true
	conn := tun.conn
	tun.conn = nil
	tun.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	h.remove(tun.key)
}

func (h *tunnelHandler) remove(key tunnelKey) {
	h.mu.Lock()
	delete(h.tunnels, key)
	h.mu.Unlock()
}

// activeCount is for tests.
func (h *tunnelHandler) activeCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.tunnels)
}

func (h *tunnelHandler) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			h.sweepOnce(time.Now())
		}
	}
}

func (h *tunnelHandler) sweepOnce(now time.Time) {
	var stale []*tunnel
	h.mu.Lock()
	for _, t := range h.tunnels {
		t.mu.Lock()
		idle := now.Sub(t.lastActivity)
		t.mu.Unlock()
		if idle > tunnelIdleTimeout {
			stale = append(stale, t)
		}
	}
	h.mu.Unlock()
	for _, t := range stale {
		h.teardown(t)
	}
}
