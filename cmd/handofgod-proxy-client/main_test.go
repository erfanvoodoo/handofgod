package main

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestTunnelSink_ReplyReadyFence proves the ordering fence in the tunnelSink:
// a deliver('D') that arrives after 'O' but before handleClient has written
// the SOCKS5 reply MUST block until signalReplyReady is called. Only then may
// the payload bytes reach the local socket. This is the field bug that would
// have corrupted TLS streams by interleaving payload before the SOCKS reply.
func TestTunnelSink_ReplyReadyFence(t *testing.T) {
	// Fake conn that records ALL writes in order.
	conn := newRecordingConn()
	sink := newTunnelSink(conn)

	// Deliver 'O' (CONNECT-OK); deliver is synchronous.
	sink.deliver(1, []byte{msgConnectOK})
	select {
	case <-sink.helloDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("helloDone was not signaled after 'O'")
	}

	// Deliver 'D' in a goroutine. It must block on the replyReady fence.
	dataDelivered := make(chan struct{})
	go func() {
		sink.deliver(1, append([]byte{msgData}, []byte("PAYLOAD")...))
		close(dataDelivered)
	}()

	// Verify 'D' has NOT reached the conn yet.
	select {
	case <-dataDelivered:
		t.Fatal("deliver(D) returned before replyReady was signaled")
	case <-time.After(150 * time.Millisecond):
		// good — still blocked
	}
	if got := conn.snapshot(); len(got) != 0 {
		t.Fatalf("payload leaked to conn before reply: %q", got)
	}

	// Simulate handleClient: write the SOCKS reply directly, THEN signal.
	if _, err := conn.Write([]byte("SOCKS-REPLY")); err != nil {
		t.Fatalf("reply write: %v", err)
	}
	sink.signalReplyReady()

	// Now deliver('D') should complete and the payload should be appended.
	select {
	case <-dataDelivered:
	case <-time.After(1 * time.Second):
		t.Fatal("deliver(D) did not return after signalReplyReady()")
	}

	// Wire order must be reply first, then payload.
	got := conn.snapshot()
	want := []byte("SOCKS-REPLYPAYLOAD")
	if !bytes.Equal(got, want) {
		t.Fatalf("write order wrong: got %q want %q", got, want)
	}
}

// TestTunnelSink_SignalReadyIdempotent guards against double-close panics
// (the defer path + explicit call both fire on success).
func TestTunnelSink_SignalReadyIdempotent(t *testing.T) {
	sink := newTunnelSink(newRecordingConn())
	sink.signalReplyReady()
	sink.signalReplyReady() // must not panic
	select {
	case <-sink.replyReady:
	default:
		t.Fatal("replyReady not closed after signalReplyReady")
	}
}

// TestMaxWritePayload_PerMode is the sanity check on chunk.go's math from the
// client side. Same idea as the server-side test, kept here so this binary can
// be exercised in isolation.
func TestMaxWritePayload_PerMode(t *testing.T) {
	// Just verify each mode is >0 and log the value. The end-to-end encoding
	// check lives in the proxy-server test package (which imports dns/frame);
	// duplicating that here would just duplicate imports.
	for _, mode := range []string{"raw", "padded", "ngram"} {
		got := maxWritePayload("v.example.com", mode)
		if got <= 0 {
			t.Errorf("maxWritePayload(%q) = %d, want > 0", mode, got)
		}
		t.Logf("mode=%s app_payload=%d", mode, got)
	}
}

// ── recording conn: a minimal net.Conn that records every Write ─────────────

type recordingConn struct {
	mu     sync.Mutex
	writes bytes.Buffer
}

func newRecordingConn() *recordingConn { return &recordingConn{} }

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.Write(p)
}

func (c *recordingConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.writes.Len())
	copy(out, c.writes.Bytes())
	return out
}

func (c *recordingConn) Read(_ []byte) (int, error)         { return 0, errUnused }
func (c *recordingConn) Close() error                       { return nil }
func (c *recordingConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *recordingConn) SetDeadline(_ time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(_ time.Time) error { return nil }

var errUnused = errors.New("recordingConn: Read unused")

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "recording" }
