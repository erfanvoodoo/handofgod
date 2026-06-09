package wire

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	wdns "github.com/handofgod/dns"
	"github.com/handofgod/path"
	mdns "github.com/miekg/dns"
)

const testZone = "v.example.com"

func startServer(t *testing.T, cfg ServerConfig) (*Server, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	s := NewServer(cfg)
	go func() { _ = s.Serve(pc) }()
	select {
	case <-s.Started():
	case <-time.After(2 * time.Second):
		t.Fatal("server did not start")
	}
	return s, addr
}

func makePath(t *testing.T, resolver string) *path.Path {
	t.Helper()
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	return e.AddPath(resolver, testZone, cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
}

// TestWireRoundTrip carries an upstream datagram in a query name to the server
// and a downstream datagram back in the TXT response, over real UDP. The wire
// layer treats datagrams as opaque bytes, so this uses plain byte payloads.
func TestWireRoundTrip(t *testing.T) {
	upstreamGot := make(chan []byte, 4)
	downstream := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}

	handler := func(dg []byte, sid uint16) []byte {
		upstreamGot <- append([]byte(nil), dg...)
		if sid != 0xBEEF {
			return nil
		}
		return downstream
	}
	s, addr := startServer(t, ServerConfig{Zone: testZone, Mode: "raw", Handler: handler})
	defer s.Shutdown()

	downGot := make(chan []byte, 4)
	cli := NewClient(ClientConfig{
		Timeout: 2 * time.Second,
		Inbound: func(dg []byte, _ *path.Path) { downGot <- append([]byte(nil), dg...) },
	})

	upstream := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	fqdn, err := wdns.EncodeFQDNMode(upstream, 0xBEEF, testZone, "raw")
	if err != nil {
		t.Fatal(err)
	}
	cli.Send(wdns.Query{FQDN: fqdn, Type: wdns.TypeTXT, SessionID: 0xBEEF}, makePath(t, addr))

	select {
	case got := <-upstreamGot:
		if !bytes.Equal(got, upstream) {
			t.Errorf("server upstream: got %x want %x", got, upstream)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive upstream datagram")
	}

	select {
	case got := <-downGot:
		if !bytes.Equal(got, downstream) {
			t.Errorf("client downstream: got %x want %x", got, downstream)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive downstream datagram")
	}
}

// TestWireDataResponseNotCached verifies tunnel-data TXT answers carry TTL 0, so
// recursive resolvers don't serve a stale cached answer to a retransmit.
func TestWireDataResponseNotCached(t *testing.T) {
	handler := func(_ []byte, _ uint16) []byte { return []byte{0x01, 0x02, 0x03} }
	s, addr := startServer(t, ServerConfig{Zone: testZone, Mode: "raw", Handler: handler})
	defer s.Shutdown()

	fqdn, err := wdns.EncodeFQDNMode([]byte("upstream"), 0xBEEF, testZone, "raw")
	if err != nil {
		t.Fatal(err)
	}
	c := new(mdns.Client)
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(fqdn), mdns.TypeTXT)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	var txt *mdns.TXT
	for _, rr := range resp.Answer {
		if v, ok := rr.(*mdns.TXT); ok {
			txt = v
		}
	}
	if txt == nil {
		t.Fatal("no TXT answer in data response")
	}
	if txt.Hdr.Ttl != 0 {
		t.Errorf("data TXT TTL = %d, want 0 (must be uncacheable)", txt.Hdr.Ttl)
	}
}

// TestWireClientBoundsConcurrency verifies Send caps in-flight round-trips and
// drops (without blocking, and without marking the path down) once saturated.
func TestWireClientBoundsConcurrency(t *testing.T) {
	cli := NewClient(ClientConfig{MaxConcurrent: 2})

	// Inject a round-trip that holds its slot until released, so the bound is
	// observable deterministically (no real network/timing).
	release := make(chan struct{})
	cli.roundTrip = func(_ *mdns.Msg, _ string) (*mdns.Msg, error) {
		<-release
		return nil, errors.New("released")
	}

	p := makePath(t, "203.0.113.1:53") // unused: roundTrip is stubbed
	q := wdns.Query{FQDN: "a." + testZone + ".", Type: wdns.TypeTXT, SessionID: 1}

	// The semaphore is acquired synchronously in Send, so after 5 sends the state
	// is deterministic regardless of goroutine scheduling.
	for i := 0; i < 5; i++ {
		if err := cli.Send(q, p); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	if st := cli.Stats(); st.InFlight != 2 || st.DroppedSaturated != 3 {
		t.Errorf("bounded concurrency: InFlight=%d DroppedSaturated=%d, want 2/3",
			st.InFlight, st.DroppedSaturated)
	}

	close(release) // let the two in-flight round-trips finish
}

// TestWireCover confirms non-Hand of God queries get plausible authoritative cover:
// an in-zone A query yields an A record, an out-of-zone query yields NXDOMAIN.
func TestWireCover(t *testing.T) {
	s, addr := startServer(t, ServerConfig{Zone: testZone, Mode: "raw"}) // no handler
	defer s.Shutdown()

	c := new(mdns.Client)

	inZone := new(mdns.Msg)
	inZone.SetQuestion(mdns.Fqdn("www."+testZone), mdns.TypeA)
	resp, _, err := c.Exchange(inZone, addr)
	if err != nil {
		t.Fatal(err)
	}
	foundA := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*mdns.A); ok {
			foundA = true
		}
	}
	if !foundA {
		t.Errorf("expected an A cover record for in-zone query, got %v", resp.Answer)
	}

	outZone := new(mdns.Msg)
	outZone.SetQuestion("www.google.com.", mdns.TypeA)
	resp2, _, err := c.Exchange(outZone, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Rcode != mdns.RcodeNameError {
		t.Errorf("expected NXDOMAIN for out-of-zone query, got rcode %d", resp2.Rcode)
	}
}

// TestWireServerDecodesNgram confirms the server decodes a non-raw entropy mode
// when configured to match the client.
func TestWireServerDecodesNgram(t *testing.T) {
	got := make(chan uint16, 1)
	handler := func(_ []byte, sid uint16) []byte {
		got <- sid
		return nil
	}
	s, addr := startServer(t, ServerConfig{Zone: testZone, Mode: "ngram", Handler: handler})
	defer s.Shutdown()

	cli := NewClient(ClientConfig{Timeout: 2 * time.Second})
	fqdn, err := wdns.EncodeFQDNMode([]byte{9, 8, 7}, 0x1234, testZone, "ngram")
	if err != nil {
		t.Fatal(err)
	}
	cli.Send(wdns.Query{FQDN: fqdn, Type: wdns.TypeTXT, SessionID: 0x1234}, makePath(t, addr))

	select {
	case sid := <-got:
		if sid != 0x1234 {
			t.Errorf("session id: got %x want 1234", sid)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not decode ngram query")
	}
}
