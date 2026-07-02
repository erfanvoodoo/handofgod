// Command handofgod-proxy-client is a local SOCKS5 (RFC 1928) listener that
// forwards each accepted TCP CONNECT through a Hand of God session to a
// handofgod-proxy-server, which dials the destination on the client's behalf.
//
// One SOCKS5 connection ↔ one Hand of God session ↔ one stream ↔ one remote
// TCP socket. Sub-protocol on that stream is described in the proxy-server's
// tunnel.go (C/O/E/D/F messages).
//
// Configuration precedence: built-in defaults < -config JSON file < explicit flags.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/path"
	"github.com/handofgod/transport"
	"github.com/handofgod/wire"
)

// Sub-protocol message types (must match cmd/handofgod-proxy-server/tunnel.go).
const (
	msgConnect    byte = 'C'
	msgConnectOK  byte = 'O'
	msgConnectErr byte = 'E'
	msgData       byte = 'D'
	msgFin        byte = 'F'

	tunnelStream uint16 = 1

	connectTimeout = 15 * time.Second
	localReadBuf   = 16 * 1024
)

var verbose bool

func vlogf(format string, a ...any) {
	if verbose {
		log.Printf("[debug] "+format, a...)
	}
}

type fileConfig struct {
	Socks     *string `json:"socks"`
	Resolvers *string `json:"resolvers"`
	Zone      *string `json:"zone"`
	ServerKey *string `json:"server_key"`
	Mode      *string `json:"mode"`
	Profile   *string `json:"profile"`
	AES       *bool   `json:"aes"`
	Verbose   *bool   `json:"verbose"`
}

func main() {
	socks := flag.String("socks", "127.0.0.1:1080", "local address for the SOCKS5 listener")
	resolvers := flag.String("resolvers", "127.0.0.1:5353", "comma-separated DNS resolver addresses (each is a multi-path route)")
	zone := flag.String("zone", "v.example.com", "authoritative zone")
	serverKey := flag.String("server-key", "", "server static public key, hex (REQUIRED; printed by proxy-server)")
	mode := flag.String("mode", "raw", "label entropy mode: raw|padded|ngram (must match the server)")
	profile := flag.String("profile", "fast", "traffic profile: fast|standard|doh|stealth (timing/cover shape)")
	aes := flag.Bool("aes", false, "advertise AES-256-GCM")
	verboseFlag := flag.Bool("v", false, "verbose logging")
	configPath := flag.String("config", "", "JSON config file (explicit flags override its values)")
	flag.Parse()

	loadConfig(*configPath, socks, resolvers, zone, serverKey, mode, profile, aes, verboseFlag)
	verbose = *verboseFlag

	pub, err := parsePubKey(*serverKey)
	if err != nil {
		log.Fatalf("-server-key: %v", err)
	}
	prof, err := buildProfile(*profile, *mode)
	if err != nil {
		log.Fatalf("-profile: %v", err)
	}
	routes := splitList(*resolvers)
	if len(routes) == 0 {
		log.Fatal("-resolvers: at least one resolver address is required")
	}
	caps := uint16(0x04) // SACK
	if *aes {
		caps |= crypto.CapAEADAESGCM
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", *socks)
	if err != nil {
		log.Fatalf("socks5 listen %q: %v", *socks, err)
	}
	log.Printf("SOCKS5 listener on %s → Hand of God carrier via %v (zone %q, mode %q, profile %q)",
		ln.Addr(), routes, *zone, *mode, *profile)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Print("shutting down")
		_ = ln.Close()
		cancel()
	}()

	dialer := &carrierDialer{
		zone:    *zone,
		mode:    *mode,
		caps:    caps,
		pub:     pub,
		routes:  routes,
		profile: prof,
	}
	acceptLoop(ctx, ln, dialer)
}

func acceptLoop(ctx context.Context, ln net.Listener, dialer *carrierDialer) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Transient accept errors: log and continue.
			log.Printf("accept: %v", err)
			continue
		}
		go handleClient(ctx, conn, dialer)
	}
}

// carrierDialer is the per-invocation config needed to open a fresh Hand of God
// session for each SOCKS5 client.
type carrierDialer struct {
	zone    string
	mode    string
	caps    uint16
	pub     [crypto.KeySize]byte
	routes  []string
	profile *dns.Profile
}

// dial opens a fresh Hand of God session bound to the given inbound handler
// (Deliver + wire Inbound). Returns the session and a shutdown func that closes
// the session and the wire client.
func (d *carrierDialer) dial(ctx context.Context, deliver func(uint16, []byte), onClose func(byte)) (*transport.Session, func(), error) {
	eng := path.NewEngine(path.DefaultConfig())
	for _, r := range d.routes {
		eng.AddPath(r, d.zone, 0.5, 0.3, 0.2)
	}
	ctrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	ctrl.SetProfile(dns.LevelStandard, d.profile)
	ctrl.SetProfile(dns.LevelElevated, d.profile)
	ctrl.SetProfile(dns.LevelMax, d.profile)

	wcli := wire.NewClient(wire.ClientConfig{Timeout: 5 * time.Second})

	sess, err := transport.Dial(transport.DialConfig{
		ServerStaticPub: d.pub,
		Caps:            d.caps,
		Zone:            d.zone,
		Mode:            d.mode,
		Engine:          eng,
		Controller:      ctrl,
		RoundTrip:       wcli.RoundTrip,
		WireSend:        wcli.Send,
		Deliver:         deliver,
		OnClose:         onClose,
	})
	if err != nil {
		return nil, nil, err
	}
	wcli.SetInbound(func(dg []byte, p *path.Path) { sess.HandleInbound(dg, p) })
	go sess.Run(ctx)

	shutdown := func() { sess.Close(0) }
	return sess, shutdown, nil
}

// tunnelSink stitches incoming Hand of God messages into the two logical
// events the SOCKS5 handler needs: the CONNECT reply (hello) and downstream
// bytes/EOF. Deliver is called serially by the transport under recvMu, so
// awaitingHello is safe to read/write without additional locking; we keep mu
// here defensively (the transport's serialization guarantee is a contract
// worth being explicit about).
//
// Ordering fence for downstream data:
//
//	replyReady is closed by handleClient IMMEDIATELY AFTER writeReply for
//	repSuccess completes. Any msgData arriving before that blocks in deliver
//	on <-replyReady, so the SOCKS5 client ALWAYS reads the reply bytes before
//	any payload bytes. handleClient also defers signalReplyReady() as a
//	safety net so error paths never leave deliver hung.
type tunnelSink struct {
	mu            sync.Mutex
	awaitingHello bool
	local         net.Conn
	helloOnce     sync.Once
	helloDone     chan helloResult

	replyReadyOnce sync.Once
	replyReady     chan struct{}

	remoteFinOnce sync.Once
	remoteFin     chan struct{}
	writeErrOnce  sync.Once
	writeErr      chan struct{}
}

type helloResult struct {
	ok     bool
	reason string
}

func newTunnelSink(local net.Conn) *tunnelSink {
	return &tunnelSink{
		awaitingHello: true,
		local:         local,
		helloDone:     make(chan helloResult, 1),
		replyReady:    make(chan struct{}),
		remoteFin:     make(chan struct{}),
		writeErr:      make(chan struct{}),
	}
}

// signalReplyReady tells any blocked deliver('D') that the SOCKS5 reply has
// been written and downstream payload may now flow to the local socket.
// Idempotent — safe to call from both the success path and a defer.
func (s *tunnelSink) signalReplyReady() {
	s.replyReadyOnce.Do(func() { close(s.replyReady) })
}

func (s *tunnelSink) deliver(_ uint16, data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	awaiting := s.awaitingHello
	s.mu.Unlock()

	if awaiting {
		switch data[0] {
		case msgConnectOK:
			s.mu.Lock()
			s.awaitingHello = false
			s.mu.Unlock()
			s.helloOnce.Do(func() { s.helloDone <- helloResult{ok: true} })
		case msgConnectErr:
			s.helloOnce.Do(func() {
				s.helloDone <- helloResult{ok: false, reason: string(data[1:])}
			})
		}
		return
	}

	switch data[0] {
	case msgData:
		// Ordering fence: never write payload bytes before the SOCKS5 reply.
		// replyReady is closed once handleClient's writeReply(repSuccess)
		// returns (or on any error-path defer), so this blocks at most one
		// local-socket write latency for the first D. Deliver is called under
		// the transport's recvMu, so this pause serializes downstream frames
		// naturally.
		<-s.replyReady
		if _, err := s.local.Write(data[1:]); err != nil {
			s.writeErrOnce.Do(func() { close(s.writeErr) })
		}
	case msgFin:
		s.remoteFinOnce.Do(func() { close(s.remoteFin) })
	}
}

// handleClient runs one SOCKS5 client end-to-end: greet, request, Hand of God
// Dial, CONNECT round-trip, then bidirectional forwarding.
func handleClient(ctx context.Context, local net.Conn, dialer *carrierDialer) {
	defer local.Close()

	// Set a modest deadline on the SOCKS5 preamble; drop deadline after CONNECT
	// succeeds (bidirectional forwarding may be long-lived).
	_ = local.SetDeadline(time.Now().Add(30 * time.Second))

	methods, err := readGreeting(local)
	if err != nil {
		vlogf("greeting: %v", err)
		return
	}
	m := chooseMethod(methods)
	if err := writeMethodChoice(local, m); err != nil {
		vlogf("method choice write: %v", err)
		return
	}
	if m == methodNoAcceptable {
		return
	}

	req, err := readRequest(local)
	if err != nil {
		vlogf("request: %v", err)
		if req != nil {
			_ = writeReply(local, repAddressTypeNotSupport, req)
		} else {
			_ = writeReply(local, repGeneralFailure, nil)
		}
		return
	}
	if req.Cmd != cmdConnect {
		vlogf("unsupported CMD 0x%02x", req.Cmd)
		_ = writeReply(local, repCommandNotSupported, req)
		return
	}

	// Clear preamble deadline; forwarding is unbounded.
	_ = local.SetDeadline(time.Time{})

	sink := newTunnelSink(local)
	// Safety net: no matter how handleClient exits, unblock any deliver('D')
	// that might be waiting on the ordering fence. Idempotent.
	defer sink.signalReplyReady()

	sess, shutdown, err := dialer.dial(ctx, sink.deliver, func(code byte) {
		vlogf("session closed by peer (code %d)", code)
		sink.remoteFinOnce.Do(func() { close(sink.remoteFin) })
	})
	if err != nil {
		vlogf("carrier dial: %v", err)
		_ = writeReply(local, repGeneralFailure, req)
		return
	}
	defer shutdown()

	// Send CONNECT
	sess.Write(tunnelStream, append([]byte{msgConnect}, []byte(req.Address)...))

	// Wait for hello
	var hello helloResult
	select {
	case hello = <-sink.helloDone:
	case <-time.After(connectTimeout):
		vlogf("carrier CONNECT timeout to %s", req.Address)
		_ = writeReply(local, repTTLExpired, req)
		return
	case <-ctx.Done():
		return
	}

	if !hello.ok {
		vlogf("carrier CONNECT rejected %s: %s", req.Address, hello.reason)
		_ = writeReply(local, replyCodeFor(hello.reason), req)
		return
	}

	// Success — send SOCKS5 reply, then release the ordering fence so any
	// buffered downstream payload can now be written to the local socket.
	if err := writeReply(local, repSuccess, req); err != nil {
		vlogf("reply write: %v", err)
		return
	}
	sink.signalReplyReady()

	// local → session. Each Read is split into chunks of at most `chunk`
	// bytes so no single Session.Write exceeds dns.Client's per-mode payload
	// ceiling (see chunk.go). ARQ reassembles in seq order on the far side;
	// sender.Next assigns seqs in call order, so ordering is preserved.
	chunk := maxWritePayload(dialer.zone, dialer.mode) - 1 // reserve 1 byte for 'D'
	if chunk < 1 {
		chunk = 1
	}
	localReadDone := make(chan struct{})
	go func() {
		defer close(localReadDone)
		buf := make([]byte, localReadBuf)
		for {
			n, err := local.Read(buf)
			for off := 0; off < n; {
				end := off + chunk
				if end > n {
					end = n
				}
				msg := make([]byte, 1+(end-off))
				msg[0] = msgData
				copy(msg[1:], buf[off:end])
				sess.Write(tunnelStream, msg)
				off = end
			}
			if err != nil {
				sess.Write(tunnelStream, []byte{msgFin})
				return
			}
		}
	}()

	// Wait for either end to signal completion; then finish the other side.
	select {
	case <-sink.remoteFin:
		// Peer done writing. Half-close local write side; the SOCKS5 client
		// sees EOF on its read half. Local read continues until its own EOF.
		if tc, ok := local.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		// Give the local read a bounded window to finish so the client can
		// send its final bytes.
		select {
		case <-localReadDone:
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	case <-localReadDone:
		// Local read finished (we already sent F). Wait for peer's F, bounded.
		select {
		case <-sink.remoteFin:
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
	case <-sink.writeErr:
		// Downstream write to local socket failed; nothing more to do.
	case <-ctx.Done():
	}
}

// ── flags + config plumbing ──────────────────────────────────────────────────

func loadConfig(path string, socks, resolvers, zone, serverKey, mode, profile *string, aes *bool, verbose *bool) {
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("config %q: %v", path, err)
	}
	var fc fileConfig
	if err := json.Unmarshal(b, &fc); err != nil {
		log.Fatalf("config %q: %v", path, err)
	}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	ovStr(set, "socks", socks, fc.Socks)
	ovStr(set, "resolvers", resolvers, fc.Resolvers)
	ovStr(set, "zone", zone, fc.Zone)
	ovStr(set, "server-key", serverKey, fc.ServerKey)
	ovStr(set, "mode", mode, fc.Mode)
	ovStr(set, "profile", profile, fc.Profile)
	ovBool(set, "aes", aes, fc.AES)
	ovBool(set, "v", verbose, fc.Verbose)
}

func ovStr(set map[string]bool, name string, dst, v *string) {
	if v != nil && !set[name] {
		*dst = *v
	}
}
func ovBool(set map[string]bool, name string, dst, v *bool) {
	if v != nil && !set[name] {
		*dst = *v
	}
}

func buildProfile(name, mode string) (*dns.Profile, error) {
	var base dns.Profile
	switch name {
	case "fast", "":
		base = dns.Profile{
			Name:              "fast",
			RecordTypeWeights: map[uint16]float64{16: 1.0},
			QueryIntervalMs:   []dns.Bucket{{Min: 0, Max: 5, Weight: 1.0}},
			BurstSize:         []dns.Bucket{{Min: 4, Max: 8, Weight: 1.0}},
			IdleGapMs:         []dns.Bucket{{Min: 5, Max: 25, Weight: 1.0}},
			CoverQueryRate:    0.0,
		}
	case "standard":
		base = dns.ProfileStandardDNS
	case "doh":
		base = dns.ProfileDoHMix
	case "stealth":
		base = dns.ProfileHighStealth
	default:
		return nil, fmt.Errorf("unknown profile %q (want fast|standard|doh|stealth)", name)
	}
	base.LabelEntropyMode = mode
	return &base, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePubKey(s string) ([crypto.KeySize]byte, error) {
	var pub [crypto.KeySize]byte
	if strings.TrimSpace(s) == "" {
		return pub, errors.New("required (the server prints its pubkey on startup)")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return pub, err
	}
	if len(raw) != crypto.KeySize {
		return pub, fmt.Errorf("want %d bytes (%d hex chars), got %d", crypto.KeySize, crypto.KeySize*2, len(raw))
	}
	copy(pub[:], raw)
	return pub, nil
}
