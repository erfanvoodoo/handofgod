// Command handofgod-proxy-server is a Hand of God carrier endpoint that forwards
// each accepted stream to a real TCP destination — i.e. it turns Hand of God into
// a TCP forwarder reachable through ordinary DNS resolvers. It uses the
// transport.Listener primitive from the carrier and adds an application-layer
// CONNECT/data/EOF protocol on top (see tunnel.go).
//
// One Hand of God session ↔ one SOCKS5 connection on the client side ↔ one
// remote TCP socket here.
//
// Configuration precedence: built-in defaults < -config JSON file < explicit flags.
// On startup it prints the server's static public key; pin that in clients via
// handofgod-proxy-client -server-key.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/handofgod/crypto"
	"github.com/handofgod/dns"
	"github.com/handofgod/transport"
	"github.com/handofgod/wire"
)

var verbose bool

func vlogf(format string, a ...any) {
	if verbose {
		log.Printf("[debug] "+format, a...)
	}
}

type fileConfig struct {
	Listen    *string `json:"listen"`
	Zone      *string `json:"zone"`
	Key       *string `json:"key"`
	Mode      *string `json:"mode"`
	AES       *bool   `json:"aes"`
	MaxRate   *int    `json:"maxrate"`
	Jitter    *bool   `json:"jitter"`
	AllowDest *string `json:"allow_dest"`
	Verbose   *bool   `json:"verbose"`
}

func main() {
	listen := flag.String("listen", ":5353", "UDP address to serve DNS on (use :53 in production)")
	zone := flag.String("zone", "v.example.com", "authoritative zone this server answers for")
	keyPath := flag.String("key", "handofgod-proxy-server.key", "static key file (hex private key; created if missing)")
	mode := flag.String("mode", "raw", "label entropy mode: raw|padded|ngram (clients must match)")
	aes := flag.Bool("aes", false, "advertise AES-256-GCM (negotiated if the client also advertises it)")
	maxRate := flag.Int("maxrate", 0, "max tunnel queries/min before serving cover-only (0 = unlimited)")
	jitter := flag.Bool("jitter", true, "add response-timing jitter to mimic real authoritative servers")
	allowDest := flag.String("allow-dest", "", "if set, only allow CONNECT to this exact host:port (MVP allow-list)")
	verboseFlag := flag.Bool("v", false, "verbose logging")
	configPath := flag.String("config", "", "JSON config file (explicit flags override its values)")
	flag.Parse()

	loadConfig(*configPath, listen, zone, keyPath, mode, aes, maxRate, jitter, allowDest, verboseFlag)
	verbose = *verboseFlag

	static, err := loadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatalf("static key: %v", err)
	}
	log.Printf("Hand of God proxy-server | zone=%q listen=%q mode=%q aes=%v jitter=%v allow-dest=%q",
		*zone, *listen, *mode, *aes, *jitter, *allowDest)
	log.Printf("pubkey=%s", hex.EncodeToString(static.Public[:]))
	log.Printf("(pin the pubkey above in clients: handofgod-proxy-client -server-key <pubkey>)")

	caps := uint16(0x04) // SACK
	if *aes {
		caps |= crypto.CapAEADAESGCM
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := newTunnelHandler(*allowDest, *zone, *mode, vlogf)
	defer handler.shutdown()

	var lis *transport.Listener
	lis = transport.NewListener(ctx, transport.ListenerConfig{
		ServerStatic: static,
		Caps:         caps,
		Zone:         *zone,
		OnAccept:     handler.onAccept,
		OnData: func(sid, stream uint16, data []byte) {
			sess := lis.Manager().Get(sid)
			if sess == nil {
				return // session was evicted between dispatch and lookup
			}
			handler.onData(sess, sid, stream, data)
		},
	})

	zc := dns.DefaultZoneConfig()
	zc.Zone = *zone
	zc.MaxQueryRatePerMin = *maxRate
	srv := wire.NewServer(wire.ServerConfig{
		Zone:    *zone,
		Mode:    *mode,
		Handler: lis.HandleUpstream,
		Mimic:   dns.NewServerMimic(zc),
		Jitter:  *jitter,
	})

	if verbose {
		go heartbeat(ctx, func() {
			vlogf("sessions=%d tunnels=%d", lis.Manager().Count(), handler.activeCount())
		})
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Print("shutting down")
		_ = srv.Shutdown()
		cancel()
	}()

	log.Printf("listening on %s/udp", *listen)
	if err := srv.ListenAndServe(*listen); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func loadConfig(path string, listen, zone, key, mode *string, aes *bool, maxRate *int, jitter *bool, allowDest *string, verbose *bool) {
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
	ovStr(set, "listen", listen, fc.Listen)
	ovStr(set, "zone", zone, fc.Zone)
	ovStr(set, "key", key, fc.Key)
	ovStr(set, "mode", mode, fc.Mode)
	ovBool(set, "aes", aes, fc.AES)
	ovInt(set, "maxrate", maxRate, fc.MaxRate)
	ovBool(set, "jitter", jitter, fc.Jitter)
	ovStr(set, "allow-dest", allowDest, fc.AllowDest)
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
func ovInt(set map[string]bool, name string, dst, v *int) {
	if v != nil && !set[name] {
		*dst = *v
	}
}

func heartbeat(ctx context.Context, fn func()) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}

// loadOrCreateKey mirrors handofgod-server's behavior: load hex private key
// from path, or generate and persist a new one (0600) if absent.
func loadOrCreateKey(path string) (*crypto.KeyPair, error) {
	if b, err := os.ReadFile(path); err == nil {
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != crypto.KeySize {
			return nil, fmt.Errorf("invalid key file %q (want %d hex bytes)", path, crypto.KeySize)
		}
		var priv [crypto.KeySize]byte
		copy(priv[:], raw)
		return crypto.KeyPairFromPrivate(priv)
	}
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(kp.Private[:])+"\n"), 0o600); err != nil {
		return nil, err
	}
	log.Printf("generated a new static key at %q", path)
	return kp, nil
}
