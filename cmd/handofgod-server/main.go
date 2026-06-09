// Command handofgod-server is the authoritative-side Hand of God endpoint. It
// listens for DNS queries, completes the handshake-over-DNS for new clients,
// delivers received application data, and echoes it back downstream (a simple,
// self-evident default that proves the full path end to end).
//
// Configuration precedence: built-in defaults < -config JSON file < explicit flags.
// On startup it prints the server's static public key; pin that in clients via
// handofgod-client -server-key.
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

// fileConfig mirrors the flags for JSON config loading. Pointers distinguish
// "absent" from "zero value" so only present keys override flag defaults.
type fileConfig struct {
	Listen  *string `json:"listen"`
	Zone    *string `json:"zone"`
	Key     *string `json:"key"`
	Mode    *string `json:"mode"`
	AES     *bool   `json:"aes"`
	MaxRate *int    `json:"maxrate"`
	Jitter  *bool   `json:"jitter"`
	Verbose *bool   `json:"verbose"`
}

func main() {
	listen := flag.String("listen", ":5353", "UDP address to serve DNS on (use :53 in production; needs privileges)")
	zone := flag.String("zone", "v.example.com", "authoritative zone this server answers for")
	keyPath := flag.String("key", "handofgod-server.key", "static key file (hex private key; created if missing)")
	mode := flag.String("mode", "raw", "label entropy mode: raw|padded|ngram (clients must match)")
	aes := flag.Bool("aes", false, "advertise AES-256-GCM (negotiated if the client also advertises it)")
	maxRate := flag.Int("maxrate", 0, "max tunnel queries/min before serving cover-only (0 = unlimited)")
	jitter := flag.Bool("jitter", true, "add response-timing jitter to mimic real authoritative servers")
	verboseFlag := flag.Bool("v", false, "verbose logging")
	configPath := flag.String("config", "", "JSON config file (explicit flags override its values)")
	flag.Parse()

	loadConfig(*configPath, listen, zone, keyPath, mode, aes, maxRate, jitter, verboseFlag)
	verbose = *verboseFlag

	static, err := loadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatalf("static key: %v", err)
	}
	log.Printf("Hand of God server | zone=%q listen=%q mode=%q aes=%v jitter=%v", *zone, *listen, *mode, *aes, *jitter)
	log.Printf("pubkey=%s", hex.EncodeToString(static.Public[:]))
	log.Printf("(pin the pubkey above in clients: handofgod-client -server-key <pubkey>)")

	caps := uint16(0x04) // SACK
	if *aes {
		caps |= crypto.CapAEADAESGCM
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var lis *transport.Listener
	lis = transport.NewListener(ctx, transport.ListenerConfig{
		ServerStatic: static,
		Caps:         caps,
		Zone:         *zone,
		OnData: func(sid, stream uint16, data []byte) {
			log.Printf("[session %04x stream %d] recv %d bytes: %q", sid, stream, len(data), preview(data))
			if s := lis.Manager().Get(sid); s != nil {
				s.Write(stream, data) // echo back downstream
			}
		},
		OnAccept: func(_ *transport.ServerSession, sid uint16) {
			log.Printf("session %04x established", sid)
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
		go heartbeat(ctx, func() { vlogf("sessions=%d", lis.Manager().Count()) })
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

func loadConfig(path string, listen, zone, key, mode *string, aes *bool, maxRate *int, jitter, verbose *bool) {
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

// loadOrCreateKey loads a hex-encoded static private key from path, or generates
// and persists a new one (0600) if the file is absent.
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

func preview(b []byte) string {
	const max = 80
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
