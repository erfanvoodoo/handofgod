// Command handofgod-client establishes a Hand of God session over DNS to a
// server (knowing only its pinned static public key) and exchanges application
// data. By default it reads lines from stdin and prints replies; with -msg it
// sends one message and prints the reply.
//
// Configuration precedence: built-in defaults < -config JSON file < explicit flags.
//
//	handofgod-client -resolvers 1.1.1.1:53,8.8.8.8:53 -zone v.example.com \
//	    -server-key <hex> -profile fast -msg "hello"
//
// -resolvers is a comma-separated list of DNS servers to query (each becomes a
// multi-path route): recursive resolvers that can reach the authoritative
// Hand of God server, or (for a direct test) the server itself.
package main

import (
	"bufio"
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
	"github.com/handofgod/path"
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
	Resolvers *string `json:"resolvers"`
	Zone      *string `json:"zone"`
	ServerKey *string `json:"server_key"`
	Mode      *string `json:"mode"`
	Profile   *string `json:"profile"`
	AES       *bool   `json:"aes"`
	Verbose   *bool   `json:"verbose"`
}

func main() {
	resolvers := flag.String("resolvers", "127.0.0.1:5353", "comma-separated DNS resolver addresses (each is a multi-path route)")
	zone := flag.String("zone", "v.example.com", "authoritative zone")
	serverKey := flag.String("server-key", "", "server static public key, hex (REQUIRED; printed by the server)")
	mode := flag.String("mode", "raw", "label entropy mode: raw|padded|ngram (must match the server)")
	profile := flag.String("profile", "fast", "traffic profile: fast|standard|doh|stealth (timing/cover shape)")
	aes := flag.Bool("aes", false, "advertise AES-256-GCM")
	msg := flag.String("msg", "", "send this one message then exit; if empty, read lines from stdin")
	verboseFlag := flag.Bool("v", false, "verbose logging")
	configPath := flag.String("config", "", "JSON config file (explicit flags override its values)")
	flag.Parse()

	loadConfig(*configPath, resolvers, zone, serverKey, mode, profile, aes, verboseFlag)
	verbose = *verboseFlag

	pub, err := parsePubKey(*serverKey)
	if err != nil {
		log.Fatalf("-server-key: %v", err)
	}
	prof, err := buildProfile(*profile, *mode)
	if err != nil {
		log.Fatalf("-profile: %v", err)
	}

	caps := uint16(0x04) // SACK
	if *aes {
		caps |= crypto.CapAEADAESGCM
	}

	eng := path.NewEngine(path.DefaultConfig())
	routes := splitList(*resolvers)
	if len(routes) == 0 {
		log.Fatal("-resolvers: at least one resolver address is required")
	}
	for _, r := range routes {
		eng.AddPath(r, *zone, 0.5, 0.3, 0.2)
	}

	// The entropy mode is deployment-fixed (not on the wire), so pin it across all
	// adaptive levels; the controller may vary timing, never the mode.
	ctrl := dns.NewAdaptiveController(dns.DefaultAdaptiveConfig())
	ctrl.SetProfile(dns.LevelStandard, prof)
	ctrl.SetProfile(dns.LevelElevated, prof)
	ctrl.SetProfile(dns.LevelMax, prof)

	wcli := wire.NewClient(wire.ClientConfig{Timeout: 5 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := transport.Dial(transport.DialConfig{
		ServerStaticPub: pub,
		Caps:            caps,
		Zone:            *zone,
		Mode:            *mode,
		Engine:          eng,
		Controller:      ctrl,
		RoundTrip:       wcli.RoundTrip,
		WireSend:        wcli.Send,
		Deliver: func(stream uint16, data []byte) {
			fmt.Printf("[stream %d] %s\n", stream, string(data))
		},
		OnClose: func(code byte) { log.Printf("session closed by server (code %d)", code) },
	})
	if err != nil {
		log.Fatalf("dial via %v: %v", routes, err)
	}
	wcli.SetInbound(func(dg []byte, p *path.Path) { sess.HandleInbound(dg, p) })
	go sess.Run(ctx)
	log.Printf("session %04x established via %d resolver(s) (zone %q, mode %q, profile %q)",
		sess.SessionID(), len(routes), *zone, *mode, *profile)

	if verbose {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					st := sess.Stats()
					vlogf("inflight=%d delivered=%d healthyPaths=%d level=%s", st.InFlight, st.Delivered, st.HealthyPaths, st.Level)
				}
			}
		}()
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		sess.Close(0)
		cancel()
		os.Exit(0)
	}()

	if *msg != "" {
		sess.Write(1, []byte(*msg))
		time.Sleep(2 * time.Second) // give the reply time to arrive
		sess.Close(0)
		return
	}

	sc := bufio.NewScanner(os.Stdin)
	log.Print("connected; type lines to send (Ctrl-D to quit)")
	for sc.Scan() {
		if line := sc.Bytes(); len(line) > 0 {
			sess.Write(1, append([]byte(nil), line...))
		}
	}
	time.Sleep(1500 * time.Millisecond) // let in-flight replies arrive before closing
	sess.Close(0)
	time.Sleep(200 * time.Millisecond) // let the SESSION_CLOSE flush
}

func loadConfig(path string, resolvers, zone, serverKey, mode, profile *string, aes, verbose *bool) {
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

// buildProfile returns a traffic profile for the named shape, with its label
// entropy mode pinned to the deployment mode (which must match the server).
func buildProfile(name, mode string) (*dns.Profile, error) {
	var base dns.Profile
	switch name {
	case "fast", "":
		base = dns.Profile{
			Name:              "fast",
			RecordTypeWeights: map[uint16]float64{16: 1.0}, // TXT carries data + downstream
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
	base.LabelEntropyMode = mode // mode is deployment-fixed; pin it regardless of the profile's own
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
		return pub, fmt.Errorf("required (the server prints its pubkey on startup)")
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
