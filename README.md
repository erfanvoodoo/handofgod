<<<<<<< HEAD
# HandofGod
A reliable, authenticated transport protocol that tunnels data over DNS. Uses Noise NK handshake (X25519), ChaCha20-Poly1305 or AES-256-GCM encryption, sliding-window ARQ with SACK, and multi-path scheduling across resolvers. Shaped traffic mimics ordinary DNS. Works where TCP, UDP, and QUIC are blocked.
=======
# Hand of God

**A reliable, authenticated, multi-path transport protocol over DNS.**

Hand of God provides robust data transport in environments with high packet loss,
variable latency, or limited connectivity options. It is designed as a resilient
fallback mechanism when traditional transports (TCP, UDP, QUIC) are blocked or
unreliable — for example, where only DNS resolution escapes a restrictive
network.

This repository implements the full protocol (Phases 1–4) plus ready-to-run
client and server binaries (`cmd/`) — a complete, working client↔server data
path over real UDP/53, including the handshake, multi-path reliability, stealth
shaping, multi-session routing, and teardown.

---

## Motivation

Traditional DNS tunneling tools exist, but Hand of God was built from the ground up
with a strong emphasis on correctness, modern cryptography, and measurable
reliability.

Key design goals:

- **Strong default security** — forward secrecy and authenticated encryption, always on.
- **High reliability** — custom ARQ with intelligent multi-path scheduling.
- **A clear, formal protocol specification** ([`PROTOCOL.md`](PROTOCOL.md)).
- **Built-in observability** — every reliability and path decision emits a metric.
- **Stealth** — traffic shaped to resemble ordinary DNS, tunable against detectability.

Hand of God builds on proven techniques — multi-path redundancy, adaptive
retransmission, per-path health monitoring — while modernizing the cryptographic,
reliability, and traffic-shaping layers.

---

## Components

| Package | Responsibility | Status |
|---|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | Wire format & state machine spec (§1–§13) | Complete |
| `crypto/` | X25519 NK handshake, HKDF, ChaCha20-Poly1305 AEAD, sliding-window replay | Tested |
| `frame/` | Datagram framing, SACK serialization | Tested |
| `arq/` | Sliding-window ARQ, adaptive RTO (RFC 6298 + Karn), reordering, dedup | Tested |
| `path/` | Path scoring, MTU tracking, multi-path scheduling, health failover & recovery | Tested |
| `metrics/` | Goodput, retransmit ratio, duplication waste, stealth cost | Implemented |
| `dns/` | DNS encoding (FQDN/TXT/HTTPS), label-entropy codecs, traffic profiles, query scheduler, server mimicry, adaptive controller | Tested |
| `transport/` | End-to-end `Session` / `ServerSession` tying the layers together | Tested |
| `wire/` | `github.com/miekg/dns` adapter — real UDP send/serve | Tested |

---

## Security Model

- **Handshake:** Noise NK pattern with X25519. The client pins the server's
  static public key for authentication and gets forward secrecy from an
  ephemeral-ephemeral DH.
- **AEAD:** ChaCha20-Poly1305 by default; AES-256-GCM is negotiated when both
  peers advertise it (cap bit 0). Both share the 32-byte key / 12-byte nonce /
  16-byte tag, so framing is identical.
- **Nonces:** deterministically derived from direction and sequence number, never
  transmitted (saves 12 bytes/datagram). Reliable and unreliable frames use
  disjoint sequence sub-spaces (distinguished by the seq high bit) so nonces never
  repeat while reliable data stays contiguous for in-order delivery.
- **Replay protection:** an independent sliding window per sequence class.

Per-datagram overhead is minimal: **26 bytes** (session ID + sequence number +
AEAD tag) plus a 3-byte frame header.

---

## Reliability Model

Hand of God's reliability layer is validated by simulation. In a test channel with 30%
loss across 3 paths with reordering and duplication, it delivers all frames in
order:

```
delivered 2000 frames over 30%-loss 3-path channel; retransmits=51 duplicates=2243
```

The duplicates are intentional multi-path redundancy, correctly deduplicated by
the receiver. Core mechanisms:

- Sliding send window with Selective Acknowledgments (SACK).
- RFC 6298 adaptive retransmission timeout (RTO) with Karn's algorithm.
- Exponential backoff on retransmission.
- Receiver-side reordering buffer with duplicate suppression.
- Coalesced acknowledgments (one up-to-date cumulative ACK per send opportunity,
  not one per data frame).

---

## Multi-Path Model

Hand of God carries one session across many independent paths (resolver × domain).
Each reliable frame is transmitted on the best `K` paths by real-time score, and
the receiver's ARQ deduplication ensures the application sees it once — trading
bandwidth for blackout survival.

Paths are scored continuously on loss rate (EWMA), latency (percentiles), and
throughput. A path with sustained consecutive failures is marked unhealthy and
excluded; because an excluded path gets no scheduled traffic, it is **re-probed
out-of-band** (a PING sent directly to it) so a recovered path can rejoin. The
usable path set can grow back, not just shrink.

---

## DNS Encoding & Stealth (Phase 2–3)

Hand of God frames are opaque bytes to this layer, which maps them onto real DNS
messages and shapes the query stream to look ordinary.

- **Query encoding:** upstream datagrams ride in the query name
  (`<data>.<session>.<zone>`); downstream rides base64url-encoded in TXT RDATA.
- **Label-entropy codecs** (reversible, selected per profile):
  - `raw` — base32hex (dense, but a high-entropy fingerprint).
  - `padded` — length-prefixed, block-padded base32hex (hides exact size).
  - `ngram` — order-1 Markov coding into pronounceable, word-like labels.
- **Traffic profiles** describe target statistics (record-type mix, burst/idle
  timing, cover-query rate, entropy mode); the **scheduler** emits queries at
  profile-shaped timing and fills idle slots with cover.
- **Server mimicry** presents a plausible authoritative nameserver (SOA/NS/A/
  AAAA/TXT/HTTPS cover, NXDOMAIN out-of-zone), with a query-rate circuit breaker
  and response-timing jitter.
- **Adaptive controller** escalates the active profile (standard → DoH-like →
  maximum stealth) on observed loss/latency/blackout and de-escalates with
  hysteresis — driven by live path-engine health.

---

## DNS Wire Adapter

The `wire/` package is the only one that imports `github.com/miekg/dns`; every
other package stays wire-agnostic via a neutral query/response representation.

- **Client** turns queries into real DNS messages over UDP, feeds downstream
  datagrams from responses back into the transport, and bounds in-flight
  round-trips (non-blocking backpressure).
- **Server** is an authoritative handler: it decodes the upstream datagram from
  the query name, drives the Hand of God server, attaches a downstream datagram to the
  response, and serves cover otherwise.

The full path — handshake, framing, encryption, ARQ, multi-path, encoding,
scheduling — is exercised end-to-end over a UDP loopback in `transport/`'s tests.

---

## Usage

**Server** — present an authoritative endpoint that mints sessions on demand:

```go
serverStatic, _ := crypto.GenerateKeyPair() // its .Public is pinned in clients

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

lis := transport.NewListener(ctx, transport.ListenerConfig{
    ServerStatic: serverStatic,
    Caps:         0x04, // SACK
    Zone:         "v.example.com",
    OnData: func(sessionID, stream uint16, data []byte) {
        // application data arrived on `stream` of session `sessionID`
    },
})

srv := wire.NewServer(wire.ServerConfig{
    Zone:    "v.example.com",
    Mode:    "raw",            // label-entropy mode; clients must match
    Handler: lis.HandleUpstream,
})
log.Fatal(srv.ListenAndServe(":53"))
```

**Client** — `Dial` performs the handshake (incl. the cookie round-trip) knowing
only the server's pinned static public key:

```go
eng := path.NewEngine(path.DefaultConfig())
// One (resolver, domain) path. Point the resolver at a recursive resolver that
// can reach your authoritative server — or, for a direct test, at the server.
eng.AddPath("8.8.8.8:53", "v.example.com", 0.5, 0.3, 0.2)

wcli := wire.NewClient(wire.ClientConfig{})

sess, err := transport.Dial(transport.DialConfig{
    ServerStaticPub: serverStaticPub, // pinned out of band
    Caps:            0x04,
    Zone:            "v.example.com",
    Mode:            "raw",
    Engine:          eng,
    RoundTrip:       wcli.RoundTrip, // handshake (synchronous)
    WireSend:        wcli.Send,      // established session (async)
    Deliver:         func(stream uint16, data []byte) { /* downstream data */ },
})
if err != nil {
    log.Fatal(err)
}

// Route downstream responses into the session, then run it.
wcli.SetInbound(func(dg []byte, p *path.Path) { sess.HandleInbound(dg, p) })
go sess.Run(ctx)

sess.Write(1, []byte("hello over dns"))
// ... when done:
sess.Close(0) // 0 = NORMAL
```

For a client multiplexing several sessions over one `wire.Client`, register each
`Dial`ed session in a `transport.ClientRouter` and use `router.Inbound` as the
client's inbound handler (the server side uses `ServerManager`/`Listener`, which
route automatically).

### Command-line binaries

Two ready-to-run programs live under `cmd/` (the server echoes received data back,
so you can prove the full path). For a real internet deployment — delegating an
authoritative zone to your server — see **[DEPLOY.md](DEPLOY.md)**.

```bash
go build -o bin/ ./cmd/handofgod-server ./cmd/handofgod-client

# Server — generates/persists a static key and prints its public key to pin:
./bin/handofgod-server -listen :5353 -zone v.example.com -mode raw
#   ... pubkey=736af04330423e97d24012e9d8b7b1d02a0c17846370070846bec77c67f45d20

# Client — pin that pubkey; -resolvers are the DNS servers to query (recursive
# resolvers that reach the authoritative server, or the server itself for a test):
./bin/handofgod-client -resolvers 127.0.0.1:5353 -zone v.example.com \
    -mode raw -server-key 736af0...f45d20 -msg "hello hand of god"
#   [stream 1] hello hand of god        ← the server's echo, round-tripped over DNS
```

Omit `-msg` for an interactive client (reads stdin lines). `:53` needs privileges;
any high port works for testing.

**Flags** (both accept `-config <file>` for a JSON config; explicit flags override it):

| `handofgod-server` | `handofgod-client` | Meaning |
|---|---|---|
| `-listen :53` | `-resolvers a:53,b:53` | where to serve / comma-separated resolvers (multi-path) |
| `-zone` | `-zone` | authoritative zone (must match) |
| `-key <file>` | `-server-key <hex>` | server static key file / pinned server public key |
| `-mode raw\|padded\|ngram` | `-mode` | label entropy mode (must match) |
| `-aes` | `-aes` | advertise AES-256-GCM (negotiated if both do) |
| `-maxrate N` | `-profile fast\|standard\|doh\|stealth` | server volume cap / client timing shape |
| `-jitter` | `-msg "..."` | response jitter / one-shot message (else stdin) |
| `-v` | `-v` | verbose logging |

Example JSON config (`-config server.json`):

```json
{ "listen": ":53", "zone": "t.example.com", "key": "/var/lib/handofgod/server.key",
  "mode": "ngram", "maxrate": 600, "jitter": true }
```

---

## Repository Layout

> "Hand of God" was previously code-named *Warren*; the Go module is
> `github.com/handofgod`.

```
cmd/handofgod-server/   authoritative server binary
cmd/handofgod-client/   client binary
crypto/                 NK handshake, HKDF, ChaCha20-Poly1305 / AES-256-GCM, replay
frame/                  datagram framing, SACK serialization
arq/                    sliding-window ARQ, adaptive RTO, reorder/dedup
path/                   path scoring, multi-path scheduling, failover & recovery
metrics/                goodput, retransmit ratio, stealth cost
dns/                    FQDN/TXT encoding, label codecs, profiles, scheduler,
                        server mimicry, adaptive controller
transport/              Session / ServerSession / Listener / routers — the glue
wire/                   miekg/dns adapter (real UDP send/serve)
PROTOCOL.md             wire format & state machine specification (§1–§13)
DEPLOY.md               how to run a server on a real authoritative DNS zone
```

---

## Building and Testing

```bash
go build -o bin/ ./cmd/...   # build the client + server binaries into bin/
go test ./...                # run all tests
go vet ./...                 # static analysis
go test -race ./...          # race detector (needs a C compiler)
```

Hand of God has two direct dependencies — `golang.org/x/crypto` (cryptography) and
`github.com/miekg/dns` (DNS wire encoding, used only by the `wire/` adapter) —
both vendored, and **no CGO**. It cross-compiles easily to Linux, Windows, macOS,
and Android.

---

## Roadmap

- **Phase 1 — Transport core.** Specification, cryptography, ARQ, multi-path
  logic, metrics. ✅ Complete.
- **Phase 2 — DNS encoding layer.** FQDN/TXT/HTTPS encoding, traffic profiles,
  query scheduler, server mimicry. ✅ Complete.
- **Phase 3 — Advanced encoding & traffic shaping.** Reversible n-gram/padded
  label codecs, adaptive profile controller, end-to-end transport glue, and the
  miekg/dns wire adapter. ✅ Complete.
- **Phase 4 — Integration & hardening.** Handshake-over-DNS with a
  return-routability cookie, multi-session routing (server and client), session
  teardown + idle reaper, coalesced ACKs, bounded wire concurrency, and
  uncacheable data responses. ✅ Complete.

The suite passes under the race detector (`go test -race ./...`). Before exposing
it on the open internet, one check remains that needs a different environment: an
end-to-end run against a real recursive resolver with the authoritative server
deployed.

---

## Use Cases

- Networks with high loss rates (satellite, long-distance wireless, congested links).
- Censorship-circumvention where only DNS escapes the network.
- Research into resilient transport protocols.
- Applications needing reliable communication under challenging network conditions.

Hand of God is not designed for high-throughput scenarios. It prioritizes reliability
and availability when other protocols struggle.

---

## License

MIT.
>>>>>>> 03074ff (Initial commit)
