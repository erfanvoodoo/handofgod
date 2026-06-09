# Deploying a Hand of God server

This guide covers running `handofgod-server` as a real authoritative DNS endpoint
so clients can reach it through ordinary recursive resolvers.

> **Authorized use only.** Run this only on networks and domains you own or are
> explicitly permitted to test. Tunneling over DNS may violate acceptable-use
> policies; you are responsible for compliance.

---

## How it fits together

```
handofgod-client ──query──▶ recursive resolver ──delegated──▶ your authoritative
                 ◀─answer──   (e.g. 1.1.1.1)     NS lookup      handofgod-server
```

The client asks a normal recursive resolver for names under a zone you control
(say `t.example.com`). You delegate that zone to your server via `NS` records, so
the resolver forwards the queries to your `handofgod-server`, which answers them.
Upstream data rides in the query names; downstream rides in the TXT responses
(uncacheable, TTL 0).

You need:
- A domain you control (e.g. `example.com`) and access to edit its DNS.
- A host with a **public IP** that can listen on **UDP/53**.
- Inbound **UDP/53** open in the host/cloud firewall.

---

## 1. Build

On a build machine with Go ≥ 1.21, from the repository root:

```bash
go build -o bin/ ./cmd/handofgod-server ./cmd/handofgod-client
```

The binaries are static (no CGO) and cross-compile, e.g. for a Linux server:

```bash
GOOS=linux GOARCH=amd64 go build -o handofgod-server ./cmd/handofgod-server
```

Copy `handofgod-server` to your host.

---

## 2. Delegate a zone to your server

Pick a subdomain to dedicate, e.g. `t.example.com`. At your DNS provider for
`example.com`, add a delegation with a glue `A` record pointing at your server:

```
t.example.com.        IN  NS   ns1.t.example.com.
ns1.t.example.com.    IN  A    203.0.113.10        ; your server's public IP
; optional IPv6 glue:
ns1.t.example.com.    IN  AAAA 2001:db8::10
```

Now any resolver that looks up `*.t.example.com` will forward to your server.

---

## 3. Run the server

`:53` is privileged. On Linux, grant the binary the capability instead of running
as root:

```bash
sudo setcap 'cap_net_bind_service=+ep' ./handofgod-server

./handofgod-server \
    -listen :53 \
    -zone   t.example.com \
    -key    /etc/handofgod/server.key \
    -mode   raw          # or padded | ngram (clients must match)
```

On first run it generates `/etc/handofgod/server.key` (chmod 600) and prints:

```
pubkey=0ebcaab1fb5c7a9fc5f703b48f7f360d12ad5467ad77374c85fe5053f4b78926
```

**Save that public key** — clients pin it. It is stable across restarts as long
as the key file is kept.

### systemd unit (optional)

```ini
# /etc/systemd/system/handofgod.service
[Unit]
Description=Hand of God DNS transport server
After=network.target

[Service]
ExecStart=/usr/local/bin/handofgod-server -config /etc/handofgod/server.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
DynamicUser=yes
StateDirectory=handofgod

[Install]
WantedBy=multi-user.target
```

With `/etc/handofgod/server.json`:

```json
{
  "listen": ":53",
  "zone":   "t.example.com",
  "key":    "/var/lib/handofgod/server.key",
  "mode":   "raw",
  "maxrate": 600,
  "jitter":  true
}
```

(Explicit flags override config-file values.)

---

## 4. Verify

From anywhere:

```bash
# Delegation is live (should list ns1.t.example.com):
dig +short NS t.example.com

# Your server answers (a cover response for a non-Hand-of-God name):
dig @1.1.1.1 A www.t.example.com
```

Then connect a client (pin the pubkey from step 3):

```bash
handofgod-client \
    -resolvers 1.1.1.1:53,8.8.8.8:53 \
    -zone t.example.com \
    -mode raw \
    -server-key 0ebcaab1...b78926 \
    -msg "hello over the internet"
# [stream 1] hello over the internet   ← echoed back through DNS
```

Listing several `-resolvers` spreads traffic across multiple recursive resolvers
(multi-path), which survives some of them blocking or failing.

---

## 5. Operational notes

- **Stealth tuning.** `-mode` controls label appearance (`ngram` is the most
  innocuous, lowest throughput); the client `-profile` (`fast|standard|doh|stealth`)
  controls query timing; the server `-maxrate` caps tunnel volume before it serves
  cover-only. `-jitter` adds authoritative-like response delay. The client `-mode`
  must match the server `-mode` (it is not negotiated on the wire).
- **AEAD.** Add `-aes` on both sides to negotiate AES-256-GCM; otherwise
  ChaCha20-Poly1305.
- **Sessions** time out after 10 min idle (reaped) and on explicit close. Many
  clients are multiplexed by session id automatically.
- **No caching of data.** Data responses use TTL 0; cover responses look like a
  normal small zone (SOA/NS/A/AAAA/TXT).
- **Logging.** `-v` adds debug logs (session counts, path health). Logs go to
  stderr; capture with your service manager.
- **Throughput.** This is a low-throughput, reliability-first transport. Expect
  modest rates — it is a fallback for when normal transports are blocked.

---

## 6. Known limitations before hostile-network use

- Validate against your actual resolver path; some resolvers cap response sizes or
  rewrite records. (Data responses are TTL 0 to avoid caching of retransmits.)
- MTU discovery is not yet active — keep application writes small (the encoder
  rejects datagrams that would exceed the 253-char DNS name limit).
- The handshake is protected by a return-routability cookie against blind floods,
  but a determined on-path attacker is bounded only by `-maxrate`.
