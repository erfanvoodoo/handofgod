# Hand of God Protocol Specification v1

A reliable, authenticated, multi-path transport designed to run over DNS as a
last-resort censorship-circumvention layer. This document specifies the wire
format and state machine in enough detail for an independent implementation
without reading the reference source.

This document specifies the transport core (framing, crypto, reliability, path
management) in §1–§12, and the DNS encoding / stealth-mimicry layer (Phase 2–3)
in §13. The DNS layer sits *below* this transport — Hand of God frames are opaque
byte strings to it.

---

## 1. Design Goals

1. **Reliability over an unreliable substrate.** DNS is lossy, reordering,
   duplicating UDP. Hand of God provides in-order, deduplicated, retransmitted
   delivery via ARQ.
2. **Authenticated confidentiality by default.** All payload bytes are protected
   by an AEAD. There is no unauthenticated or plaintext mode in mainstream builds.
3. **Forward secrecy.** Session keys are derived from ephemeral X25519 keys and
   cannot be recovered from the server's long-term key alone.
4. **Multi-path.** A single logical session may be carried across many DNS
   resolver+domain paths simultaneously, with duplication for blackout survival.
5. **Measurability.** Every reliability and path decision emits a metric.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| Session | One authenticated client↔server association, identified by a 2-byte Session ID |
| Stream | One multiplexed bidirectional byte stream within a session (2-byte Stream ID) |
| Frame | The atomic protocol unit. Exactly one frame per DNS message |
| Path | One (resolver, domain) tuple over which frames travel |
| Datagram | The on-wire encrypted representation of one frame |

---

## 3. Cryptography

### 3.1 Primitives

- **Key agreement:** X25519 (RFC 7748)
- **KDF:** HKDF-SHA256 (RFC 5869)
- **AEAD:** ChaCha20-Poly1305 (RFC 8439), 256-bit key, 96-bit nonce, 128-bit tag
- **Server authentication:** static X25519 key, pinned in the client config

AES-256-GCM is permitted as an alternative AEAD for platforms with hardware AES.
It is selected only when **both** peers advertise it via cap bit 0 (§3.4);
otherwise the session uses ChaCha20-Poly1305, which is the default and
mandatory-to-implement. AES-256-GCM uses the same 256-bit key, 96-bit nonce, and
128-bit tag, so the datagram format is unchanged. The handshake messages
themselves (§3.2) always use ChaCha20-Poly1305 — the caps are exchanged *inside*
the handshake, so the negotiated AEAD can only apply to post-handshake traffic.

### 3.2 Handshake

A two-message handshake based on the Noise NK pattern (server static key known
to client; client is anonymous). Provides server authentication and forward
secrecy.

Let:
- `S_s`, `S_p` = server static private / public key (S_p pinned in client config)
- `e_s`, `e_p` = client ephemeral private / public key (fresh per handshake)
- `f_s`, `f_p` = server ephemeral private / public key (fresh per handshake)

**Message 1 (client → server), HANDSHAKE_INIT:**

```
es = X25519(e_s, S_p)                       # ephemeral-static DH
k1 = HKDF(salt="handofgod/v1/init", ikm=es, info="", len=32)
ct1 = AEAD_Seal(k1, nonce=0, plaintext=ClientHello, aad=e_p)

wire = [ version:1 = 0x01 ]
       [ msg_type:1 = 0x01 ]               # HANDSHAKE_INIT
       [ e_p : 32 ]                         # client ephemeral public key
       [ ct1 : len(ClientHello)+16 ]        # encrypted ClientHello + tag
```

`ClientHello` = `[client_random:16][caps:2]` where caps is a bitfield (see §3.4).

**Message 2 (server → client), HANDSHAKE_RESP:**

```
es = X25519(S_s, e_p)                        # server recomputes ephemeral-static
ee = X25519(f_s, e_p)                        # ephemeral-ephemeral (forward secrecy)
k2 = HKDF(salt="handofgod/v1/resp", ikm=es||ee, info="", len=32)
ct2 = AEAD_Seal(k2, nonce=0, plaintext=ServerHello, aad=f_p)

wire = [ version:1 = 0x01 ]
       [ msg_type:1 = 0x02 ]                # HANDSHAKE_RESP
       [ f_p : 32 ]                          # server ephemeral public key
       [ ct2 : len(ServerHello)+16 ]
```

`ServerHello` = `[session_id:2][server_random:16][caps:2]`.

**Session key derivation (both sides):**

```
session_secret = HKDF(salt="handofgod/v1/session",
                      ikm = es || ee,
                      info = client_random || server_random,
                      len = 64)
tx_key   = session_secret[0:32]    # client→server direction
rx_key   = session_secret[32:64]   # server→client direction
```

The client uses `tx_key` to seal and `rx_key` to open; the server does the reverse.

### 3.3 Nonce construction (no nonce on the wire)

Nonces are derived from the frame sequence number and direction. They are never
transmitted. This saves 12 bytes per datagram.

```
nonce (96-bit) = [ direction:1 ][ zero:3 ][ seq:8 (big-endian) ]
  direction = 0x00 for client→server, 0x01 for server→client
```

The 64-bit `seq` space is per-direction and never repeats within a session. A
session MUST be re-keyed (new handshake) before `seq` would exhaust (practically
never reached).

**Sequence classes.** Within a direction the `seq` space is split by its high
bit (bit 63) into two independently-incrementing sub-spaces:

- **Reliable** (bit 63 = 0): DATA / STREAM_OPEN / STREAM_CLOSE — the ARQ-tracked
  frames (§6). These stay contiguous so the receiver can deliver them in order.
- **Unreliable** (bit 63 = 1): ACK / PING / PONG / MTU / SESSION_CLOSE — frames
  that consume a `seq` only for the nonce and are never retransmitted.

Because the class bit is part of `seq`, it is part of the nonce, so nonces remain
unique across both classes (no reuse). Keeping the two spaces separate means
interleaving an unreliable frame (e.g. an ACK) does not punch a hole in the
reliable sequence and stall in-order delivery. The receiver keeps an independent
replay window per class.

### 3.4 Capability bitfield

```
bit 0 : AEAD_AESGCM       (peer supports AES-256-GCM)
bit 1 : COMPRESSION       (peer supports payload compression)
bit 2 : SACK              (peer supports selective ACK; v1 always sets this)
bits 3-15 : reserved (MUST be 0)
```

---

## 4. Datagram Format

After the handshake, every DNS message carries exactly one datagram:

```
[ session_id : 2 ]      # cleartext — server needs it to select the session key
[ seq        : 8 ]      # cleartext — doubles as AEAD nonce counter
[ ciphertext : N ]      # AEAD_Seal(key, nonce(seq,dir), frame_body, aad)
                        # where aad = session_id || seq
                        # ciphertext includes the 16-byte Poly1305 tag
```

Fixed overhead per datagram: 2 + 8 + 16 = **26 bytes**.

The decrypted `frame_body` is:

```
[ type      : 1 ]       # frame type (see §5)
[ stream_id : 2 ]       # 0x0000 for session-level frames
[ payload   : M ]       # type-specific
```

So a DATA frame's total overhead = 26 (datagram) + 3 (frame header) = 29 bytes.

> Rationale for 2-byte session IDs and stream IDs: removes the 255-session limit
> seen in prior DNS tunnels. 65,536 sessions/server and 65,536 streams/session.

---

## 5. Frame Types

| Value | Name | Reliable | Description |
|-------|------|----------|-------------|
| 0x01 | HANDSHAKE_INIT | — | Handshake message 1 (special format, §3.2) |
| 0x02 | HANDSHAKE_RESP | — | Handshake message 2 (special format, §3.2) |
| 0x10 | DATA | yes | Stream data; carries a seq, subject to ARQ |
| 0x11 | ACK | no | Selective acknowledgment (§6.2) |
| 0x20 | STREAM_OPEN | yes | Open a new stream |
| 0x21 | STREAM_CLOSE | yes | Half-close a stream (FIN semantics) |
| 0x30 | PING | no | Keepalive / RTT probe; payload = 8-byte echo token |
| 0x31 | PONG | no | RTT probe response; echoes PING token |
| 0x40 | MTU_PROBE | no | Padded frame for MTU discovery (§7) |
| 0x41 | MTU_ACK | no | Confirms largest MTU_PROBE received |
| 0x50 | SESSION_CLOSE | no | Tear down the session |

Reliable frames consume sequence numbers and are tracked by ARQ. Unreliable
frames (ACK, PING/PONG, MTU, SESSION_CLOSE) use `seq` only for the AEAD nonce and
are not retransmitted by ARQ.

---

## 6. Reliability (ARQ)

### 6.1 Sender

- Maintains a send window of up to `WindowSize` unacknowledged reliable frames.
- Each reliable frame is assigned the next monotonic `seq`.
- Unacked frames are held in a retransmission buffer with a send timestamp.
- On RTO expiry for the oldest unacked frame, that frame is retransmitted and RTO
  is doubled (exponential backoff, capped at `MaxRTO`).
- On receipt of an ACK, acknowledged frames are removed from the buffer and the
  window slides forward.

### 6.2 ACK / SACK format

The ACK frame payload (selective acknowledgment):

```
[ cumulative_ack : 8 ]   # next expected seq: all seqs strictly below are received
[ num_ranges     : 1 ]   # number of additional SACK ranges
[ range_start    : 8 ]   # repeated num_ranges times
[ range_end      : 8 ]   # inclusive range of received seqs above cumulative_ack
...
```

A receiver sends an ACK on every received DATA frame (or coalesced on a short
timer). `cumulative_ack` uses *next-expected* semantics: it is the lowest
sequence number not yet received in order, so all sequence numbers strictly
below it have been received. A value of `0` therefore means "nothing received
yet" and acknowledges nothing — this avoids the ambiguity of a "highest
received" encoding, where `0` could not distinguish "seq 0 received" from
"nothing received" and would let a sender falsely retire a lost seq 0. SACK
ranges describe out-of-order blocks received at or above `cumulative_ack`,
letting the sender retransmit only true gaps.

### 6.3 Receiver

- Maintains a reorder buffer keyed by `seq`.
- Deduplicates: a `seq` already delivered or buffered is dropped silently. (This
  is what makes multi-path duplication safe — duplicate copies are discarded.)
- Delivers contiguous in-order runs to the application as they complete.
- Tracks received seqs to build cumulative_ack and SACK ranges.

### 6.4 Adaptive RTO

RTT is sampled via DATA→ACK round trips and PING→PONG. RTO follows RFC 6298:

```
On first RTT sample R:
  SRTT   = R
  RTTVAR = R / 2
On subsequent samples R':
  RTTVAR = (1 - 1/4) * RTTVAR + (1/4) * |SRTT - R'|
  SRTT   = (1 - 1/8) * SRTT   + (1/8) * R'
RTO = clamp(SRTT + 4 * RTTVAR, MinRTO, MaxRTO)
```

DNS paths have high, variable latency; `MinRTO` defaults to 200ms, `MaxRTO` to 4s.

---

## 7. MTU Discovery

Each path has an independent usable payload size determined by the resolver and
the DNS encoding. At session start (and periodically), the client performs a
binary search:

1. Send MTU_PROBE frames padded to candidate sizes between `[MinMTU, MaxMTU]`.
2. The server replies with MTU_ACK echoing the largest probe size it received intact.
3. Binary search converges on the largest size that survives the path.
4. The discovered MTU is stored in the path's MTU map and bounds DATA frame size.

After bootstrap, MTU may be learned passively (the largest DATA frame that gets
ACKed) to reduce probe noise.

---

## 8. Path Engine

### 8.1 Path scoring

Each path (resolver+domain) is scored continuously:

```
score = w_loss * (1 - loss_rate)
      + w_lat  * latency_percentile_factor
      + w_tput * throughput_factor
```

- `loss_rate`: EWMA of probe/data loss on the path
- `latency_percentile_factor`: derived from a moving p50/p95 of RTT
- `throughput_factor`: bytes successfully delivered per unit time

### 8.2 Multi-path scheduling

Given `K` = duplication count and the set of healthy paths sorted by score, each
reliable frame is transmitted on the top `K` paths simultaneously. The receiver's
ARQ deduplication ensures the application sees each frame once. This trades
bandwidth for blackout survival: with `K=6` over 12 paths, 5 of 6 chosen paths
can fail and the frame still arrives.

### 8.3 Health checks and failover

Paths are probed periodically (PING/PONG). A path with `N` consecutive failures
(probe or data, with no intervening success) is marked unhealthy and excluded
from scheduling. Because an excluded path receives no scheduled traffic, it is
re-probed **out-of-band**: the client periodically sends a PING directly to each
unhealthy path (bypassing top-`K` selection). A response readmits the path (a
single success clears the failure count); continued silence keeps it excluded.
This guarantees the usable path set can grow back, not just shrink.

---

## 9. Error Codes

Carried in SESSION_CLOSE / STREAM_CLOSE payloads:

```
0x00 NORMAL          graceful close
0x01 PROTOCOL_ERROR  malformed frame
0x02 CRYPTO_ERROR    AEAD open failed / handshake failed
0x03 TIMEOUT         session/stream idle timeout
0x04 RESOURCE        server resource exhaustion
0x05 VERSION         unsupported protocol version
```

---

## 10. Version Negotiation

The single `version` byte in handshake messages governs the protocol. A server
receiving an unsupported version replies with SESSION_CLOSE + VERSION error.
Future versions MUST keep HANDSHAKE_INIT parseable (version + msg_type in the
first two bytes) so version negotiation never requires guessing.

---

## 11. Security Considerations

- **Replay:** the receiver maintains a sliding window of seen `seq` values per
  direction and rejects replays. Because nonces are seq-derived, a replayed
  datagram has a reused nonce and is detectable.
- **Server key compromise:** compromise of the static key allows impersonation of
  the server going forward but does NOT retroactively decrypt past sessions
  (forward secrecy via ephemeral-ephemeral DH).
- **Traffic analysis:** this transport does not by itself defend against DNS
  query-pattern analysis. That is the responsibility of the Phase 2 DNS encoding
  and stealth layer. Hand of God frames are designed to be uniform-looking ciphertext
  to facilitate that layer.
- **Weak ciphers:** there is no XOR or null cipher in mainstream builds. AEAD only.

---

## 12. Constants (defaults)

```
WindowSize        = 1024 frames
MinRTO            = 200ms
MaxRTO            = 4s
MinMTU            = 16 bytes payload
MaxMTU            = 220 bytes payload
HealthProbeEvery  = 5s
HealthFailLimit   = 3 probes
SessionTimeout    = 120s idle
ReplayWindow      = 4096 seqs
```

---

## 13. DNS Encoding & Stealth (Phase 2–3)

Hand of God frames are opaque byte strings to this layer. The DNS layer maps a
datagram onto a DNS message and shapes the resulting query stream to resemble
ordinary resolver traffic. Nothing here is authenticated or secret — all
confidentiality and integrity is already provided by §3/§4. This layer only
changes *appearance*.

### 13.1 Query name structure

An upstream (client→server) datagram is carried in the query name:

```
<data_labels>.<session_hex>.<zone>
```

- `session_hex` — the 2-byte session ID as 4 lowercase hex chars.
- `zone` — the operator's authoritative zone.
- `data_labels` — the datagram bytes run through the active **label entropy
  codec** (§13.2), split into ≤63-char DNS labels. The whole name stays ≤253
  chars; payloads that would overflow are rejected (the caller must fragment via
  MTU, §7).

The codec mode is a deployment/profile setting known to both endpoints; it is
**not** carried on the wire. Downstream (server→client) payloads ride in record
RDATA (TXT strings, or a private HTTPS/SVCB SvcParam key `0xFF00`).

### 13.2 Label entropy modes

Each mode is a bijection over the data labels:

| Mode | Construction | Property |
|------|--------------|----------|
| `raw` | base32hex(payload) | dense (1.6 ch/byte), high-entropy — the classic tunnel tell |
| `padded` | base32hex(`[len:2][payload][rand]` padded up to a 16-byte block) | leaks size only at block granularity |
| `ngram` | order-1 Markov letter coding, 2 chars/byte | pronounceable, word-like labels; lowest density |

`ngram` walks a fixed order-1 model: the previous output letter selects a
16-entry candidate set (a vowel is followed by a consonant; a consonant by a
vowel or common consonant), and each 4-bit payload nibble indexes into that set.
Because the sets are fixed and identical on both sides, decoding is a plain
base-16 read of the same chain. Output is lowercase `a–z` only and is normalized
on decode so resolver case-randomization (0x20) is harmless.

### 13.3 Traffic shaping & adaptation

A **profile** describes target traffic statistics (record-type mix, inter-query
and burst/idle timing, cover-query rate, label entropy mode). The scheduler
emits send slots at profile-shaped timing; cover queries fill timing when no
payload is queued. The server presents a plausible authoritative identity (SOA /
NS / cover A/AAAA/TXT/HTTPS) and rate-limits tunnel processing to a normal
authoritative volume.

An **adaptive controller** escalates the active profile on adverse conditions
and de-escalates with hysteresis:

```
Blackout OR loss ≥ 0.50            → max stealth   (immediate)
loss ≥ 0.15 OR rtt ≥ 800ms         → elevated      (immediate)
otherwise                          → standard
de-escalation: one level per N consecutive good samples (default N=5)
```

Escalation is immediate (survive filtering first); relaxation is slow (don't
abandon a needed posture on one good sample).

### 13.4 Handshake over DNS

Session id `0` is **reserved** to mark a query as carrying a handshake message
rather than session data; real sessions use `1..65535`.

The two-message NK handshake (§3.2) rides ordinary queries/responses:

```
client                                    server
------                                    ------
ClientInit → HANDSHAKE_INIT bytes
  encoded in a query name (session id 0) ─▶ recognizes session id 0,
                                            ServerProcessInit → mints a session id
                                            + keys, registers the session
ClientProcessResp ◀── HANDSHAKE_RESP bytes ─ returns RESP (carries the session id)
  → derives the same id + keys              in the TXT response
```

`HANDSHAKE_INIT`/`HANDSHAKE_RESP` are the raw handshake wire format of §3.2 (not
sealed datagrams); they are wrapped in a one-byte transport envelope and encoded
into the query name / response exactly like a datagram. The server
**deduplicates by client ephemeral key**: a retransmitted or multi-path-duplicated
INIT returns the cached response and the same session, so duplication never mints
duplicate sessions. A query whose INIT body doesn't begin with
`[version][HANDSHAKE_INIT]` is treated as cover, costing no session id.

**Return-routability cookie (anti-DoS).** Because the NK client is anonymous,
the server commits *no* state on a first INIT. Instead it replies with a
stateless challenge — a cookie `= HMAC(server_secret, client_ephemeral ||
time_bucket)` truncated to 16 bytes. The client re-sends its INIT with the cookie
echoed; the server recomputes and verifies it (accepting the current or previous
time bucket) before minting any session id, keys, or memory. Since the challenge
is only delivered to the source the query actually came from, a blind/spoofed
flood can never produce a valid cookie, so it cannot force the server to create
state. The cookie is purely a round-trip proof — it is *not* authentication (the
client is anonymous by design); an on-path attacker completing round-trips is
additionally bounded by the server's query-rate circuit breaker (§13.3). The
cookie adds one round-trip to session setup and can be disabled on trusted paths.

Once established, the client tags all its queries (data and cover) with the
assigned session id, so the server routes them to the session and pulls its
buffered downstream onto the responses.

### 13.5 Session teardown

`SESSION_CLOSE` (§5, unreliable) carries an error code (§9). Teardown is
asymmetric because downstream is pull-based:

- **Client-initiated:** the client sends `SESSION_CLOSE` on its active paths and
  stops. The server evicts the session immediately on receipt.
- **Server-initiated:** the server cannot push, so it can only piggyback a
  `SESSION_CLOSE` onto the next response when the client queries.

Because `SESSION_CLOSE` is unreliable (a single datagram that may be lost), the
authoritative side also runs an **idle reaper**: any session with no inbound
query for longer than a configurable idle timeout (cf. `SessionTimeout`, §12) is
evicted, freeing its session id. The reaper is the real backstop for clients that
vanish without closing; explicit `SESSION_CLOSE` is the prompt fast path.
