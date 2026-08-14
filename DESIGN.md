# Ultralight Chat — Backend Design

## Scope

This document covers the **server**. The client is separate work with its own
design.

What appears here about the client is only the contract it must satisfy to
interoperate: the wire format, the signing and verification rules, the rejoin
handshake, and the obligations the server's behaviour imposes on it. How the
client stores, renders, or recovers anything is out of scope and deliberately
left undecided. See *Client contract* for the boundary.

## Goals & constraints
- Go backend: minimal dependencies, single deployable binary
- Shared-password access, no accounts, no private data
- Server history is a supplement; clients are expected to hold more than it does
- Images relayed and archived without their bytes
- Target ~10–20 people; avoid designs that cap growth arbitrarily

## Trust model

State this plainly, because the crypto below is easy to over-read.

Everyone with the password is trusted. There is no per-user identity: the
nickname is client-supplied and the server signs whatever it is told. Signatures
therefore attest **"the server broadcast this at this sequence"** — they prevent
fabrication of history, not impersonation. Anyone can set their nickname to
anyone else's.

The realistic server-side attack surface is credential lifetime, addressed under
*Token revocation*. The realistic client-side one is XSS, which belongs to the
client project but is worth naming here so it is not assumed handled.

## Hub

One goroutine per room owning that room's client set, driven by register /
unregister / broadcast channels. No mutexes. A registry goroutine sits above the
rooms and owns the room table; it is what lets a client receive activity pings
for rooms it is not subscribed to. Per connection, a read goroutine and a write
goroutine with a buffered outbound channel.

The hub only ever broadcasts. There are no directed messages and no connection
identity — see *Peer backfill*, below, for why that stayed out.

**Slow consumers are disconnected, not skipped.** When an outbound buffer fills,
close the connection with a close code. Never drop messages on a live socket: a
silently skipped message is a gap with nothing to trigger recovery, whereas a
closed socket puts the client on the reconnect-and-gap-fill path that already
exists. This is the whole reason dropping is safe.

Image payloads are shared by reference across outbound queues, never copied per
client.

## Endpoints

- `POST /login` — constant-time password compare; returns an HMAC-signed token
  with an expiry, the Ed25519 public key, and the server's image byte ceiling.
  Stateless verification, no session store. Per-IP rate limit.
- `GET /ws` — token passed via `Sec-WebSocket-Protocol`, keeping it out of URLs
  and access logs. The server must echo the selected subprotocol or the browser
  fails the handshake.

`//go:embed` bundles the client assets, so deployment is one binary plus
environment variables. Caddy in front for TLS.

Because the binary serves the assets, it also owns the response headers,
including CSP. Serving real files rather than inline script costs nothing here
and lets the policy stay strict:

```
default-src 'self'; script-src 'self'; style-src 'self';
img-src 'self' data:; connect-src 'self' wss:
```

**Token revocation.** Stateless tokens cannot be revoked individually, which
means rotating the shared password does not evict anyone already holding a
token. Mix a server-side epoch counter into the token HMAC key
(`key = HKDF(secret, epoch)`). Bumping the epoch invalidates every outstanding
token at once. Keep expiry in hours, not weeks.

## Message model

Server assigns a monotonic per-room sequence number at broadcast time. Sequence
is the ordering and gap-detection key. Client timestamps are display-only; the
authoritative timestamp is server-assigned and inside the signature.

### Envelope

Two parts: a **signed header** and an **unsigned payload** bound to it by hash.

```json
{
  "h":   "<header, raw JSON string, signed verbatim>",
  "sig": "<base64 Ed25519 signature over the bytes of h>",
  "p":   "<payload string>"
}
```

Header contents:

```json
{"v":1,"room":"general","seq":1234,"ts":1755130000,"nick":"sam",
 "kind":"text","hash":"<hex sha256 of p>","keyid":"k1"}
```

Image headers additionally carry `mime`, `w`, `h`, so a client can reserve
layout space before the payload lands and can still describe an image whose
bytes are gone.

`kind` is `text`, `image`, or `shush`.

**The header is signed; the payload is authenticated transitively by `hash`.**
This split is load-bearing — it is what lets the archive store an image message
with its payload stripped and still have that record verify. A stripped image is
then a *known-authentic* record rather than a signature failure.

### Signing rules

1. **Sign bytes, never a re-serialization.** The server serializes the header
   once, signs those exact bytes, and transmits them as a string. Verification
   happens against the string, *before* parsing. JSON has no canonical form —
   key order, unicode escaping and number formatting all vary between
   `encoding/json` and `JSON.stringify` — so no party may ever re-serialize a
   header and expect the signature to hold. Verify-then-parse makes
   canonicalization a non-problem instead of a latent one.
2. `hash` is sha256 over the payload's UTF-8 bytes **exactly as transmitted**.
   For images that means the base64 string, not the decoded bytes. Slightly
   wasteful, one rule, and it means anything stored or re-served byte-for-byte
   can never fail its own hash.
3. `v` (schema version) and `ts` are inside the header, therefore signed.
   Anything outside the signature is tamperable and must not be trusted.
4. `keyid` is on every message so signing keys can rotate while old messages
   still verify. The signing key is never derived from the shared password.

Ed25519 via `crypto/ed25519`. HMAC is unusable here: verification would require
handing every client forging power.

## Images

- Base64 inline on the wire, so a message stays one self-contained object across
  send, relay, sign, and archive. Accepts ~33% inflation for a single code path.
- The server enforces a byte ceiling and advertises it at login. Encoded size is
  not knowable before encoding, so clients need a measure-and-retry loop to hit
  it; the server's job is only to publish the number and reject what exceeds it.
- Raise per-message read limits on both server and proxy; defaults sit far below
  image size.
- **Leave WebSocket compression enabled.** Deflate over base64 recovers
  essentially all of base64's ~33% inflation, because base64 spends 8 bits
  carrying 6 bits of entropy. "Already compressed, nothing to gain" is true of
  raw JPEG bytes and false of base64. The real trade-off is CPU: deflate contexts
  are per-connection, so a broadcast image is compressed once per client. At
  ~20 people either choice is fine — but choose it for the right reason.
  (`coder/websocket` exposes compression per connection, not per message, so
  selective per-frame control is not available anyway.)

## Shush

Global, signed marker referencing a sequence number and occupying its own
sequence; the referenced seq lives in the payload and is therefore covered by
`hash`. Because it carries a sequence of its own, it survives backfill and
archive like any other record.

Retained longer than the messages it references; markers are tiny, keep them
effectively forever.

Any member can shush any message. This is a deliberate consequence of having no
per-user identity, not an oversight. Advisory by nature: the server stops
serving the message, but anyone who already has the bytes keeps them.

## Rooms

One full subscription per connection at a time. The registry goroutine pushes
lightweight activity pings for other rooms (room name and latest sequence, no
payloads), giving unread badges without multiplying fan-out. A room switch is
leave, join, then gap-fill through the existing machinery.

**Room lifetime vs. sequence lifetime.** These are separate, and conflating them
corrupts the key space clients index history by. A room's *client set* may be
garbage-collected when empty, and its in-memory state may be evicted entirely.
Its *sequence counter* may never restart: a room that resets to 0 hands clients
duplicate keys for distinct messages and breaks gap detection permanently.

This is safe because of one invariant: **every sequence number appears in the
JSONL file.** The counter is therefore recoverable by reading the file's last
line when a room is next opened. Rooms can be evicted freely; the counter cannot
be lost.

## Server history

Two tiers, both server-side:

1. **Ring buffer (warm).** Long text tail of several thousand messages; short
   byte-budgeted image window, oldest-first eviction. All limits are environment
   variables, not constants.
2. **JSONL archive (permanent, text only).** See *Persistence*.

Clients are expected to keep their own primary store holding far more than
either tier. That expectation is what allows the server's retention to stay
modest; the design of that store is the client project's.

**Rejoin:** the client sends its newest known sequence per room. The server
returns everything newer — from the ring buffer, falling back to a scan of the
JSONL for ranges below it. A gap marker is returned only when the range
genuinely cannot be served. The server never silently splices a discontinuity.

Because the archive is complete for text, the gap marker is a rare response
rather than a routine one: it is reachable essentially only for images.

## Persistence

- One JSONL file per room, opened `O_APPEND`, one JSON object per line, written
  by the room's own goroutine.
- Image messages persist as their signed header with the payload replaced by a
  placeholder. Image bytes are never written to disk. The header still verifies
  — that is what the signature split buys.
- Monotonic seq plus append-only means **the file is sorted by seq by
  construction**, so serving a historical range is a scan. A sparse offset index
  is available later if a few megabytes ever stops being trivial, which at 20
  people over a year it will not.
- No rotation, no compaction, no retention policy.
- Crash recovery is free: a torn final line fails to parse and is discarded.

Reading the archive back to serve history is **part of v1**, not deferred. It is
a file scan reusing the rejoin response that already exists, and it is what makes
history deterministic.

## Peer backfill — cut

WebRTC data-channel backfill between clients was considered and dropped.

It would have been the largest subsystem in the design — signaling relay,
ephemeral session IDs, a deliver-to-one hub path, a coverage-offer protocol,
chunked transfer with acks and backpressure, consent UX with IP disclosure, and
NAT pairs that simply fail — in exchange for filling gaps *probabilistically*.
Two people with the same gap would get different outcomes for reasons neither
could see.

Server-side archive reads cover the same need deterministically and completely
for text, using the protocol that already exists. The one capability genuinely
lost is images that have aged out of the ring buffer.

Dropping it also keeps three properties that are cheaper to hold than to
recover: the hub stays pure fan-out, connections stay anonymous (no session IDs,
which are the camel's nose for connection identity), and the server remains the
only party that ever sees a member's IP address.

If old images turn out to matter, the answer is a hash-keyed blob directory on
the server, not WebRTC: `hash` is already in the signed header and is already the
natural filename, and blobs are stored and re-served byte-for-byte so they can
never fail their own hash. The sequence-range request is unchanged either way —
only the answering party differs.

## Client contract

The boundary. Everything here is forced by the server's behaviour; everything
not here is the client project's to decide.

- Authenticate at `POST /login`, then pass the token via
  `Sec-WebSocket-Protocol` on `GET /ws`.
- Verify every message: Ed25519 over the raw header bytes using the advertised
  public key, matched by `keyid`; then sha256 the payload against `hash`. Verify
  before parsing, and never re-serialize a header.
- Treat a header that verifies with an absent payload as authentic — it is an
  archived image, not a forgery.
- Track the newest known sequence per room and send it on rejoin. Detect gaps by
  sequence, and surface gap markers rather than hiding them.
- Expect to be disconnected when slow. Reconnect and resume from last known
  sequence; the server assumes this and is otherwise free to drop connections.
- Clamp images to the byte ceiling advertised at login before sending.
- Carry `v` forward into any stored record, so a schema change is a migration
  rather than a break.

## Decide before the first draft

Frozen by the wire format, and expensive to change once clients have stored
records shaped by it:
- Sequence semantics and their per-room scope
- Which fields the signature covers **and how they are encoded for signing**
- What `hash` covers

The schema version field turns each of these from a breaking change into a
migration.

## Deferrable
- Retention numbers (environment variables)
- Sparse offset index over the JSONL, if scans ever stop being trivial
- Room discovery: server-published list vs. implicit creation by name
- Base64 vs. binary framing (the wire format is easy to change; stored history is
  not, which the version field covers)
- Server-side image blobs in a hash-keyed directory
