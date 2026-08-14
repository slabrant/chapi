# chapi

The backend for ultralight chat, built to [DESIGN.md](DESIGN.md). One Go
binary, one dependency, the client assets embedded in it.

DESIGN.md is the authority on *why*. This file covers what it deliberately
leaves open: the client-to-server frames, the environment variables, and the
decisions taken while implementing it.

```
go test ./...
go build ./cmd/chapi
CHAPI_PASSWORD=... ./chapi
```

## Layout

| Package | Holds |
| --- | --- |
| `internal/envelope` | Wire format, signing, verification. The rules the rest depends on. |
| `internal/auth` | Shared-password login, stateless tokens, epoch revocation, login rate limit. |
| `internal/store` | Warm ring, JSONL archive, sequence recovery, gap detection. |
| `internal/hub` | Registry and room goroutines, fan-out, session dispatch. |
| `internal/httpapi` | `/login`, `/ws`, static assets, CSP. |
| `internal/config` | Environment variables and secret resolution. |
| `web/dist` | Placeholder client. |

## Protocol

Server-to-client messages are the signed envelope from DESIGN.md. Everything
below is the other direction, plus the unsigned control frames.

A **signed message** carries `h` and no `t`. A **control frame** carries `t`
and no `h`. That is how a client tells them apart.

### Client to server

Frames are JSON text. They are not signed: the server is the only party that
can assign a sequence, and it signs what it broadcasts.

```jsonc
{"t":"join","room":"general","since":1234}   // subscribe, gap-fill from `since`
{"t":"send","nick":"sam","kind":"text","p":"hello"}
{"t":"send","nick":"sam","kind":"image","p":"<base64>","mime":"image/jpeg","w":800,"h":600}
{"t":"shush","nick":"sam","seq":1234}        // shush a sequence in the current room
{"t":"backfill","from":10,"to":50}           // walk back through a gap
{"t":"rooms"}                                // list rooms that have history
```

One subscription per connection. A `join` to another room leaves the current
one first.

### Server to client

```jsonc
{"t":"joined","room":"general","seq":1234}   // subscribed; room's newest sequence
{"t":"activity","room":"other","seq":99}     // traffic in a room you are not in
{"t":"gap","room":"general","from":10,"to":50}
{"t":"rooms","rooms":["general","off-topic"]}
{"t":"error","msg":"..."}
```

### Handshake

`POST /login` with `{"password":"..."}` returns:

```json
{"token":"...","exp":1755130000,"pubkey":"<base64 Ed25519>","keyid":"k1","image_max_bytes":2097152}
```

Then open `GET /ws` offering two subprotocols: `chapi.v1` and the token. The
server selects and echoes `chapi.v1`, which keeps the credential out of URLs
and access logs.

### Close codes

| Code | Meaning |
| --- | --- |
| 4001 | You fell behind. Reconnect and resume from your newest sequence. |
| 4002 | Server-side failure. Reconnect. |
| 4003 | Protocol error. Retrying the same frame will fail again. |
| 4004 | Token no longer valid. Log in again. |

## Configuration

Everything is an environment variable. Sizes accept `KiB`/`MiB`/`GiB` or
`KB`/`MB`/`GB`; durations use Go syntax (`30s`, `12h`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `CHAPI_PASSWORD` | *required* | The shared password. |
| `CHAPI_ADDR` | `:8080` | Listen address. |
| `CHAPI_DATA_DIR` | `./data` | Archives and generated secrets. |
| `CHAPI_TOKEN_SECRET` | generated | Token MAC secret, min 16 bytes. |
| `CHAPI_TOKEN_EPOCH` | `1` | Bump to invalidate every outstanding token. |
| `CHAPI_TOKEN_TTL` | `12h` | Token lifetime. Rejected above a week. |
| `CHAPI_SIGNING_SEED` | generated | Ed25519 seed, 64 hex characters. |
| `CHAPI_KEY_ID` | `k1` | `keyid` stamped into headers. |
| `CHAPI_IMAGE_MAX_BYTES` | `2MiB` | Ceiling on an encoded image, advertised at login. |
| `CHAPI_TEXT_MAX_BYTES` | `16KiB` | Ceiling on a text payload. |
| `CHAPI_RING_TEXT` | `5000` | Warm text tail, in messages. |
| `CHAPI_RING_IMAGE_BYTES` | `64MiB` | Warm image window, in bytes. |
| `CHAPI_MAX_BACKFILL` | `5000` | Messages per history response. |
| `CHAPI_OUTBOUND_BUFFER` | `64` | How far a client may fall behind before it is closed. |
| `CHAPI_ROOM_IDLE_TIMEOUT` | `10m` | How long an empty room stays open. |
| `CHAPI_SWEEP_INTERVAL` | `1m` | How often empty rooms are considered for eviction. |
| `CHAPI_PING_INTERVAL` | `30s` | Keepalive, and how often a live token is rechecked. |
| `CHAPI_WRITE_TIMEOUT` | `10s` | Per-frame write deadline. |
| `CHAPI_LOGIN_BURST` | `10` | Login attempts per window per address. |
| `CHAPI_LOGIN_WINDOW` | `1m` | Login rate-limit window. |
| `CHAPI_ALLOWED_ORIGINS` | same-origin | Comma-separated origin patterns for `/ws`. |
| `CHAPI_TRUST_PROXY_HEADER` | `false` | Read `X-Forwarded-For` for rate limiting. |
| `CHAPI_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error`. |

### Secrets

If `CHAPI_SIGNING_SEED` or `CHAPI_TOKEN_SECRET` is unset, one is generated and
written to the data directory (`signing.key`, `token.key`, mode 0600) so it
survives a restart. This matters more than it looks for the signing key: it is
what archived messages verify against, and a key that changes on restart turns
the whole archive into apparent forgeries. Back it up with the archive.

`CHAPI_TRUST_PROXY_HEADER` is off by default because a client that can forge
`X-Forwarded-For` can spread password guesses across unlimited rate-limit
buckets. Turn it on only behind a proxy that overwrites the header.

## Decisions taken while implementing

DESIGN.md left these open or unstated. Each is a place to push back.

- **Room names** are `[a-z0-9_-]`, up to 64 bytes. Rooms are created by being
  joined, so the name is untrusted input that becomes a filename.
- **Shush is room-scoped.** DESIGN.md calls the marker "global" but sequences
  are per-room, so a reference has nothing to resolve against outside its own
  room. Read as "applies to everyone" rather than "spans rooms".
- **Backfill is capped** at `CHAPI_MAX_BACKFILL` per response. The remainder
  comes back as a gap, and the `backfill` frame exists so a client can walk
  back through it. Without a cap, a client resuming from zero after a year
  would ask for the entire archive in one response.
- **An archive write failure closes the room.** The in-memory counter has
  advanced past what reached disk, and continuing would reissue a sequence
  after the next restart. The room is dropped and its clients are closed with
  4002; the next join reopens it and re-derives the counter from the file.
- **Live tokens are rechecked** on each ping interval, not only at the
  handshake. Otherwise bumping the epoch evicts nobody who is already
  connected, which is most of the point of having an epoch.
- **The stripped-payload placeholder is the empty string**, which is
  unambiguous only because the server rejects empty payloads on the way in.
- **`frame-ancestors 'none'`** was added to the CSP in DESIGN.md. The assets
  are same-origin files with no reason to be framed.
- **Compression is left on** (`CompressionContextTakeover`), per DESIGN.md.
  The library's default is off, so this is set explicitly.

## Not implemented

Deferred in DESIGN.md and still deferred here: the sparse offset index over the
JSONL, server-side image blobs in a hash-keyed directory, and binary framing.
Peer backfill stays cut.
