package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/slabrant/chapi/internal/envelope"
	"github.com/slabrant/chapi/internal/store"
)

// ErrRoomClosed is returned when a room shut down while a request was in
// flight. It is a retry, not a failure: the caller asks the registry for the
// room again and gets a freshly opened one.
var ErrRoomClosed = errors.New("hub: room closed")

// MaxNickLen bounds a nickname. Nicknames are client-supplied and unverified;
// the only thing the server owes them is a size limit.
const MaxNickLen = 32

type joinRequest struct {
	client *Client
	since  uint64
	reply  chan error
}

type roomRequest struct {
	client *Client
	frame  clientFrame
}

// Room owns everything about one room: its client set, its sequence counter,
// its warm ring and its archive.
//
// All of that state is reached only from the room's own goroutine, so none of
// it is locked. Other goroutines interact through the channels below.
type Room struct {
	name   string
	cfg    Config
	signer *envelope.Signer
	keys   envelope.KeyLookup
	reg    *Registry
	log    *slog.Logger

	register   chan joinRequest
	unregister chan *Client
	requests   chan roomRequest
	shutdown   chan struct{}
	done       chan struct{}

	clients map[*Client]bool
	hist    *store.History
}

func newRoom(name string, reg *Registry) *Room {
	return &Room{
		name:       name,
		cfg:        reg.cfg,
		signer:     reg.signer,
		keys:       reg.keys,
		reg:        reg,
		log:        reg.log.With("room", name),
		register:   make(chan joinRequest),
		unregister: make(chan *Client),
		requests:   make(chan roomRequest),
		shutdown:   make(chan struct{}, 1),
		done:       make(chan struct{}),
		clients:    make(map[*Client]bool),
	}
}

// Name returns the room's name.
func (r *Room) Name() string { return r.name }

// Join subscribes a client and delivers everything newer than since.
func (r *Room) Join(c *Client, since uint64) error {
	reply := make(chan error, 1)
	select {
	case r.register <- joinRequest{client: c, since: since, reply: reply}:
	case <-r.done:
		return ErrRoomClosed
	}
	select {
	case err := <-reply:
		return err
	case <-r.done:
		return ErrRoomClosed
	}
}

// Leave unsubscribes a client. It is safe to call for a client that never
// joined.
func (r *Room) Leave(c *Client) {
	select {
	case r.unregister <- c:
	case <-r.done:
	}
}

// Submit hands the room a frame from one of its clients.
func (r *Room) Submit(c *Client, f clientFrame) {
	select {
	case r.requests <- roomRequest{client: c, frame: f}:
	case <-r.done:
		c.send(errorBytes("room closed, rejoin"))
	}
}

// run is the room's goroutine. The archive is opened here rather than in the
// registry so that a slow open — a large archive is scanned to recover the
// sequence counter — never stalls every other room's traffic.
func (r *Room) run() {
	defer close(r.done)

	hist, err := store.OpenHistory(r.cfg.DataDir, r.name, r.cfg.Store, r.keys)
	if err != nil {
		r.log.Error("opening room history", "err", err)
		r.failOpen(err)
		return
	}
	r.hist = hist
	defer hist.Close()

	for {
		select {
		case <-r.shutdown:
			return

		case req := <-r.register:
			req.reply <- r.join(req.client, req.since)

		case c := <-r.unregister:
			delete(r.clients, c)

		case req := <-r.requests:
			if fatal := r.handle(req); fatal != nil {
				r.failFatal(fatal)
				return
			}
		}
	}
}

// failOpen drains pending joins with an error so nobody waits on a room that
// never opened, then asks the registry to forget it. A later join reopens it,
// which is the right behaviour for a transient disk problem.
func (r *Room) failOpen(cause error) {
	r.reg.evict(r.name)
	for {
		select {
		case req := <-r.register:
			req.reply <- fmt.Errorf("hub: room %s unavailable: %w", r.name, cause)
		case req := <-r.requests:
			req.client.send(errorBytes("room unavailable"))
		case <-r.unregister:
		default:
			return
		}
	}
}

// failFatal handles an archive write that failed.
//
// This is not recoverable in place. The in-memory counter has advanced past
// what reached disk, so continuing would reissue a sequence after the next
// restart and hand clients duplicate keys for distinct messages. Dropping the
// room and letting it reopen re-derives the counter from the file, which is
// the only copy that was ever authoritative.
func (r *Room) failFatal(cause error) {
	r.log.Error("archive write failed, closing room", "err", cause)
	r.reg.evict(r.name)
	for c := range r.clients {
		c.Kill(CloseServerError, "room archive unavailable")
	}
}

func (r *Room) join(c *Client, since uint64) error {
	r.clients[c] = true
	c.send(joinedBytes(r.name, r.hist.LastSeq()))

	msgs, gaps, err := r.hist.Since(since)
	if err != nil {
		r.log.Error("reading history for rejoin", "err", err)
		c.send(errorBytes("history unavailable"))
		return nil
	}
	r.deliver(c, msgs, gaps)
	return nil
}

// deliver sends a backfill response. Gaps go out alongside the messages rather
// than instead of them: the server never splices a discontinuity shut.
func (r *Room) deliver(c *Client, msgs []*envelope.Message, gaps []store.Gap) {
	for _, g := range gaps {
		c.send(gapBytes(r.name, g))
	}
	for _, m := range msgs {
		c.send(m.Wire())
	}
}

// handle processes one client frame. A non-nil return is a fatal archive
// error; everything else is reported to the sender and survivable.
func (r *Room) handle(req roomRequest) error {
	switch req.frame.T {
	case FrameSend:
		return r.publish(req.client, req.frame)
	case FrameShush:
		return r.shush(req.client, req.frame)
	case FrameBackfill:
		r.backfill(req.client, req.frame)
		return nil
	default:
		req.client.send(errorBytes("unknown frame type " + req.frame.T))
		return nil
	}
}

func (r *Room) publish(c *Client, f clientFrame) error {
	nick, err := cleanNick(f.Nick)
	if err != nil {
		c.send(errorBytes(err.Error()))
		return nil
	}

	kind := envelope.Kind(f.Kind)
	header := envelope.Header{Room: r.name, Nick: nick, Kind: kind}

	switch kind {
	case envelope.KindText:
		if len(f.P) == 0 {
			c.send(errorBytes("empty message"))
			return nil
		}
		if len(f.P) > r.cfg.MaxTextBytes {
			c.send(errorBytes(fmt.Sprintf("message over %d bytes", r.cfg.MaxTextBytes)))
			return nil
		}
		if !utf8.ValidString(f.P) {
			c.send(errorBytes("message is not valid UTF-8"))
			return nil
		}
	case envelope.KindImage:
		if len(f.P) == 0 {
			c.send(errorBytes("empty image"))
			return nil
		}
		// The ceiling is on the encoded payload, which is what the client was
		// told at login and what it can measure before sending.
		if len(f.P) > r.cfg.ImageMaxBytes {
			c.send(errorBytes(fmt.Sprintf("image over %d bytes", r.cfg.ImageMaxBytes)))
			return nil
		}
		if f.Mime == "" {
			c.send(errorBytes("image without mime type"))
			return nil
		}
		header.Mime, header.W, header.H = f.Mime, f.W, f.H
	default:
		c.send(errorBytes("cannot send kind " + f.Kind))
		return nil
	}

	return r.broadcast(c, header, f.P)
}

func (r *Room) shush(c *Client, f clientFrame) error {
	nick, err := cleanNick(f.Nick)
	if err != nil {
		c.send(errorBytes(err.Error()))
		return nil
	}
	if f.Seq == 0 || f.Seq > r.hist.LastSeq() {
		c.send(errorBytes("shush references an unknown sequence"))
		return nil
	}
	if r.hist.IsShushed(f.Seq) {
		return nil // already shushed; re-broadcasting would just burn a sequence
	}
	header := envelope.Header{Room: r.name, Nick: nick, Kind: envelope.KindShush}
	return r.broadcast(c, header, envelope.MarshalShush(f.Seq))
}

// broadcast assigns a sequence, seals, archives and fans out.
//
// The archive write happens before the fan-out. A message that reached clients
// but not the file would be a permanent hole in the sequence space, and the
// file is what the counter is recovered from.
func (r *Room) broadcast(c *Client, header envelope.Header, payload string) error {
	header.Seq = r.hist.NextSeq()
	header.TS = time.Now().Unix()

	m, err := r.signer.Seal(header, payload)
	if err != nil {
		c.send(errorBytes(err.Error()))
		return nil
	}
	if err := r.hist.Append(m); err != nil {
		return err
	}
	for client := range r.clients {
		// Every client gets the same slice; a broadcast image is never copied
		// per recipient.
		client.send(m.Wire())
	}
	r.reg.notifyActivity(r.name, m.Header.Seq)
	return nil
}

func (r *Room) backfill(c *Client, f clientFrame) {
	if f.From == 0 || f.To < f.From {
		c.send(errorBytes("backfill needs from <= to"))
		return
	}
	msgs, gaps, err := r.hist.Range(f.From, f.To)
	if err != nil {
		r.log.Error("reading history for backfill", "err", err)
		c.send(errorBytes("history unavailable"))
		return
	}
	r.deliver(c, msgs, gaps)
}

func cleanNick(nick string) (string, error) {
	nick = strings.TrimSpace(nick)
	if nick == "" {
		return "", errors.New("nickname required")
	}
	if len(nick) > MaxNickLen {
		return "", fmt.Errorf("nickname over %d bytes", MaxNickLen)
	}
	if !utf8.ValidString(nick) {
		return "", errors.New("nickname is not valid UTF-8")
	}
	// Control characters would ride into a signed header and out to every
	// client. Nicknames are unverifiable anyway; they need not also be able to
	// carry escape sequences.
	if strings.ContainsFunc(nick, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("nickname contains control characters")
	}
	return nick, nil
}
