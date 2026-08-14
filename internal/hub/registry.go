// Package hub owns the live state of the chat: which rooms exist, who is
// connected, and the fan-out of messages to them.
//
// Every piece of mutable state here belongs to exactly one goroutine and is
// reached only through channels. There are no mutexes on the message path.
//
// The dependency between the two kinds of goroutine runs one way. Rooms send
// to the registry; the registry never sends to a room and never blocks on one.
// That is what keeps the fan-out free of cycles, and it is why rooms may block
// on the registry safely.
package hub

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/slabrant/chapi/internal/envelope"
	"github.com/slabrant/chapi/internal/store"
)

// Config carries the hub's tunables. Every one of these is an environment
// variable at the edge.
type Config struct {
	DataDir string
	Store   store.Config

	// ImageMaxBytes is the ceiling on an encoded image payload, advertised to
	// clients at login so they can measure before sending.
	ImageMaxBytes int
	// MaxTextBytes is the ceiling on a text payload.
	MaxTextBytes int
	// OutboundBuffer is how far behind a client may fall before it is closed.
	OutboundBuffer int

	// RoomIdleTimeout is how long an empty room keeps its archive open. A room
	// may be evicted freely; its sequence counter is recovered from the file.
	RoomIdleTimeout time.Duration
	// SweepInterval is how often empty rooms are considered for eviction.
	SweepInterval time.Duration
}

type activityNote struct {
	room string
	seq  uint64
}

type addClientCmd struct{ client *Client }
type removeClientCmd struct{ client *Client }
type joinRoomCmd struct {
	client *Client
	room   string
	reply  chan *Room
}
type leaveRoomCmd struct{ client *Client }
type evictRoomCmd struct{ room string }

// Registry owns the room table and the connected client set.
//
// It is what lets a client receive activity pings for rooms it is not
// subscribed to: it is the only goroutine that knows both which rooms exist
// and where every client currently is.
type Registry struct {
	cfg    Config
	signer *envelope.Signer
	keys   envelope.KeyLookup
	log    *slog.Logger

	cmds     chan any
	activity chan activityNote

	// stopping is closed before rooms are torn down, so a room blocked on the
	// registry can give up instead of deadlocking against a drain.
	stopping chan struct{}
	done     chan struct{}
	wg       sync.WaitGroup
}

// NewRegistry returns a registry. Run must be called before use.
func NewRegistry(cfg Config, signer *envelope.Signer, keys envelope.KeyLookup, log *slog.Logger) *Registry {
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Minute
	}
	return &Registry{
		cfg:      cfg,
		signer:   signer,
		keys:     keys,
		log:      log,
		cmds:     make(chan any),
		activity: make(chan activityNote, 256),
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Config returns the hub's configuration.
func (r *Registry) Config() Config { return r.cfg }

// Run drives the registry until ctx is cancelled, then shuts every room down.
func (r *Registry) Run(ctx context.Context) {
	rooms := make(map[string]*Room)
	lastUse := make(map[string]time.Time)
	clients := make(map[*Client]string)

	ticker := time.NewTicker(r.cfg.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.shutdown(rooms, clients)
			return

		case cmd := <-r.cmds:
			switch c := cmd.(type) {
			case addClientCmd:
				clients[c.client] = ""

			case removeClientCmd:
				delete(clients, c.client)

			case leaveRoomCmd:
				clients[c.client] = ""

			case joinRoomCmd:
				room, ok := rooms[c.room]
				if !ok {
					room = newRoom(c.room, r)
					rooms[c.room] = room
					r.wg.Add(1)
					go func() {
						defer r.wg.Done()
						room.run()
					}()
				}
				lastUse[c.room] = time.Now()
				// Recording the client here, before it has finished
				// registering with the room, is what keeps the sweep from
				// evicting a room somebody is in the middle of joining.
				clients[c.client] = c.room
				c.reply <- room

			case evictRoomCmd:
				delete(rooms, c.room)
				delete(lastUse, c.room)
			}

		case note := <-r.activity:
			lastUse[note.room] = time.Now()
			ping := activityBytes(note.room, note.seq)
			for client, current := range clients {
				if current != note.room {
					client.send(ping)
				}
			}

		case <-ticker.C:
			r.sweep(rooms, lastUse, clients)
		}
	}
}

// sweep evicts rooms nobody is in.
//
// This is safe only because the sequence counter lives in the archive rather
// than in the room: the client set and the in-memory ring can be thrown away,
// and a later join reopens the room with its numbering intact.
func (r *Registry) sweep(rooms map[string]*Room, lastUse map[string]time.Time, clients map[*Client]string) {
	if r.cfg.RoomIdleTimeout <= 0 {
		return
	}
	occupied := make(map[string]bool, len(clients))
	for _, room := range clients {
		if room != "" {
			occupied[room] = true
		}
	}
	now := time.Now()
	for name, room := range rooms {
		if occupied[name] || now.Sub(lastUse[name]) < r.cfg.RoomIdleTimeout {
			continue
		}
		// The registry is the sole owner of the client-to-room mapping, so a
		// room recorded as empty here cannot acquire a client concurrently.
		delete(rooms, name)
		delete(lastUse, name)
		room.stop()
	}
}

func (r *Registry) shutdown(rooms map[string]*Room, clients map[*Client]string) {
	close(r.stopping)
	for _, room := range rooms {
		room.stop()
	}
	for client := range clients {
		client.Kill(CloseServerError, "server shutting down")
	}

	// Rooms may be mid-send to the registry as they wind down. Keep draining
	// so nothing blocks on a channel this goroutine has stopped reading.
	drained := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(drained)
	}()
	for {
		select {
		case <-r.cmds:
		case <-r.activity:
		case <-drained:
			close(r.done)
			return
		}
	}
}

// stop asks a room's goroutine to exit. The buffered channel makes this safe
// to call from the registry, which must never block on a room.
func (r *Room) stop() {
	select {
	case r.shutdown <- struct{}{}:
	default:
	}
}

func (r *Registry) submit(cmd any) bool {
	select {
	case r.cmds <- cmd:
		return true
	case <-r.done:
		return false
	}
}

// Add registers a connection so it can receive activity pings.
func (r *Registry) Add(c *Client) { r.submit(addClientCmd{client: c}) }

// Remove drops a connection.
func (r *Registry) Remove(c *Client) { r.submit(removeClientCmd{client: c}) }

// Leave records that a client is no longer in any room.
func (r *Registry) Leave(c *Client) { r.submit(leaveRoomCmd{client: c}) }

// Join resolves a room by name, creating it if this is the first join.
//
// Rooms come into existence by being joined. There is no create step and no
// server-published list, which is what keeps the room space from being capped
// by configuration.
func (r *Registry) Join(c *Client, room string) (*Room, error) {
	if err := store.ValidateRoomName(room); err != nil {
		return nil, err
	}
	reply := make(chan *Room, 1)
	if !r.submit(joinRoomCmd{client: c, room: room, reply: reply}) {
		return nil, ErrRoomClosed
	}
	select {
	case got := <-reply:
		return got, nil
	case <-r.done:
		return nil, ErrRoomClosed
	}
}

// evict removes a room from the table. Called by a room that is giving up on
// itself, so that the next join gets a fresh one.
func (r *Registry) evict(room string) {
	select {
	case r.cmds <- evictRoomCmd{room: room}:
	case <-r.stopping:
	case <-r.done:
	}
}

// notifyActivity tells the registry a room has new traffic, so clients
// elsewhere can show an unread badge without subscribing.
func (r *Registry) notifyActivity(room string, seq uint64) {
	select {
	case r.activity <- activityNote{room: room, seq: seq}:
	case <-r.stopping:
	case <-r.done:
	}
}

// Wait blocks until the registry has fully shut down.
func (r *Registry) Wait() { <-r.done }
