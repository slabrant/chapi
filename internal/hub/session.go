package hub

import (
	"encoding/json"
	"errors"

	"github.com/slabrant/chapi/internal/store"
)

// joinAttempts bounds the retry when a room is evicted between the registry
// handing it out and the client registering with it. The retry gets a freshly
// opened room, so one extra attempt is almost always enough.
const joinAttempts = 3

// Session is one connection's protocol state: which room it is in, and how
// its frames are dispatched.
//
// It is driven by that connection's read goroutine and by nothing else, so it
// needs no synchronization of its own.
type Session struct {
	reg    *Registry
	client *Client
	room   *Room
}

// NewSession registers a connection with the hub.
func NewSession(reg *Registry, client *Client) *Session {
	reg.Add(client)
	return &Session{reg: reg, client: client}
}

// Close unsubscribes the connection and drops it from the registry.
func (s *Session) Close() {
	if s.room != nil {
		s.room.Leave(s.client)
		s.room = nil
	}
	s.reg.Remove(s.client)
}

// Handle dispatches one frame from the client.
func (s *Session) Handle(raw []byte) {
	var f clientFrame
	if err := json.Unmarshal(raw, &f); err != nil {
		s.client.send(errorBytes("frame is not valid JSON"))
		return
	}

	switch f.T {
	case FrameJoin:
		s.join(f)
	case FrameRooms:
		s.listRooms()
	case FrameSend, FrameShush, FrameBackfill:
		if s.room == nil {
			s.client.send(errorBytes("join a room first"))
			return
		}
		if f.Room != "" && f.Room != s.room.Name() {
			s.client.send(errorBytes("frame targets a room this connection is not in"))
			return
		}
		s.room.Submit(s.client, f)
	default:
		s.client.send(errorBytes("unknown frame type " + f.T))
	}
}

// join switches the connection's single subscription.
//
// A room switch is leave, join, then gap-fill through the machinery that
// already exists; there is no separate resynchronization path.
func (s *Session) join(f clientFrame) {
	if s.room != nil {
		s.room.Leave(s.client)
		s.room = nil
		s.reg.Leave(s.client)
	}

	for range joinAttempts {
		room, err := s.reg.Join(s.client, f.Room)
		if err != nil {
			s.client.send(errorBytes(err.Error()))
			return
		}
		switch err := room.Join(s.client, f.Since); {
		case err == nil:
			s.room = room
			return
		case errors.Is(err, ErrRoomClosed):
			continue // evicted underneath us; ask for a fresh one
		default:
			s.client.send(errorBytes(err.Error()))
			return
		}
	}
	s.client.send(errorBytes("room unavailable, try again"))
}

// listRooms reports the rooms that have history on disk.
//
// This reads the data directory from the connection's own goroutine rather
// than the registry's: it is a directory listing, and it has no business
// stalling the fan-out.
func (s *Session) listRooms() {
	names, err := store.RoomNames(s.reg.Config().DataDir)
	if err != nil {
		s.client.send(errorBytes("cannot list rooms"))
		return
	}
	s.client.send(roomsBytes(names))
}
