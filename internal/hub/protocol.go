package hub

import (
	"encoding/json"

	"github.com/slabrant/chapi/internal/store"
)

// Frames a client sends. DESIGN.md fixes the server-to-client message
// envelope; these are the other direction, which it leaves open.
//
// Client frames are not signed. There is nothing for a signature to attest:
// the server is the only party that can assign a sequence, and it signs what
// it broadcasts.
const (
	FrameJoin     = "join"     // subscribe to a room and gap-fill from a sequence
	FrameSend     = "send"     // publish a text or image message
	FrameShush    = "shush"    // mark a sequence as shushed
	FrameBackfill = "backfill" // request an explicit sequence range
	FrameRooms    = "rooms"    // list rooms that have history on the server
)

// clientFrame is the union of everything a client may send. Fields not
// relevant to the frame's type are ignored.
type clientFrame struct {
	T    string `json:"t"`
	Room string `json:"room,omitempty"`
	Nick string `json:"nick,omitempty"`

	// join
	Since uint64 `json:"since,omitempty"`

	// backfill
	From uint64 `json:"from,omitempty"`
	To   uint64 `json:"to,omitempty"`

	// send
	Kind string `json:"kind,omitempty"`
	P    string `json:"p,omitempty"`
	Mime string `json:"mime,omitempty"`
	W    int    `json:"w,omitempty"`
	H    int    `json:"h,omitempty"`

	// shush
	Seq uint64 `json:"seq,omitempty"`
}

// Control frames the server sends alongside signed messages.
//
// A signed message carries "h" and no "t"; a control frame carries "t" and no
// "h". That is how a client tells them apart, and it is why control frames
// need no signature: they carry no history, only transport state.
const (
	FrameJoined   = "joined"   // subscription confirmed, with the room's newest sequence
	FrameActivity = "activity" // a room the client is not in has new traffic
	FrameGap      = "gap"      // a sequence range the server could not serve
	FrameError    = "error"    // the previous frame was rejected
)

type joinedFrame struct {
	T    string `json:"t"`
	Room string `json:"room"`
	Seq  uint64 `json:"seq"`
}

type activityFrame struct {
	T    string `json:"t"`
	Room string `json:"room"`
	Seq  uint64 `json:"seq"`
}

type gapFrame struct {
	T    string `json:"t"`
	Room string `json:"room"`
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

type roomsFrame struct {
	T     string   `json:"t"`
	Rooms []string `json:"rooms"`
}

type errorFrame struct {
	T   string `json:"t"`
	Msg string `json:"msg"`
}

func encodeFrame(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("hub: encoding control frame: " + err.Error())
	}
	return b
}

func joinedBytes(room string, seq uint64) []byte {
	return encodeFrame(joinedFrame{T: FrameJoined, Room: room, Seq: seq})
}

func activityBytes(room string, seq uint64) []byte {
	return encodeFrame(activityFrame{T: FrameActivity, Room: room, Seq: seq})
}

func gapBytes(room string, g store.Gap) []byte {
	return encodeFrame(gapFrame{T: FrameGap, Room: room, From: g.From, To: g.To})
}

func roomsBytes(names []string) []byte {
	if names == nil {
		names = []string{}
	}
	return encodeFrame(roomsFrame{T: FrameRooms, Rooms: names})
}

func errorBytes(msg string) []byte {
	return encodeFrame(errorFrame{T: FrameError, Msg: msg})
}
