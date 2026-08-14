package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/slabrant/chapi/internal/envelope"
	"github.com/slabrant/chapi/internal/store"
)

type harness struct {
	reg    *Registry
	signer *envelope.Signer
	keys   envelope.KeyLookup
	dir    string
}

func newHarness(t *testing.T, tweak func(*Config)) *harness {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer := envelope.NewSigner("k1", priv)
	keys := envelope.SingleKey("k1", signer.Public())

	cfg := Config{
		DataDir:         t.TempDir(),
		Store:           store.Config{MaxText: 1000, MaxImageBytes: 1 << 20, MaxBackfill: 1000},
		ImageMaxBytes:   1 << 20,
		MaxTextBytes:    4096,
		OutboundBuffer:  32,
		RoomIdleTimeout: time.Hour,
		SweepInterval:   time.Hour,
	}
	if tweak != nil {
		tweak(&cfg)
	}

	reg := NewRegistry(cfg, signer, keys, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	go reg.Run(ctx)
	t.Cleanup(func() {
		cancel()
		select {
		case <-time.After(5 * time.Second):
			t.Error("registry did not shut down")
		default:
			reg.Wait()
		}
	})
	return &harness{reg: reg, signer: signer, keys: keys, dir: cfg.DataDir}
}

func (h *harness) connect(t *testing.T) (*Client, *Session) {
	t.Helper()
	c := NewClient(h.reg.Config().OutboundBuffer)
	s := NewSession(h.reg, c)
	t.Cleanup(s.Close)
	return c, s
}

// next reads one frame, failing the test if none arrives.
func next(t *testing.T, c *Client) map[string]any {
	t.Helper()
	select {
	case raw := <-c.Out():
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("frame is not JSON: %v", err)
		}
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

// waitFor reads control frames until one of the given type arrives.
//
// Frames from different connections are not ordered against each other: a
// client that connects while another's traffic is still being fanned out can
// see an activity ping before its own join is confirmed.
func waitFor(t *testing.T, c *Client, frameType string) map[string]any {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case raw := <-c.Out():
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("frame is not JSON: %v", err)
			}
			if v["t"] == frameType {
				return v
			}
		case <-deadline:
			t.Fatalf("timed out waiting for a %q frame", frameType)
			return nil
		}
	}
}

// nextMessage reads frames until a signed message arrives, verifying it.
func nextMessage(t *testing.T, h *harness, c *Client) *envelope.Message {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case raw := <-c.Out():
			var probe map[string]json.RawMessage
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("frame is not JSON: %v", err)
			}
			if _, signed := probe["h"]; !signed {
				continue
			}
			m, err := envelope.Open(raw, h.keys)
			if err != nil {
				t.Fatalf("broadcast message does not verify: %v", err)
			}
			return m
		case <-deadline:
			t.Fatal("timed out waiting for a signed message")
			return nil
		}
	}
}

func drain(c *Client) {
	for {
		select {
		case <-c.Out():
		default:
			return
		}
	}
}

func joinFrame(room string, since uint64) []byte {
	return encodeFrame(clientFrame{T: FrameJoin, Room: room, Since: since})
}

func sendFrame(nick, body string) []byte {
	return encodeFrame(clientFrame{T: FrameSend, Nick: nick, Kind: string(envelope.KindText), P: body})
}

func TestBroadcastReachesEveryoneInRoom(t *testing.T) {
	h := newHarness(t, nil)
	c1, s1 := h.connect(t)
	c2, s2 := h.connect(t)

	s1.Handle(joinFrame("general", 0))
	s2.Handle(joinFrame("general", 0))
	drain(c1)
	drain(c2)

	s1.Handle(sendFrame("sam", "hello"))

	for i, c := range []*Client{c1, c2} {
		m := nextMessage(t, h, c)
		if m.Payload != "hello" {
			t.Errorf("client %d payload = %q, want hello", i+1, m.Payload)
		}
		if m.Header.Seq != 1 {
			t.Errorf("client %d seq = %d, want 1", i+1, m.Header.Seq)
		}
		if m.Header.Nick != "sam" {
			t.Errorf("client %d nick = %q, want sam", i+1, m.Header.Nick)
		}
	}
}

// The sender's own message comes back through the same fan-out, so every
// client's history is built from the same signed records.
func TestSenderReceivesOwnMessage(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	s.Handle(sendFrame("sam", "hello"))
	if m := nextMessage(t, h, c); m.Payload != "hello" {
		t.Errorf("payload = %q, want hello", m.Payload)
	}
}

// Activity pings are what give unread badges without multiplying fan-out: the
// ping carries a room and a sequence, never a payload.
func TestActivityPingReachesClientsElsewhere(t *testing.T) {
	h := newHarness(t, nil)
	sender, senderSession := h.connect(t)
	elsewhere, elsewhereSession := h.connect(t)
	idle, _ := h.connect(t)

	senderSession.Handle(joinFrame("general", 0))
	elsewhereSession.Handle(joinFrame("other", 0))
	drain(sender)
	drain(elsewhere)
	drain(idle)

	senderSession.Handle(sendFrame("sam", "hello"))

	for name, c := range map[string]*Client{"other room": elsewhere, "no room": idle} {
		frame := waitFor(t, c, FrameActivity)
		if frame["room"] != "general" {
			t.Errorf("%s: ping room = %v, want general", name, frame["room"])
		}
		if _, hasPayload := frame["p"]; hasPayload {
			t.Errorf("%s: activity ping carried a payload", name)
		}
	}

	// The sender is in the room, so it gets the message rather than a ping.
	if m := nextMessage(t, h, sender); m.Header.Seq != 1 {
		t.Errorf("sender seq = %d, want 1", m.Header.Seq)
	}
}

// A slow consumer is disconnected rather than skipped. Skipping would leave a
// gap with nothing to trigger recovery; a close puts the client on the
// reconnect path that already exists.
func TestSlowConsumerIsDisconnectedNotSkipped(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OutboundBuffer = 2 })
	slow, slowSession := h.connect(t)
	sender, senderSession := h.connect(t)

	slowSession.Handle(joinFrame("general", 0))
	senderSession.Handle(joinFrame("general", 0))
	drain(sender)
	// Deliberately do not drain the slow client.

	for range 10 {
		senderSession.Handle(sendFrame("sam", "hello"))
		drain(sender)
	}

	select {
	case <-slow.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("slow consumer was not disconnected")
	}
	if code, _ := slow.CloseInfo(); code != CloseSlowConsumer {
		t.Errorf("close code = %d, want %d", code, CloseSlowConsumer)
	}
}

func TestRejoinBackfillsFromSequence(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	for range 3 {
		s.Handle(sendFrame("sam", "hello"))
	}
	for range 3 {
		nextMessage(t, h, c)
	}

	// A second connection rejoining from sequence 1 gets only what it missed.
	rejoin, rejoinSession := h.connect(t)
	rejoinSession.Handle(joinFrame("general", 1))

	frame := waitFor(t, rejoin, FrameJoined)
	if seq, _ := frame["seq"].(float64); seq != 3 {
		t.Errorf("joined seq = %v, want 3", frame["seq"])
	}
	for _, want := range []uint64{2, 3} {
		if got := nextMessage(t, h, rejoin).Header.Seq; got != want {
			t.Errorf("backfill seq = %d, want %d", got, want)
		}
	}
}

// A room switch is leave, join, gap-fill through the existing machinery.
func TestRoomSwitchResubscribes(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	other, otherSession := h.connect(t)

	s.Handle(joinFrame("general", 0))
	otherSession.Handle(joinFrame("general", 0))
	drain(c)
	drain(other)

	s.Handle(joinFrame("off-topic", 0))
	drain(c)

	// Traffic in the room just left arrives as a ping, not as a message.
	otherSession.Handle(sendFrame("sam", "still here"))
	if frame := waitFor(t, c, FrameActivity); frame["room"] != "general" {
		t.Fatalf("ping room = %v, want general", frame["room"])
	}

	// Traffic in the new room arrives as a message.
	s.Handle(sendFrame("sam", "moved"))
	m := nextMessage(t, h, c)
	if m.Header.Room != "off-topic" || m.Payload != "moved" {
		t.Errorf("message = %s in %s, want \"moved\" in off-topic", m.Payload, m.Header.Room)
	}
}

// Rooms may be evicted freely; only their sequence counter is sacred, and that
// lives in the archive.
func TestEvictedRoomKeepsItsSequenceCounter(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.RoomIdleTimeout = 20 * time.Millisecond
		c.SweepInterval = 10 * time.Millisecond
	})

	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)
	s.Handle(sendFrame("sam", "hello"))
	if got := nextMessage(t, h, c).Header.Seq; got != 1 {
		t.Fatalf("seq = %d, want 1", got)
	}

	// Hold a reference so eviction is observable, then empty the room.
	room, err := h.reg.Join(c, "general")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	s.Close()

	select {
	case <-room.done:
	case <-time.After(2 * time.Second):
		t.Fatal("empty room was never evicted")
	}

	// Rejoining reopens the room, which recovers the counter from the file.
	c2, s2 := h.connect(t)
	s2.Handle(joinFrame("general", 0))
	frame := waitFor(t, c2, FrameJoined)
	if seq, _ := frame["seq"].(float64); seq != 1 {
		t.Fatalf("joined seq after eviction = %v, want 1", frame["seq"])
	}
	drain(c2)

	s2.Handle(sendFrame("sam", "after eviction"))
	if got := nextMessage(t, h, c2).Header.Seq; got != 2 {
		t.Fatalf("seq after eviction = %d, want 2: the counter restarted", got)
	}
}

func TestShushWithholdsMessageFromBackfill(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	s.Handle(sendFrame("sam", "regrettable"))
	if got := nextMessage(t, h, c).Header.Seq; got != 1 {
		t.Fatalf("seq = %d, want 1", got)
	}
	s.Handle(encodeFrame(clientFrame{T: FrameShush, Nick: "someone-else", Seq: 1}))
	marker := nextMessage(t, h, c)
	if marker.Header.Kind != envelope.KindShush {
		t.Fatalf("kind = %q, want shush", marker.Header.Kind)
	}
	target, err := envelope.ParseShush(marker.Payload)
	if err != nil || target != 1 {
		t.Fatalf("marker references %d (%v), want 1", target, err)
	}

	// A fresh client backfilling gets the marker but not what it shushed.
	fresh, freshSession := h.connect(t)
	freshSession.Handle(joinFrame("general", 0))
	waitFor(t, fresh, FrameJoined)
	if got := nextMessage(t, h, fresh).Header.Seq; got != 2 {
		t.Error("shushed message was served in backfill")
	}
}

func TestImageCeilingEnforced(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.ImageMaxBytes = 64 })
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	oversized := base64.StdEncoding.EncodeToString(make([]byte, 256))
	s.Handle(encodeFrame(clientFrame{
		T: FrameSend, Nick: "sam", Kind: string(envelope.KindImage),
		P: oversized, Mime: "image/jpeg", W: 10, H: 10,
	}))

	waitFor(t, c, FrameError)
}

func TestImageBroadcastCarriesDimensions(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	payload := base64.StdEncoding.EncodeToString([]byte("pretend jpeg"))
	s.Handle(encodeFrame(clientFrame{
		T: FrameSend, Nick: "sam", Kind: string(envelope.KindImage),
		P: payload, Mime: "image/jpeg", W: 800, H: 600,
	}))

	m := nextMessage(t, h, c)
	if m.Header.Mime != "image/jpeg" || m.Header.W != 800 || m.Header.H != 600 {
		t.Errorf("header = %+v, want the image dimensions carried through", m.Header)
	}
	if m.Payload != payload {
		t.Error("image payload was altered in transit")
	}
}

func TestUnsafeRoomNameRejected(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)

	s.Handle(joinFrame("../escape", 0))
	waitFor(t, c, FrameError)
}

func TestSendBeforeJoinRejected(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)

	s.Handle(sendFrame("sam", "hello"))
	waitFor(t, c, FrameError)
}

func TestMalformedFrameRejected(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)

	s.Handle([]byte("{not json"))
	waitFor(t, c, FrameError)
}

func TestNicknameValidation(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	for _, nick := range []string{"", "   ", "sam\nimposter", string(make([]byte, MaxNickLen+1))} {
		s.Handle(sendFrame(nick, "hello"))
		waitFor(t, c, FrameError)
	}
}

func TestBackfillRangeRequest(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)

	for range 5 {
		s.Handle(sendFrame("sam", "hello"))
	}
	for range 5 {
		nextMessage(t, h, c)
	}

	s.Handle(encodeFrame(clientFrame{T: FrameBackfill, From: 2, To: 3}))
	for _, want := range []uint64{2, 3} {
		if got := nextMessage(t, h, c).Header.Seq; got != want {
			t.Errorf("backfill seq = %d, want %d", got, want)
		}
	}
}

func TestListRooms(t *testing.T) {
	h := newHarness(t, nil)
	c, s := h.connect(t)
	s.Handle(joinFrame("general", 0))
	drain(c)
	s.Handle(joinFrame("off-topic", 0))
	drain(c)

	s.Handle(encodeFrame(clientFrame{T: FrameRooms}))
	frame := waitFor(t, c, FrameRooms)
	rooms, _ := frame["rooms"].([]any)
	if len(rooms) != 2 {
		t.Fatalf("rooms = %v, want two", rooms)
	}
}

// Many connections joining, switching and sending at once, run under -race to
// catch anything the channel discipline missed.
func TestConcurrentTraffic(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.RoomIdleTimeout = 5 * time.Millisecond
		c.SweepInterval = 5 * time.Millisecond
	})

	const clients = 8
	done := make(chan struct{})
	for range clients {
		go func() {
			defer func() { done <- struct{}{} }()
			c := NewClient(64)
			s := NewSession(h.reg, c)
			defer s.Close()
			// Keep the queue drained so nothing is closed for being slow.
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				for {
					select {
					case <-c.Out():
					case <-stop:
						return
					case <-c.Closed():
						return
					}
				}
			}()
			rooms := []string{"general", "off-topic"}
			for j := range 20 {
				s.Handle(joinFrame(rooms[j%len(rooms)], 0))
				s.Handle(sendFrame("sam", "hello"))
				s.Handle(encodeFrame(clientFrame{T: FrameRooms}))
			}
		}()
	}
	for range clients {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("concurrent clients did not finish")
		}
	}
}
