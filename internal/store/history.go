// Package store holds a room's history: a warm in-memory ring and a permanent
// JSONL archive on disk.
//
// The server's retention is deliberately modest. Clients are expected to keep
// their own primary store holding far more than either tier, and that
// expectation is what lets the ring stay small and the archive stay a flat
// file.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/slabrant/chapi/internal/envelope"
)

// Config carries a room's retention limits. Every one of these is an
// environment variable rather than a constant.
type Config struct {
	// MaxText is how many text and shush messages the warm ring keeps.
	MaxText int
	// MaxImageBytes bounds the image window by payload bytes, not by count.
	MaxImageBytes int
	// MaxBackfill bounds how many messages one history response may carry.
	MaxBackfill int
}

// Gap is a range of sequences the server could not serve.
//
// A gap is surfaced, never papered over: the server does not silently splice a
// discontinuity, because a client that cannot see the hole cannot recover it.
type Gap struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// History is one room's two-tier history plus the state a restart must
// recover: the sequence counter and the shushed set.
//
// It is owned by the room's goroutine and is not safe for concurrent use.
type History struct {
	ring    *Ring
	archive *Archive
	shushed map[uint64]bool
	lastSeq uint64
	cfg     Config
}

// OpenHistory opens the archive for room under dir and rebuilds its sequence
// counter and shushed set.
func OpenHistory(dir, room string, cfg Config, keys envelope.KeyLookup) (*History, error) {
	if err := ValidateRoomName(room); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: creating data directory %s: %w", dir, err)
	}
	archive, err := OpenArchive(filepath.Join(dir, room+".jsonl"), keys)
	if err != nil {
		return nil, err
	}
	lastSeq, shushed, err := archive.Recover()
	if err != nil {
		archive.Close()
		return nil, err
	}
	return &History{
		ring:    NewRing(cfg.MaxText, cfg.MaxImageBytes),
		archive: archive,
		shushed: shushed,
		lastSeq: lastSeq,
		cfg:     cfg,
	}, nil
}

// LastSeq returns the highest sequence assigned in this room.
func (h *History) LastSeq() uint64 { return h.lastSeq }

// NextSeq reserves and returns the next sequence number.
//
// A room's client set may be garbage collected and its memory evicted, but
// this counter may never restart; it is recovered from the archive instead.
func (h *History) NextSeq() uint64 {
	h.lastSeq++
	return h.lastSeq
}

// Append records a broadcast message in both tiers.
//
// The ring keeps the message as sent, image bytes included. The archive gets
// the archival form, which for an image is the signed header with its payload
// replaced by the placeholder.
func (h *History) Append(m *envelope.Message) error {
	// The counter follows what has actually been written, so it stays correct
	// whether the sequence came from NextSeq or from a recovered archive.
	if m.Header.Seq > h.lastSeq {
		h.lastSeq = m.Header.Seq
	}
	h.ring.Append(m)
	if m.Header.Kind == envelope.KindShush {
		if target, err := envelope.ParseShush(m.Payload); err == nil {
			h.shushed[target] = true
		}
	}
	return h.archive.Append(m.Archival())
}

// IsShushed reports whether a sequence has been shushed.
func (h *History) IsShushed(seq uint64) bool { return h.shushed[seq] }

// Since serves everything newer than the client's newest known sequence.
//
// When the range is longer than one response may carry, the newest window is
// served and the older remainder comes back as a gap, which the client can
// request explicitly with Range.
func (h *History) Since(since uint64) ([]*envelope.Message, []Gap, error) {
	if since >= h.lastSeq {
		return nil, nil, nil
	}
	from, to := since+1, h.lastSeq

	var truncated []Gap
	if limit := uint64(h.cfg.MaxBackfill); limit > 0 && to-from+1 > limit {
		windowStart := to - limit + 1
		truncated = append(truncated, Gap{From: from, To: windowStart - 1})
		from = windowStart
	}

	msgs, gaps, err := h.serve(from, to)
	return msgs, append(truncated, gaps...), err
}

// Range serves an explicitly requested span, oldest-first, so a client can
// walk back through a gap it was told about.
func (h *History) Range(from, to uint64) ([]*envelope.Message, []Gap, error) {
	if from == 0 {
		from = 1
	}
	if to > h.lastSeq {
		to = h.lastSeq
	}
	if from > to {
		return nil, nil, nil
	}

	var truncated []Gap
	if limit := uint64(h.cfg.MaxBackfill); limit > 0 && to-from+1 > limit {
		windowEnd := from + limit - 1
		truncated = append(truncated, Gap{From: windowEnd + 1, To: to})
		to = windowEnd
	}

	msgs, gaps, err := h.serve(from, to)
	return msgs, append(gaps, truncated...), err
}

// serve assembles [from, to] out of the ring, falling back to the archive for
// anything the ring has evicted.
func (h *History) serve(from, to uint64) ([]*envelope.Message, []Gap, error) {
	found := make(map[uint64]*envelope.Message)
	for _, m := range h.ring.Since(from - 1) {
		if m.Header.Seq <= to {
			found[m.Header.Seq] = m
		}
	}

	// The archive is consulted only when the warm ring did not already cover
	// the whole span, which is the common case for a short disconnect.
	if h.missing(from, to, found) {
		archived, err := h.archive.Range(from, to)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range archived {
			// The ring's copy wins: it still has the image bytes the archive
			// dropped.
			if _, ok := found[m.Header.Seq]; !ok {
				found[m.Header.Seq] = m
			}
		}
	}

	msgs := make([]*envelope.Message, 0, len(found))
	var gaps []Gap
	var run *Gap
	for seq := from; seq <= to; seq++ {
		m, ok := found[seq]
		switch {
		case h.shushed[seq]:
			// Withheld on purpose. The shush marker itself travels with its own
			// sequence, so the client learns why rather than seeing a hole.
		case ok:
			msgs = append(msgs, m)
		default:
			if run != nil && run.To == seq-1 {
				run.To = seq
			} else {
				gaps = append(gaps, Gap{From: seq, To: seq})
				run = &gaps[len(gaps)-1]
			}
		}
	}

	slices.SortFunc(msgs, func(a, b *envelope.Message) int {
		return int(a.Header.Seq) - int(b.Header.Seq)
	})
	return msgs, gaps, nil
}

func (h *History) missing(from, to uint64, found map[uint64]*envelope.Message) bool {
	for seq := from; seq <= to; seq++ {
		if _, ok := found[seq]; !ok && !h.shushed[seq] {
			return true
		}
	}
	return false
}

// Close releases the archive handle.
func (h *History) Close() error { return h.archive.Close() }

// MaxRoomNameLen bounds a room name.
const MaxRoomNameLen = 64

// ValidateRoomName rejects names that cannot safely become a filename.
//
// Rooms are created implicitly by joining them, so a room name is untrusted
// input that becomes a path. The character set is restrictive on purpose:
// there is no legitimate room name that needs a separator, a dot, or a
// non-ASCII character, and allowing any of them turns room creation into
// arbitrary file creation.
func ValidateRoomName(name string) error {
	if name == "" {
		return fmt.Errorf("store: empty room name")
	}
	if len(name) > MaxRoomNameLen {
		return fmt.Errorf("store: room name longer than %d bytes", MaxRoomNameLen)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("store: room name %q may use only a-z, 0-9, - and _", name)
		}
	}
	return nil
}

// RoomNames lists the rooms that already have an archive on disk.
func RoomNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: listing data directory %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".jsonl")
		if ValidateRoomName(name) == nil {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}
