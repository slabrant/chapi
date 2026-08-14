package store

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/slabrant/chapi/internal/envelope"
)

type fixture struct {
	signer *envelope.Signer
	keys   envelope.KeyLookup
	dir    string
	seq    uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	s := envelope.NewSigner("k1", priv)
	return &fixture{signer: s, keys: envelope.SingleKey("k1", s.Public()), dir: t.TempDir()}
}

func (f *fixture) seal(t *testing.T, seq uint64, kind envelope.Kind, payload string) *envelope.Message {
	t.Helper()
	h := envelope.Header{Room: "general", Seq: seq, TS: 1755130000, Nick: "sam", Kind: kind}
	if kind == envelope.KindImage {
		h.Mime = "image/jpeg"
		h.W, h.H = 10, 10
	}
	m, err := f.signer.Seal(h, payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return m
}

func (f *fixture) text(t *testing.T, body string) *envelope.Message {
	t.Helper()
	f.seq++
	return f.seal(t, f.seq, envelope.KindText, body)
}

func (f *fixture) image(t *testing.T, bytes int) *envelope.Message {
	t.Helper()
	f.seq++
	return f.seal(t, f.seq, envelope.KindImage, base64.StdEncoding.EncodeToString(make([]byte, bytes)))
}

func (f *fixture) history(t *testing.T, cfg Config) *History {
	t.Helper()
	h, err := OpenHistory(f.dir, "general", cfg, f.keys)
	if err != nil {
		t.Fatalf("OpenHistory: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func seqs(msgs []*envelope.Message) []uint64 {
	out := make([]uint64, len(msgs))
	for i, m := range msgs {
		out[i] = m.Header.Seq
	}
	return out
}

func equalSeqs(got []uint64, want ...uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestRingEvictsTextByCount(t *testing.T) {
	f := newFixture(t)
	r := NewRing(3, 1<<20)
	for range 5 {
		r.Append(f.text(t, "hello"))
	}
	if got := seqs(r.Since(0)); !equalSeqs(got, 3, 4, 5) {
		t.Fatalf("retained %v, want [3 4 5]", got)
	}
}

func TestRingEvictsImagesByBytes(t *testing.T) {
	f := newFixture(t)
	// Each payload is base64 of 300 bytes, so 400 encoded bytes.
	r := NewRing(1000, 900)
	for range 4 {
		r.Append(f.image(t, 300))
	}
	if r.ImageBytes() > 900 {
		t.Fatalf("image window is %d bytes, over the 900 budget", r.ImageBytes())
	}
	if got := seqs(r.Since(0)); !equalSeqs(got, 3, 4) {
		t.Fatalf("retained %v, want [3 4]", got)
	}
}

// The sub-rings hold different spans, so a read has to merge them rather than
// concatenate: text older than every retained image is the normal case.
func TestRingMergesTextAndImagesInSequenceOrder(t *testing.T) {
	f := newFixture(t)
	r := NewRing(1000, 1<<20)
	r.Append(f.text(t, "one"))
	r.Append(f.image(t, 10))
	r.Append(f.text(t, "two"))
	r.Append(f.image(t, 10))
	if got := seqs(r.Since(0)); !equalSeqs(got, 1, 2, 3, 4) {
		t.Fatalf("order %v, want [1 2 3 4]", got)
	}
	if got := seqs(r.Since(2)); !equalSeqs(got, 3, 4) {
		t.Fatalf("Since(2) = %v, want [3 4]", got)
	}
}

func TestRingSurvivesHeavyEviction(t *testing.T) {
	f := newFixture(t)
	r := NewRing(4, 1<<20)
	for range 200 {
		r.Append(f.text(t, "x"))
	}
	if r.Len() != 4 {
		t.Fatalf("Len = %d, want 4", r.Len())
	}
	if got := seqs(r.Since(0)); !equalSeqs(got, 197, 198, 199, 200) {
		t.Fatalf("retained %v, want the last four", got)
	}
}

// The counter is the key clients index history by. A room that restarts it
// hands out duplicate keys for distinct messages and breaks gap detection
// permanently, so this is the invariant the archive exists to protect.
func TestSequenceCounterSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 1000}

	h := f.history(t, cfg)
	for range 3 {
		if err := h.Append(f.text(t, "hello")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if h.LastSeq() != 3 {
		t.Fatalf("LastSeq = %d, want 3", h.LastSeq())
	}
	h.Close()

	reopened := f.history(t, cfg)
	if reopened.LastSeq() != 3 {
		t.Fatalf("LastSeq after restart = %d, want 3", reopened.LastSeq())
	}
	if next := reopened.NextSeq(); next != 4 {
		t.Fatalf("NextSeq after restart = %d, want 4", next)
	}
}

// Images have no bytes on disk, but they must still occupy their sequence or
// the counter could not be recovered from the file.
func TestEverySequenceAppearsInArchive(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 1000}

	h := f.history(t, cfg)
	if err := h.Append(f.text(t, "one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := h.Append(f.image(t, 64)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := h.Append(f.text(t, "three")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	h.Close()

	raw, err := os.ReadFile(filepath.Join(f.dir, "general.jsonl"))
	if err != nil {
		t.Fatalf("reading archive: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("archive has %d lines, want 3", len(lines))
	}
	if strings.Contains(lines[1], base64.StdEncoding.EncodeToString(make([]byte, 64))) {
		t.Error("image bytes were written to the archive")
	}
}

func TestArchiveFallbackServesStrippedImage(t *testing.T) {
	f := newFixture(t)
	// A ring too small to keep any image, so the read must fall through.
	cfg := Config{MaxText: 100, MaxImageBytes: 0, MaxBackfill: 1000}
	h := f.history(t, cfg)

	if err := h.Append(f.text(t, "one")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := h.Append(f.image(t, 64)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	msgs, gaps, err := h.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none: the archive can serve the header", gaps)
	}
	if !equalSeqs(seqs(msgs), 1, 2) {
		t.Fatalf("served %v, want [1 2]", seqs(msgs))
	}
	if !msgs[1].Stripped() {
		t.Error("archived image was not served as a stripped record")
	}
	if msgs[1].Header.W != 10 || msgs[1].Header.Mime != "image/jpeg" {
		t.Error("stripped image lost the dimensions a client needs to lay it out")
	}
}

// Because the archive is complete for text, a gap is a rare answer rather than
// a routine one. Deleting the archive is one of the few ways to produce one.
func TestGapReportedWhenArchiveCannotServe(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 2, MaxImageBytes: 0, MaxBackfill: 1000}
	h := f.history(t, cfg)

	for range 5 {
		if err := h.Append(f.text(t, "hello")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// Truncate the archive so the evicted head is genuinely unserveable.
	if err := os.Truncate(filepath.Join(f.dir, "general.jsonl"), 0); err != nil {
		t.Fatalf("truncating archive: %v", err)
	}

	msgs, gaps, err := h.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !equalSeqs(seqs(msgs), 4, 5) {
		t.Fatalf("served %v, want the ring's [4 5]", seqs(msgs))
	}
	if len(gaps) != 1 || gaps[0].From != 1 || gaps[0].To != 3 {
		t.Fatalf("gaps = %v, want one covering 1-3", gaps)
	}
}

func TestShushWithholdsMessageButKeepsMarker(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 1000}
	h := f.history(t, cfg)

	for range 3 {
		if err := h.Append(f.text(t, "hello")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	f.seq++
	marker := f.seal(t, f.seq, envelope.KindShush, envelope.MarshalShush(2))
	if err := h.Append(marker); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if !h.IsShushed(2) {
		t.Error("IsShushed(2) = false after shushing it")
	}
	msgs, gaps, err := h.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	// Sequence 2 is withheld and is not a gap: the marker explains the absence.
	if !equalSeqs(seqs(msgs), 1, 3, 4) {
		t.Fatalf("served %v, want [1 3 4]", seqs(msgs))
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none for a shushed message", gaps)
	}
}

func TestShushSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 1000}

	h := f.history(t, cfg)
	if err := h.Append(f.text(t, "hello")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	f.seq++
	if err := h.Append(f.seal(t, f.seq, envelope.KindShush, envelope.MarshalShush(1))); err != nil {
		t.Fatalf("Append: %v", err)
	}
	h.Close()

	reopened := f.history(t, cfg)
	if !reopened.IsShushed(1) {
		t.Error("shush did not survive a restart")
	}
	msgs, _, err := reopened.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !equalSeqs(seqs(msgs), 2) {
		t.Fatalf("served %v, want only the marker [2]", seqs(msgs))
	}
}

// Crash recovery is meant to be free: the torn record fails to parse and is
// discarded, and everything written before it is untouched.
func TestTornFinalRecordIsDiscarded(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 1000}

	h := f.history(t, cfg)
	for range 2 {
		if err := h.Append(f.text(t, "hello")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	h.Close()

	path := filepath.Join(f.dir, "general.jsonl")
	torn := f.seal(t, 3, envelope.KindText, "interrupted")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	half := torn.Wire()[:len(torn.Wire())/2]
	if _, err := file.Write(half); err != nil {
		t.Fatalf("writing torn record: %v", err)
	}
	file.Close()

	reopened := f.history(t, cfg)
	if reopened.LastSeq() != 2 {
		t.Fatalf("LastSeq = %d, want 2: the torn record should be gone", reopened.LastSeq())
	}
	msgs, gaps, err := reopened.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !equalSeqs(seqs(msgs), 1, 2) {
		t.Fatalf("served %v, want [1 2]", seqs(msgs))
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none", gaps)
	}

	// The next append must land cleanly after the truncation, not after debris.
	if err := reopened.Append(f.seal(t, reopened.NextSeq(), envelope.KindText, "after")); err != nil {
		t.Fatalf("Append after recovery: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading archive: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("archive has %d lines, want 3", len(lines))
	}
}

func TestBackfillCapTruncatesToNewestWindow(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 3}
	h := f.history(t, cfg)

	for range 10 {
		if err := h.Append(f.text(t, "hello")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	msgs, gaps, err := h.Since(0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !equalSeqs(seqs(msgs), 8, 9, 10) {
		t.Fatalf("served %v, want the newest three", seqs(msgs))
	}
	if len(gaps) != 1 || gaps[0].From != 1 || gaps[0].To != 7 {
		t.Fatalf("gaps = %v, want one covering 1-7", gaps)
	}

	// The client can then walk back through the gap it was told about.
	older, olderGaps, err := h.Range(1, 7)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if !equalSeqs(seqs(older), 1, 2, 3) {
		t.Fatalf("Range served %v, want [1 2 3]", seqs(older))
	}
	if len(olderGaps) != 1 || olderGaps[0].From != 4 || olderGaps[0].To != 7 {
		t.Fatalf("Range gaps = %v, want one covering 4-7", olderGaps)
	}
}

func TestSinceUpToDateClientGetsNothing(t *testing.T) {
	f := newFixture(t)
	h := f.history(t, Config{MaxText: 100, MaxImageBytes: 1 << 20, MaxBackfill: 1000})
	if err := h.Append(f.text(t, "hello")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	msgs, gaps, err := h.Since(1)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(msgs) != 0 || len(gaps) != 0 {
		t.Fatalf("Since(1) = %v, %v, want nothing", seqs(msgs), gaps)
	}
}

// Rooms are created by joining them, so the name is untrusted input that
// becomes a filename.
func TestValidateRoomName(t *testing.T) {
	valid := []string{"general", "off-topic", "room_2", "a", strings.Repeat("a", MaxRoomNameLen)}
	for _, name := range valid {
		if err := ValidateRoomName(name); err != nil {
			t.Errorf("ValidateRoomName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"", "../etc/passwd", "a/b", "a.b", "General", "room name", "café",
		strings.Repeat("a", MaxRoomNameLen+1), ".", "..", "room\x00",
	}
	for _, name := range invalid {
		if err := ValidateRoomName(name); err == nil {
			t.Errorf("ValidateRoomName(%q) = nil, want an error", name)
		}
	}
}

func TestOpenHistoryRejectsUnsafeRoomName(t *testing.T) {
	f := newFixture(t)
	if _, err := OpenHistory(f.dir, "../escape", Config{MaxText: 1, MaxBackfill: 1}, f.keys); err == nil {
		t.Fatal("OpenHistory accepted a traversing room name")
	}
}

func TestRoomNames(t *testing.T) {
	f := newFixture(t)
	cfg := Config{MaxText: 10, MaxImageBytes: 1 << 20, MaxBackfill: 10}
	for _, room := range []string{"general", "off-topic"} {
		h, err := OpenHistory(f.dir, room, cfg, f.keys)
		if err != nil {
			t.Fatalf("OpenHistory(%s): %v", room, err)
		}
		h.Close()
	}
	if err := os.WriteFile(filepath.Join(f.dir, "notes.txt"), []byte("ignore me"), 0o600); err != nil {
		t.Fatalf("writing decoy: %v", err)
	}

	names, err := RoomNames(f.dir)
	if err != nil {
		t.Fatalf("RoomNames: %v", err)
	}
	if len(names) != 2 || names[0] != "general" || names[1] != "off-topic" {
		t.Fatalf("RoomNames = %v, want [general off-topic]", names)
	}
}
