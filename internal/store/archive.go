package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/slabrant/chapi/internal/envelope"
)

// maxLine bounds a single archive record. Image bytes never reach disk, so a
// line is a header plus text; a megabyte is far past generous.
const maxLine = 1 << 20

// repairAttempts bounds the torn-tail loop. Only the final line can be torn
// under O_APPEND with a single writer, so one pass suffices in practice.
const repairAttempts = 8

// Archive is a room's permanent history: one JSONL file, opened O_APPEND, one
// message per line, written only by the owning room's goroutine.
//
// Monotonic sequence plus append-only means the file is sorted by sequence by
// construction, so serving a historical range is a scan rather than an index
// lookup.
type Archive struct {
	path string
	f    *os.File
	keys envelope.KeyLookup
}

// OpenArchive opens or creates the archive at path, discarding a torn final
// line left by a crash.
func OpenArchive(path string, keys envelope.KeyLookup) (*Archive, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: opening archive %s: %w", path, err)
	}
	if err := repairTail(f); err != nil {
		f.Close()
		return nil, err
	}
	return &Archive{path: path, f: f, keys: keys}, nil
}

// repairTail truncates a trailing partial or unparseable record.
//
// This is the whole of crash recovery. A torn write leaves either a line with
// no terminating newline or a line that is not valid JSON; both are dropped,
// and the messages before them are untouched because nothing ever rewrites
// them.
func repairTail(f *os.File) error {
	for range repairAttempts {
		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("store: stat archive: %w", err)
		}
		size := info.Size()
		if size == 0 {
			return nil
		}

		start, line, err := lastLine(f, size)
		if err != nil {
			return err
		}

		terminated := len(line) > 0 && line[len(line)-1] == '\n'
		record := line
		if terminated {
			record = record[:len(record)-1]
		}

		if terminated && json.Valid(record) {
			return nil
		}
		if err := f.Truncate(start); err != nil {
			return fmt.Errorf("store: truncating torn record: %w", err)
		}
	}
	return errors.New("store: archive tail still unparseable after repair")
}

// lastLine returns the offset and bytes of the final line in the file,
// including its newline if it has one.
func lastLine(f *os.File, size int64) (int64, []byte, error) {
	const chunk = 4096

	// Search backwards for the newline that ends the second-to-last record.
	end := size
	if b := make([]byte, 1); size > 0 {
		if _, err := f.ReadAt(b, size-1); err != nil {
			return 0, nil, fmt.Errorf("store: reading archive tail: %w", err)
		}
		if b[0] == '\n' {
			end = size - 1 // ignore the terminator of the line we are looking for
		}
	}

	start := int64(0)
	for off := end; off > 0; {
		n := int64(chunk)
		if off < n {
			n = off
		}
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off-n); err != nil && !errors.Is(err, io.EOF) {
			return 0, nil, fmt.Errorf("store: reading archive tail: %w", err)
		}
		found := false
		for i := len(buf) - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				start = off - n + int64(i) + 1
				found = true
				break
			}
		}
		if found {
			break
		}
		off -= n
	}

	line := make([]byte, size-start)
	if _, err := f.ReadAt(line, start); err != nil && !errors.Is(err, io.EOF) {
		return 0, nil, fmt.Errorf("store: reading archive tail: %w", err)
	}
	return start, line, nil
}

// Append writes a message to the archive.
//
// The caller is responsible for passing the archival form; images must have
// been stripped already. The record is written in one call so an interrupted
// write can only ever truncate the tail, never interleave.
func (a *Archive) Append(m *envelope.Message) error {
	line := make([]byte, 0, len(m.Wire())+1)
	line = append(line, m.Wire()...)
	line = append(line, '\n')
	if _, err := a.f.Write(line); err != nil {
		return fmt.Errorf("store: appending to %s: %w", a.path, err)
	}
	return nil
}

// record is the cheap view of an archive line: enough to locate a message by
// sequence without paying for signature verification.
type record struct {
	seq     uint64
	kind    envelope.Kind
	payload string
}

type peekOuter struct {
	H string `json:"h"`
	P string `json:"p"`
}

type peekHeader struct {
	Seq  uint64        `json:"seq"`
	Kind envelope.Kind `json:"kind"`
}

func peek(line []byte) (record, error) {
	var outer peekOuter
	if err := json.Unmarshal(line, &outer); err != nil {
		return record{}, fmt.Errorf("store: malformed archive line: %w", err)
	}
	var header peekHeader
	if err := json.Unmarshal([]byte(outer.H), &header); err != nil {
		return record{}, fmt.Errorf("store: malformed archive header: %w", err)
	}
	return record{seq: header.Seq, kind: header.Kind, payload: outer.P}, nil
}

// scan walks the archive from the start, calling fn for each parseable record.
// fn returns false to stop early, which the sorted-by-sequence property makes
// worthwhile: a range request stops as soon as it passes its upper bound.
func (a *Archive) scan(fn func(rec record, line []byte) bool) error {
	f, err := os.Open(a.path)
	if err != nil {
		return fmt.Errorf("store: reading archive %s: %w", a.path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		rec, err := peek(line)
		if err != nil {
			// A record that does not parse is one a crash left behind. Skip it
			// rather than failing the whole read.
			continue
		}
		if !fn(rec, line) {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("store: scanning archive %s: %w", a.path, err)
	}
	return nil
}

// Recover reads the archive to rebuild the state a restart loses: the room's
// sequence counter and its set of shushed sequences.
//
// The counter must never restart. A room that resets to zero hands clients
// duplicate keys for distinct messages and breaks gap detection permanently,
// which is why every sequence — including images whose bytes were dropped —
// appears in this file.
func (a *Archive) Recover() (lastSeq uint64, shushed map[uint64]bool, err error) {
	shushed = make(map[uint64]bool)
	err = a.scan(func(rec record, _ []byte) bool {
		if rec.seq > lastSeq {
			lastSeq = rec.seq
		}
		if rec.kind == envelope.KindShush {
			if target, perr := envelope.ParseShush(rec.payload); perr == nil {
				shushed[target] = true
			}
		}
		return true
	})
	return lastSeq, shushed, err
}

// Range returns archived messages with sequences in [from, to], verified.
//
// Verification is not free, so it is paid only for records actually being
// served; locating them uses the cheap header peek instead.
func (a *Archive) Range(from, to uint64) ([]*envelope.Message, error) {
	var out []*envelope.Message
	err := a.scan(func(rec record, line []byte) bool {
		if rec.seq < from {
			return true
		}
		if rec.seq > to {
			return false // sorted by construction, so nothing further qualifies
		}
		m, err := envelope.Open(line, a.keys)
		if err != nil {
			// A record that does not verify is corrupt, not authentic history.
			// Leaving it out turns it into a gap the client is told about.
			return true
		}
		out = append(out, m)
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Close releases the append handle.
func (a *Archive) Close() error { return a.f.Close() }
