package envelope

import (
	"encoding/json"
	"fmt"
)

// ShushRef is the payload of a shush marker: the sequence number being
// shushed. It rides in the payload rather than the header so it is covered by
// the header's hash, and so the header shape stays the same for every kind.
type ShushRef struct {
	Seq uint64 `json:"seq"`
}

// MarshalShush renders the payload of a shush marker referencing seq.
//
// The referenced sequence is in the shushing message's own room. Sequence
// numbers are per-room, so a cross-room reference has nothing to resolve
// against.
func MarshalShush(seq uint64) string {
	b, err := json.Marshal(ShushRef{Seq: seq})
	if err != nil {
		panic("envelope: encoding shush ref: " + err.Error())
	}
	return string(b)
}

// ParseShush reads the sequence a shush marker refers to.
func ParseShush(payload string) (uint64, error) {
	var ref ShushRef
	if err := json.Unmarshal([]byte(payload), &ref); err != nil {
		return 0, fmt.Errorf("%w: shush payload: %v", ErrMalformed, err)
	}
	if ref.Seq == 0 {
		return 0, fmt.Errorf("%w: shush references sequence 0", ErrMalformed)
	}
	return ref.Seq, nil
}
