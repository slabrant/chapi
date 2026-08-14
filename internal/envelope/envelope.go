// Package envelope defines the message wire format and the rules for signing
// and verifying it.
//
// A message is a signed header plus an unsigned payload bound to the header by
// hash:
//
//	{"h": "<header JSON, signed verbatim>", "sig": "<base64 Ed25519>", "p": "<payload>"}
//
// The split is load-bearing. The signature covers only the header, so an image
// message can have its payload stripped for archival and the record still
// verifies. A stripped image is a known-authentic record of an image whose
// bytes are gone, rather than a signature failure.
//
// Signatures attest that the server broadcast this content at this sequence.
// They do not attest identity: nicknames are client-supplied and the server
// signs whatever it is told.
package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Version is the schema version stamped into every header. It is inside the
// signature, so a client can trust it and treat a bump as a migration rather
// than a break.
const Version = 1

// Kind enumerates the message kinds.
type Kind string

const (
	KindText  Kind = "text"
	KindImage Kind = "image"
	KindShush Kind = "shush"
)

// Valid reports whether k is a kind this schema version defines.
func (k Kind) Valid() bool {
	switch k {
	case KindText, KindImage, KindShush:
		return true
	}
	return false
}

// PayloadStripped is what an image payload is replaced by on the way to disk.
// Image bytes are never written to the archive; the signed header is, and it
// still verifies.
//
// The empty string is unambiguous as a sentinel only because text and shush
// payloads are rejected when empty. See Header.Validate.
const PayloadStripped = ""

var (
	ErrMalformed    = errors.New("envelope: malformed")
	ErrUnknownKey   = errors.New("envelope: unknown keyid")
	ErrBadSignature = errors.New("envelope: signature does not verify")
	ErrHashMismatch = errors.New("envelope: payload does not match header hash")
)

// Header is the signed part of a message.
//
// Field order here is the order they are serialized in, and those exact bytes
// are what gets signed. Nothing may re-serialize a header and expect the
// signature to hold.
type Header struct {
	V     int    `json:"v"`
	Room  string `json:"room"`
	Seq   uint64 `json:"seq"`
	TS    int64  `json:"ts"`
	Nick  string `json:"nick"`
	Kind  Kind   `json:"kind"`
	Hash  string `json:"hash"`
	KeyID string `json:"keyid"`

	// Image messages carry enough to reserve layout space before the payload
	// lands, and to still describe an image whose bytes are gone.
	Mime string `json:"mime,omitempty"`
	W    int    `json:"w,omitempty"`
	H    int    `json:"h,omitempty"`
}

// Validate checks the fields a peer supplies. The server fills in the rest.
func (h Header) Validate() error {
	if !h.Kind.Valid() {
		return fmt.Errorf("%w: unknown kind %q", ErrMalformed, h.Kind)
	}
	if h.Room == "" {
		return fmt.Errorf("%w: empty room", ErrMalformed)
	}
	if h.Nick == "" {
		return fmt.Errorf("%w: empty nick", ErrMalformed)
	}
	if h.Kind == KindImage && h.Mime == "" {
		return fmt.Errorf("%w: image without mime", ErrMalformed)
	}
	return nil
}

// Message is a sealed message: the header, the exact bytes that were signed,
// the signature, and the payload.
//
// A Message is immutable once sealed and is shared by reference across every
// outbound queue it is broadcast to. Image payloads are never copied per
// client.
type Message struct {
	Header    Header
	RawHeader []byte
	Sig       []byte
	Payload   string

	wire []byte
}

// wireEnvelope is the on-the-wire shape. The header travels as a string so it
// survives transit byte-for-byte.
type wireEnvelope struct {
	H   string `json:"h"`
	Sig string `json:"sig"`
	P   string `json:"p"`
}

// HashPayload returns the hex sha256 of the payload's UTF-8 bytes exactly as
// transmitted. For images that is the base64 string, not the decoded bytes:
// slightly wasteful, but it means anything stored or re-served byte-for-byte
// can never fail its own hash.
func HashPayload(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// Wire returns the encoded envelope. It is computed once at seal time and
// shared, so a broadcast serializes a message once regardless of audience.
func (m *Message) Wire() []byte { return m.wire }

// Stripped reports whether this message's payload has been replaced by the
// archival placeholder. Such a record is authentic, not forged.
func (m *Message) Stripped() bool {
	return m.Header.Kind == KindImage && m.Payload == PayloadStripped
}

// Archival returns the form of m that belongs on disk. Image bytes never reach
// the archive; everything else is stored as broadcast.
//
// The returned message carries the same signed header bytes and the same
// signature, so it verifies exactly as the original did.
func (m *Message) Archival() *Message {
	if m.Header.Kind != KindImage || m.Stripped() {
		return m
	}
	stripped := &Message{
		Header:    m.Header,
		RawHeader: m.RawHeader,
		Sig:       m.Sig,
		Payload:   PayloadStripped,
	}
	stripped.wire = encodeWire(stripped)
	return stripped
}

func encodeWire(m *Message) []byte {
	b, err := json.Marshal(wireEnvelope{
		H:   string(m.RawHeader),
		Sig: base64.StdEncoding.EncodeToString(m.Sig),
		P:   m.Payload,
	})
	if err != nil {
		// The inputs are three strings; marshalling them cannot fail.
		panic("envelope: encoding wire form: " + err.Error())
	}
	return b
}

// Signer seals messages with the server's Ed25519 key.
//
// The signing key is never derived from the shared password: verification
// requires handing every client the public key, and any shared-secret scheme
// would hand them forging power along with it.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewSigner returns a Signer that stamps keyID into every header it seals.
func NewSigner(keyID string, priv ed25519.PrivateKey) *Signer {
	return &Signer{keyID: keyID, priv: priv}
}

// KeyID returns the identifier stamped into sealed headers.
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the verifying key, which the server advertises at login.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Seal fills in the server-owned header fields, serializes the header once,
// and signs those exact bytes.
//
// The caller supplies Room, Seq, TS, Nick, Kind and any image dimensions. V,
// KeyID and Hash are set here and overwrite whatever was passed.
func (s *Signer) Seal(h Header, payload string) (*Message, error) {
	if payload == "" {
		// Keeps PayloadStripped unambiguous: an empty payload can only ever be
		// the archival placeholder, never something a peer sent.
		return nil, fmt.Errorf("%w: empty payload", ErrMalformed)
	}
	h.V = Version
	h.KeyID = s.keyID
	h.Hash = HashPayload(payload)
	if err := h.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshalling header: %w", err)
	}
	m := &Message{
		Header:    h,
		RawHeader: raw,
		Sig:       ed25519.Sign(s.priv, raw),
		Payload:   payload,
	}
	m.wire = encodeWire(m)
	return m, nil
}

// KeyLookup resolves a keyid to its public key, so old messages keep verifying
// across a key rotation.
type KeyLookup func(keyID string) (ed25519.PublicKey, bool)

// SingleKey is a KeyLookup for a server running one signing key.
func SingleKey(keyID string, pub ed25519.PublicKey) KeyLookup {
	return func(id string) (ed25519.PublicKey, bool) {
		if id != keyID {
			return nil, false
		}
		return pub, true
	}
}

// Open parses and verifies an encoded envelope.
//
// Verification happens against the header string before that string is parsed.
// JSON has no canonical form, so verify-then-parse is what keeps
// canonicalization from being a latent problem: no party ever needs to
// reproduce the exact bytes the server signed.
//
// A stripped image payload is accepted without a hash check, because its bytes
// are gone by design.
func Open(data []byte, keys KeyLookup) (*Message, error) {
	var w wireEnvelope
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if w.H == "" {
		return nil, fmt.Errorf("%w: missing header", ErrMalformed)
	}
	sig, err := base64.StdEncoding.DecodeString(w.Sig)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64: %v", ErrMalformed, err)
	}

	// Peek at keyid to pick the verifying key. This parse is untrusted and its
	// result is used for nothing but key selection; the authoritative parse
	// happens below, after the signature holds.
	var peek struct {
		KeyID string `json:"keyid"`
	}
	if err := json.Unmarshal([]byte(w.H), &peek); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON: %v", ErrMalformed, err)
	}
	pub, ok := keys(peek.KeyID)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, peek.KeyID)
	}

	raw := []byte(w.H)
	if !ed25519.Verify(pub, raw, sig) {
		return nil, ErrBadSignature
	}

	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON: %v", ErrMalformed, err)
	}

	m := &Message{Header: h, RawHeader: raw, Sig: sig, Payload: w.P}
	if !m.Stripped() && h.Hash != HashPayload(w.P) {
		return nil, ErrHashMismatch
	}
	m.wire = append([]byte(nil), data...)
	return m, nil
}
