package envelope

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testSigner(t *testing.T, keyID string) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return NewSigner(keyID, priv)
}

func textHeader() Header {
	return Header{Room: "general", Seq: 1234, TS: 1755130000, Nick: "sam", Kind: KindText}
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := testSigner(t, "k1")
	keys := SingleKey("k1", s.Public())

	sealed, err := s.Seal(textHeader(), "hello")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := Open(sealed.Wire(), keys)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Payload != "hello" {
		t.Errorf("payload = %q, want %q", got.Payload, "hello")
	}
	if got.Header.Seq != 1234 {
		t.Errorf("seq = %d, want 1234", got.Header.Seq)
	}
	if got.Header.V != Version {
		t.Errorf("v = %d, want %d", got.Header.V, Version)
	}
	if got.Header.KeyID != "k1" {
		t.Errorf("keyid = %q, want k1", got.Header.KeyID)
	}
}

// The signature must cover the bytes as transmitted, so a header that has been
// re-serialized on the way through must not verify. This is the property that
// lets clients skip canonicalization entirely.
func TestReserializedHeaderFailsVerification(t *testing.T) {
	s := testSigner(t, "k1")
	keys := SingleKey("k1", s.Public())

	sealed, err := s.Seal(textHeader(), "hello")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Re-serialize the header through a generic map, the way a naive relay or
	// a client written in another language would.
	var generic map[string]any
	if err := json.Unmarshal(sealed.RawHeader, &generic); err != nil {
		t.Fatalf("unmarshalling header: %v", err)
	}
	rebuilt, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshalling header: %v", err)
	}
	if string(rebuilt) == string(sealed.RawHeader) {
		t.Skip("re-serialization happened to be byte-identical on this build")
	}

	tampered, err := json.Marshal(wireEnvelope{
		H:   string(rebuilt),
		Sig: base64.StdEncoding.EncodeToString(sealed.Sig),
		P:   sealed.Payload,
	})
	if err != nil {
		t.Fatalf("marshalling envelope: %v", err)
	}
	if _, err := Open(tampered, keys); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Open of re-serialized header: err = %v, want ErrBadSignature", err)
	}
}

func TestTamperedPayloadFailsHash(t *testing.T) {
	s := testSigner(t, "k1")
	keys := SingleKey("k1", s.Public())

	sealed, err := s.Seal(textHeader(), "hello")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	swapped, err := json.Marshal(wireEnvelope{
		H:   string(sealed.RawHeader),
		Sig: base64.StdEncoding.EncodeToString(sealed.Sig),
		P:   "goodbye",
	})
	if err != nil {
		t.Fatalf("marshalling envelope: %v", err)
	}
	if _, err := Open(swapped, keys); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Open with swapped payload: err = %v, want ErrHashMismatch", err)
	}
}

func TestTamperedHeaderFailsSignature(t *testing.T) {
	s := testSigner(t, "k1")
	keys := SingleKey("k1", s.Public())

	sealed, err := s.Seal(textHeader(), "hello")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Bump the sequence number without touching anything else.
	forged := strings.Replace(string(sealed.RawHeader), `"seq":1234`, `"seq":9999`, 1)
	if forged == string(sealed.RawHeader) {
		t.Fatal("test did not modify the header")
	}
	tampered, err := json.Marshal(wireEnvelope{
		H:   forged,
		Sig: base64.StdEncoding.EncodeToString(sealed.Sig),
		P:   sealed.Payload,
	})
	if err != nil {
		t.Fatalf("marshalling envelope: %v", err)
	}
	if _, err := Open(tampered, keys); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Open with forged seq: err = %v, want ErrBadSignature", err)
	}
}

// An archived image keeps its header and signature and loses only its bytes.
// The record must still verify, or history would be full of apparent forgeries.
func TestStrippedImageStillVerifies(t *testing.T) {
	s := testSigner(t, "k1")
	keys := SingleKey("k1", s.Public())

	h := Header{
		Room: "general", Seq: 7, TS: 1755130000, Nick: "sam",
		Kind: KindImage, Mime: "image/jpeg", W: 800, H: 600,
	}
	sealed, err := s.Seal(h, base64.StdEncoding.EncodeToString([]byte("pretend jpeg")))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	archived := sealed.Archival()
	if !archived.Stripped() {
		t.Fatal("Archival() did not strip the payload")
	}
	if string(archived.RawHeader) != string(sealed.RawHeader) {
		t.Error("Archival() changed the signed header bytes")
	}

	got, err := Open(archived.Wire(), keys)
	if err != nil {
		t.Fatalf("Open of stripped image: %v", err)
	}
	if !got.Stripped() {
		t.Error("reopened archived image is not reported as stripped")
	}
	if got.Header.W != 800 || got.Header.H != 600 || got.Header.Mime != "image/jpeg" {
		t.Error("stripped image lost its dimensions")
	}
	// The header still carries the hash of bytes that no longer exist, which is
	// exactly what makes the record re-verifiable if the bytes ever come back.
	if got.Header.Hash != sealed.Header.Hash {
		t.Error("stripped image lost its payload hash")
	}
}

func TestArchivalLeavesTextAlone(t *testing.T) {
	s := testSigner(t, "k1")
	sealed, err := s.Seal(textHeader(), "hello")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed.Archival() != sealed {
		t.Error("Archival() copied a text message instead of returning it as-is")
	}
}

// Hashing what is transmitted, rather than what it decodes to, is what lets a
// stored record be re-served byte-for-byte without ever failing its own hash.
func TestHashCoversPayloadAsTransmitted(t *testing.T) {
	raw := []byte{0x00, 0xff, 0x10}
	encoded := base64.StdEncoding.EncodeToString(raw)
	if HashPayload(encoded) == HashPayload(string(raw)) {
		t.Fatal("hash of base64 string matches hash of decoded bytes")
	}
}

func TestUnknownKeyIDRejected(t *testing.T) {
	s := testSigner(t, "k2")
	sealed, err := s.Seal(textHeader(), "hello")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(sealed.Wire(), SingleKey("k1", s.Public())); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Open with unknown keyid: err = %v, want ErrUnknownKey", err)
	}
}

// Rotation is the reason keyid is on every message: messages signed by a
// retired key keep verifying as long as the lookup still knows it.
func TestKeyRotationKeepsOldMessagesVerifiable(t *testing.T) {
	old := testSigner(t, "k1")
	current := testSigner(t, "k2")

	keys := func(id string) (ed25519.PublicKey, bool) {
		switch id {
		case "k1":
			return old.Public(), true
		case "k2":
			return current.Public(), true
		}
		return nil, false
	}

	sealedOld, err := old.Seal(textHeader(), "from before the rotation")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealedNew, err := current.Seal(textHeader(), "from after")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	for _, m := range []*Message{sealedOld, sealedNew} {
		if _, err := Open(m.Wire(), keys); err != nil {
			t.Errorf("Open(keyid=%s): %v", m.Header.KeyID, err)
		}
	}
}

func TestSealRejectsEmptyPayload(t *testing.T) {
	s := testSigner(t, "k1")
	if _, err := s.Seal(textHeader(), ""); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Seal with empty payload: err = %v, want ErrMalformed", err)
	}
}

func TestSealRejectsInvalidHeaders(t *testing.T) {
	s := testSigner(t, "k1")
	tests := []struct {
		name string
		h    Header
	}{
		{"unknown kind", Header{Room: "general", Nick: "sam", Kind: "bogus"}},
		{"empty room", Header{Nick: "sam", Kind: KindText}},
		{"empty nick", Header{Room: "general", Kind: KindText}},
		{"image without mime", Header{Room: "general", Nick: "sam", Kind: KindImage}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.Seal(tt.h, "x"); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestShushRoundTrip(t *testing.T) {
	payload := MarshalShush(42)
	seq, err := ParseShush(payload)
	if err != nil {
		t.Fatalf("ParseShush: %v", err)
	}
	if seq != 42 {
		t.Errorf("seq = %d, want 42", seq)
	}
	if _, err := ParseShush("not json"); !errors.Is(err, ErrMalformed) {
		t.Errorf("ParseShush of garbage: err = %v, want ErrMalformed", err)
	}
	if _, err := ParseShush(`{"seq":0}`); !errors.Is(err, ErrMalformed) {
		t.Errorf("ParseShush of zero seq: err = %v, want ErrMalformed", err)
	}
}
