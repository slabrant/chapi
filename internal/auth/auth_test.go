package auth

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func testAuth(t *testing.T, epoch uint32) *Authenticator {
	t.Helper()
	a, err := New("hunter2", []byte("0123456789abcdef0123456789abcdef"), epoch, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestCheckPassword(t *testing.T) {
	a := testAuth(t, 1)
	if err := a.CheckPassword("hunter2"); err != nil {
		t.Errorf("correct password: %v", err)
	}
	for _, wrong := range []string{"", "hunter", "hunter2 ", "HUNTER2", "hunter22"} {
		if err := a.CheckPassword(wrong); !errors.Is(err, ErrBadPassword) {
			t.Errorf("CheckPassword(%q): err = %v, want ErrBadPassword", wrong, err)
		}
	}
}

func TestMintVerifyRoundTrip(t *testing.T) {
	a := testAuth(t, 1)
	token, expiry, err := a.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !expiry.After(time.Now()) {
		t.Errorf("expiry %v is not in the future", expiry)
	}
	if err := a.Verify(token); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	a := testAuth(t, 1)
	for _, tok := range []string{"", "!!!not base64!!!", "c2hvcnQ", "AAAA"} {
		if err := a.Verify(tok); !errors.Is(err, ErrBadToken) {
			t.Errorf("Verify(%q): err = %v, want ErrBadToken", tok, err)
		}
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	a := testAuth(t, 1)
	token, _, err := a.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Flip a bit in the decoded MAC rather than in the base64 text: the final
	// base64 character carries unused bits, so editing it can re-encode to
	// byte-identical claims.
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	forged := base64.RawURLEncoding.EncodeToString(raw)
	if err := a.Verify(forged); !errors.Is(err, ErrBadToken) {
		t.Errorf("Verify(tampered): err = %v, want ErrBadToken", err)
	}
}

// Bumping the epoch is the only way to evict holders of a live token, so this
// is the property a password rotation actually depends on.
func TestEpochBumpRevokesOutstandingTokens(t *testing.T) {
	before := testAuth(t, 1)
	token, _, err := before.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := before.Verify(token); err != nil {
		t.Fatalf("token invalid before rotation: %v", err)
	}

	after := testAuth(t, 2)
	if err := after.Verify(token); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Verify after epoch bump: err = %v, want ErrRevoked", err)
	}

	fresh, _, err := after.Mint()
	if err != nil {
		t.Fatalf("Mint after bump: %v", err)
	}
	if err := after.Verify(fresh); err != nil {
		t.Errorf("freshly minted token invalid after bump: %v", err)
	}
}

// A token whose epoch field is rewritten to the current epoch must not verify:
// the MAC was computed under a key the current epoch does not derive.
func TestForgedEpochDoesNotVerify(t *testing.T) {
	old := testAuth(t, 1)
	token, _, err := old.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	// Rewrite the epoch claim from 1 to 2, leaving the MAC alone.
	raw[11] = 2
	forged := base64.RawURLEncoding.EncodeToString(raw)
	if err := testAuth(t, 2).Verify(forged); !errors.Is(err, ErrBadToken) {
		t.Fatalf("Verify with forged epoch: err = %v, want ErrBadToken", err)
	}
}

func TestExpiredToken(t *testing.T) {
	a := testAuth(t, 1)
	token, _, err := a.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	a.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if err := a.Verify(token); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify of expired token: err = %v, want ErrExpired", err)
	}
}

func TestNewRejectsWeakConfig(t *testing.T) {
	good := []byte("0123456789abcdef0123456789abcdef")
	tests := []struct {
		name     string
		password string
		secret   []byte
		ttl      time.Duration
	}{
		{"empty password", "", good, time.Hour},
		{"short secret", "hunter2", []byte("tiny"), time.Hour},
		{"zero ttl", "hunter2", good, 0},
		{"negative ttl", "hunter2", good, -time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.password, tt.secret, 1, tt.ttl); err == nil {
				t.Fatal("New accepted invalid config")
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Now()
	r := NewRateLimiter(3, time.Minute)
	r.now = func() time.Time { return now }

	for i := range 3 {
		if !r.Allow("10.0.0.1") {
			t.Fatalf("attempt %d denied within burst", i+1)
		}
	}
	if r.Allow("10.0.0.1") {
		t.Fatal("fourth attempt allowed past burst")
	}
	// Other addresses are unaffected.
	if !r.Allow("10.0.0.2") {
		t.Fatal("unrelated address denied")
	}
	// Refills over the window.
	now = now.Add(30 * time.Second)
	if !r.Allow("10.0.0.1") {
		t.Fatal("attempt denied after partial refill")
	}
}

func TestRateLimiterSweepsIdleBuckets(t *testing.T) {
	now := time.Now()
	r := NewRateLimiter(1, time.Minute)
	r.now = func() time.Time { return now }

	r.Allow("10.0.0.1")
	if len(r.buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(r.buckets))
	}
	now = now.Add(10 * time.Minute)
	r.Allow("10.0.0.2")
	if _, ok := r.buckets["10.0.0.1"]; ok {
		t.Error("idle bucket was not swept")
	}
}
