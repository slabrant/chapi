// Package auth implements shared-password login and the stateless tokens it
// issues.
//
// There are no accounts and no per-user identity. Holding the password is the
// whole of authorization, so the realistic attack surface is credential
// lifetime rather than credential strength. Two things address it: short
// expiry, and an epoch counter mixed into the signing key so every outstanding
// token can be invalidated at once.
package auth

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var (
	ErrBadPassword = errors.New("auth: incorrect password")
	ErrBadToken    = errors.New("auth: token does not verify")
	ErrExpired     = errors.New("auth: token expired")
	ErrRevoked     = errors.New("auth: token issued under a superseded epoch")
)

const (
	// tokenClaimsLen is 8 bytes of expiry plus 4 bytes of epoch.
	tokenClaimsLen = 12
	macLen         = sha256.Size
	tokenLen       = tokenClaimsLen + macLen

	keyInfo = "chapi token key v1"
)

// Authenticator verifies passwords and mints tokens.
//
// It holds no session state: a token is verified by recomputing its MAC, so
// there is nothing to look up and nothing to replicate.
type Authenticator struct {
	passwordDigest [sha256.Size]byte
	secret         []byte
	epoch          uint32
	ttl            time.Duration

	// now is swappable so tests can reason about expiry without sleeping.
	now func() time.Time
}

// New returns an Authenticator for the given shared password.
//
// Bumping epoch invalidates every token minted under previous epochs, which is
// what makes a password rotation actually evict people. Keep ttl in hours, not
// weeks: it is the only bound on a leaked token that nobody notices.
func New(password string, secret []byte, epoch uint32, ttl time.Duration) (*Authenticator, error) {
	if password == "" {
		return nil, errors.New("auth: empty password")
	}
	if len(secret) < 16 {
		return nil, errors.New("auth: token secret must be at least 16 bytes")
	}
	if ttl <= 0 {
		return nil, errors.New("auth: token ttl must be positive")
	}
	return &Authenticator{
		passwordDigest: sha256.Sum256([]byte(password)),
		secret:         secret,
		epoch:          epoch,
		ttl:            ttl,
		now:            time.Now,
	}, nil
}

// TTL returns how long a freshly minted token remains valid.
func (a *Authenticator) TTL() time.Duration { return a.ttl }

// tokenKey derives the MAC key for an epoch.
//
// Deriving per epoch rather than storing a flag is what makes revocation
// unconditional: a token from a retired epoch does not merely fail a check, it
// was signed with a key that no longer produces matching MACs.
func (a *Authenticator) tokenKey(epoch uint32) ([]byte, error) {
	salt := binary.BigEndian.AppendUint32(nil, epoch)
	key, err := hkdf.Key(sha256.New, a.secret, salt, keyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: deriving token key: %w", err)
	}
	return key, nil
}

// CheckPassword compares an attempt against the shared password in constant
// time. Both sides are hashed first so the comparison does not leak length.
func (a *Authenticator) CheckPassword(attempt string) error {
	got := sha256.Sum256([]byte(attempt))
	if subtle.ConstantTimeCompare(got[:], a.passwordDigest[:]) != 1 {
		return ErrBadPassword
	}
	return nil
}

// Mint issues a token valid for the configured TTL under the current epoch.
func (a *Authenticator) Mint() (string, time.Time, error) {
	expiry := a.now().Add(a.ttl).UTC()

	claims := make([]byte, 0, tokenClaimsLen)
	claims = binary.BigEndian.AppendUint64(claims, uint64(expiry.Unix()))
	claims = binary.BigEndian.AppendUint32(claims, a.epoch)

	key, err := a.tokenKey(a.epoch)
	if err != nil {
		return "", time.Time{}, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(claims)

	token := mac.Sum(claims)
	return base64.RawURLEncoding.EncodeToString(token), expiry, nil
}

// Verify checks a token's MAC, epoch and expiry.
//
// The epoch is read from the untrusted token only to select a key. A token
// claiming an epoch other than the current one is rejected outright, so
// naming a stale epoch buys an attacker nothing.
func (a *Authenticator) Verify(token string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenLen {
		return ErrBadToken
	}
	claims, presented := raw[:tokenClaimsLen], raw[tokenClaimsLen:]

	epoch := binary.BigEndian.Uint32(claims[8:12])
	if epoch != a.epoch {
		return ErrRevoked
	}

	key, err := a.tokenKey(epoch)
	if err != nil {
		return ErrBadToken
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(claims)
	if !hmac.Equal(mac.Sum(nil), presented) {
		return ErrBadToken
	}

	// Expiry is checked only after the MAC holds, so an unauthenticated caller
	// cannot distinguish "expired" from "forged" by timing the two paths.
	if a.now().After(time.Unix(int64(binary.BigEndian.Uint64(claims[:8])), 0)) {
		return ErrExpired
	}
	return nil
}

// NewSecret returns a random token secret, for deployments that have not been
// given one. A generated secret does not survive a restart, which invalidates
// every outstanding token: fine for development, wrong for production.
func NewSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("auth: generating token secret: %w", err)
	}
	return secret, nil
}
