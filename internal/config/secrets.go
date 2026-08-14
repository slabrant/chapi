package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	signingKeyFile = "signing.key"
	tokenKeyFile   = "token.key"
)

// LoadSecrets resolves the signing seed and the token secret.
//
// Either may be supplied through the environment. Anything not supplied is
// generated once and written into the data directory, because the alternative
// is worse than it looks: a signing key that changes on restart makes every
// archived message fail verification, and the archive is the permanent copy.
func (c *Config) LoadSecrets() error {
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return fmt.Errorf("config: creating data directory %s: %w", c.DataDir, err)
	}

	seed, generated, err := c.resolveSigningSeed()
	if err != nil {
		return err
	}
	c.SigningSeed, c.GeneratedSigningKey = seed, generated

	secret, generated, err := c.resolveTokenSecret()
	if err != nil {
		return err
	}
	c.TokenSecret, c.GeneratedTokenSecret = secret, generated
	return nil
}

func (c *Config) resolveSigningSeed() ([]byte, bool, error) {
	if raw := strings.TrimSpace(os.Getenv("CHAPI_SIGNING_SEED")); raw != "" {
		seed, err := hex.DecodeString(raw)
		if err != nil {
			return nil, false, fmt.Errorf("config: CHAPI_SIGNING_SEED is not hex: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, false, fmt.Errorf("config: CHAPI_SIGNING_SEED must be %d hex-encoded bytes", ed25519.SeedSize)
		}
		return seed, false, nil
	}

	path := filepath.Join(c.DataDir, signingKeyFile)
	seed, err := readHexFile(path, ed25519.SeedSize)
	switch {
	case err == nil:
		return seed, false, nil
	case !os.IsNotExist(err):
		return nil, false, err
	}

	seed = make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, false, fmt.Errorf("config: generating signing key: %w", err)
	}
	if err := writeHexFile(path, seed); err != nil {
		return nil, false, err
	}
	return seed, true, nil
}

func (c *Config) resolveTokenSecret() ([]byte, bool, error) {
	// Unlike the signing seed, this one is a secret of any length rather than
	// a fixed-size key, so it is taken verbatim.
	if raw := os.Getenv("CHAPI_TOKEN_SECRET"); raw != "" {
		if len(raw) < 16 {
			return nil, false, fmt.Errorf("config: CHAPI_TOKEN_SECRET must be at least 16 bytes")
		}
		return []byte(raw), false, nil
	}

	path := filepath.Join(c.DataDir, tokenKeyFile)
	secret, err := readHexFile(path, 32)
	switch {
	case err == nil:
		return secret, false, nil
	case !os.IsNotExist(err):
		return nil, false, err
	}

	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, fmt.Errorf("config: generating token secret: %w", err)
	}
	if err := writeHexFile(path, secret); err != nil {
		return nil, false, err
	}
	return secret, true, nil
}

func readHexFile(path string, want int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("config: %s is not hex: %w", path, err)
	}
	if len(decoded) != want {
		return nil, fmt.Errorf("config: %s holds %d bytes, want %d", path, len(decoded), want)
	}
	return decoded, nil
}

func writeHexFile(path string, secret []byte) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(secret)+"\n"), 0o600); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}
	return nil
}
