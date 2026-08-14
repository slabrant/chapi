// Package config reads the server's settings from the environment.
//
// Deployment is one binary plus environment variables, so every retention
// number, ceiling and timeout is a variable rather than a constant. The
// defaults suit the target of ten to twenty people.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved server configuration.
type Config struct {
	Addr    string
	DataDir string

	Password    string
	TokenSecret []byte
	TokenEpoch  uint32
	TokenTTL    time.Duration

	SigningSeed []byte
	KeyID       string

	ImageMaxBytes  int
	TextMaxBytes   int
	RingText       int
	RingImageBytes int
	MaxBackfill    int
	OutboundBuffer int

	RoomIdleTimeout time.Duration
	SweepInterval   time.Duration
	PingInterval    time.Duration
	WriteTimeout    time.Duration

	LoginBurst  int
	LoginWindow time.Duration

	AllowedOrigins   []string
	TrustProxyHeader bool
	LogLevel         string

	// GeneratedSigningKey and GeneratedTokenSecret report that a secret was
	// created rather than supplied, so the caller can say so out loud.
	GeneratedSigningKey  bool
	GeneratedTokenSecret bool
}

// Load reads the environment and applies defaults.
//
// Every problem found is reported at once. Starting a chat server is not an
// interactive activity, and fixing one variable per restart is miserable.
func Load() (*Config, error) {
	e := &env{}

	cfg := &Config{
		Addr:    e.str("CHAPI_ADDR", ":8080"),
		DataDir: e.str("CHAPI_DATA_DIR", "./data"),

		Password:   os.Getenv("CHAPI_PASSWORD"),
		TokenEpoch: uint32(e.integer("CHAPI_TOKEN_EPOCH", 1)),
		TokenTTL:   e.duration("CHAPI_TOKEN_TTL", 12*time.Hour),
		KeyID:      e.str("CHAPI_KEY_ID", "k1"),

		ImageMaxBytes:  e.bytes("CHAPI_IMAGE_MAX_BYTES", 2<<20),
		TextMaxBytes:   e.bytes("CHAPI_TEXT_MAX_BYTES", 16<<10),
		RingText:       e.integer("CHAPI_RING_TEXT", 5000),
		RingImageBytes: e.bytes("CHAPI_RING_IMAGE_BYTES", 64<<20),
		MaxBackfill:    e.integer("CHAPI_MAX_BACKFILL", 5000),
		OutboundBuffer: e.integer("CHAPI_OUTBOUND_BUFFER", 64),

		RoomIdleTimeout: e.duration("CHAPI_ROOM_IDLE_TIMEOUT", 10*time.Minute),
		SweepInterval:   e.duration("CHAPI_SWEEP_INTERVAL", time.Minute),
		PingInterval:    e.duration("CHAPI_PING_INTERVAL", 30*time.Second),
		WriteTimeout:    e.duration("CHAPI_WRITE_TIMEOUT", 10*time.Second),

		LoginBurst:  e.integer("CHAPI_LOGIN_BURST", 10),
		LoginWindow: e.duration("CHAPI_LOGIN_WINDOW", time.Minute),

		TrustProxyHeader: e.boolean("CHAPI_TRUST_PROXY_HEADER", false),
		LogLevel:         e.str("CHAPI_LOG_LEVEL", "info"),
	}

	if origins := os.Getenv("CHAPI_ALLOWED_ORIGINS"); origins != "" {
		for _, origin := range strings.Split(origins, ",") {
			if origin = strings.TrimSpace(origin); origin != "" {
				cfg.AllowedOrigins = append(cfg.AllowedOrigins, origin)
			}
		}
	}

	if cfg.Password == "" {
		e.fail(errors.New("CHAPI_PASSWORD is required"))
	}
	if cfg.TokenTTL > 7*24*time.Hour {
		// Stateless tokens cannot be revoked one at a time, so expiry is the
		// only per-token bound there is.
		e.fail(errors.New("CHAPI_TOKEN_TTL over a week; keep it in hours"))
	}
	if cfg.OutboundBuffer < 1 {
		e.fail(errors.New("CHAPI_OUTBOUND_BUFFER must be at least 1"))
	}

	if err := e.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// env accumulates parse failures so Load can report all of them together.
type env struct{ errs []error }

func (e *env) fail(err error) { e.errs = append(e.errs, err) }

func (e *env) err() error { return errors.Join(e.errs...) }

func (e *env) str(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (e *env) integer(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.fail(fmt.Errorf("%s: %q is not a number", key, v))
		return fallback
	}
	return n
}

func (e *env) duration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.fail(fmt.Errorf("%s: %q is not a duration, try 30s or 12h", key, v))
		return fallback
	}
	return d
}

func (e *env) boolean(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.fail(fmt.Errorf("%s: %q is not a boolean", key, v))
		return fallback
	}
	return b
}

// bytes parses a size, accepting a unit suffix so retention limits stay
// readable in a deployment file.
func (e *env) bytes(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	multiplier := 1
	for _, unit := range []struct {
		suffix string
		scale  int
	}{
		{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
	} {
		if rest, ok := strings.CutSuffix(v, unit.suffix); ok {
			multiplier = unit.scale
			v = strings.TrimSpace(rest)
			break
		}
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.fail(fmt.Errorf("%s: %q is not a size, try 2MiB or 2097152", key, os.Getenv(key)))
		return fallback
	}
	return n * multiplier
}
