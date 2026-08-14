// Package httpapi serves the two endpoints the client contract names, plus the
// embedded client assets.
//
// Because the binary serves the assets itself, it also owns their response
// headers. Serving real files rather than inline script costs nothing here and
// lets the content security policy stay strict.
package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/slabrant/chapi/internal/auth"
	"github.com/slabrant/chapi/internal/envelope"
	"github.com/slabrant/chapi/internal/hub"
)

// contentSecurityPolicy is the policy from DESIGN.md, plus frame-ancestors:
// the assets are same-origin files, so nothing here needs to be framable.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self' wss: ws:; frame-ancestors 'none'"

// maxLoginBody bounds the login request. It carries one short password.
const maxLoginBody = 4 << 10

// Config carries the transport's tunables.
type Config struct {
	// AllowedOrigins restricts which origins may open a websocket. Empty means
	// same-origin only, which is what a binary serving its own client wants.
	AllowedOrigins []string

	// TrustProxyHeader makes the login rate limiter read X-Forwarded-For.
	// Enable it only when a proxy you control sets that header, because a
	// client that can forge it can spread guesses across unlimited buckets.
	TrustProxyHeader bool

	// PingInterval is how often an idle connection is probed, and how often a
	// live connection's token is rechecked.
	PingInterval time.Duration
	// WriteTimeout bounds a single frame write.
	WriteTimeout time.Duration

	LoginBurst  int
	LoginWindow time.Duration
}

// Server wires the authenticator, the hub and the embedded assets together.
type Server struct {
	cfg     Config
	auth    *auth.Authenticator
	limiter *auth.RateLimiter
	reg     *hub.Registry
	signer  *envelope.Signer
	assets  fs.FS
	log     *slog.Logger
}

// New returns a Server. Handler exposes its routes.
func New(cfg Config, a *auth.Authenticator, reg *hub.Registry, signer *envelope.Signer, assets fs.FS, log *slog.Logger) *Server {
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.LoginBurst <= 0 {
		cfg.LoginBurst = 10
	}
	if cfg.LoginWindow <= 0 {
		cfg.LoginWindow = time.Minute
	}
	return &Server{
		cfg:     cfg,
		auth:    a,
		limiter: auth.NewRateLimiter(cfg.LoginBurst, cfg.LoginWindow),
		reg:     reg,
		signer:  signer,
		assets:  assets,
		log:     log,
	}
}

// Handler returns the server's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("GET /ws", s.handleWebsocket)
	mux.Handle("GET /", s.staticAssets())
	return mux
}

func (s *Server) staticAssets() http.Handler {
	files := http.FileServerFS(s.assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		files.ServeHTTP(w, r)
	})
}

type loginRequest struct {
	Password string `json:"password"`
}

type loginResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"exp"`
	// PubKey is the Ed25519 verifying key, base64 standard encoding.
	PubKey string `json:"pubkey"`
	KeyID  string `json:"keyid"`
	// ImageMaxBytes is the ceiling on an encoded image payload. Encoded size is
	// not knowable before encoding, so the client needs this to run a
	// measure-and-retry loop; publishing the number is the server's whole part
	// in that.
	ImageMaxBytes int `json:"image_max_bytes"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.Allow(clientIP(r, s.cfg.TrustProxyHeader)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if err := s.auth.CheckPassword(req.Password); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token, expiry, err := s.auth.Mint()
	if err != nil {
		s.log.Error("minting token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(loginResponse{
		Token:         token,
		Expires:       expiry.Unix(),
		PubKey:        base64.StdEncoding.EncodeToString(s.signer.Public()),
		KeyID:         s.signer.KeyID(),
		ImageMaxBytes: s.reg.Config().ImageMaxBytes,
	}); err != nil {
		s.log.Warn("writing login response", "err", err)
	}
}

// clientIP returns the address the login rate limiter buckets by.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			if first, _, ok := strings.Cut(forwarded, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(forwarded)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// errNoToken is returned when the handshake carried no credential.
var errNoToken = errors.New("httpapi: no token offered")
