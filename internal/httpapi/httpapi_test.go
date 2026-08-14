package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/slabrant/chapi/internal/auth"
	"github.com/slabrant/chapi/internal/envelope"
	"github.com/slabrant/chapi/internal/httpapi"
	"github.com/slabrant/chapi/internal/hub"
	"github.com/slabrant/chapi/internal/store"
	"github.com/slabrant/chapi/web"
)

const testPassword = "hunter2"

type server struct {
	*httptest.Server
	keys envelope.KeyLookup
}

func newServer(t *testing.T, tweak func(*hub.Config, *httpapi.Config)) *server {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer := envelope.NewSigner("k1", priv)
	keys := envelope.SingleKey("k1", signer.Public())

	hubCfg := hub.Config{
		DataDir:         t.TempDir(),
		Store:           store.Config{MaxText: 1000, MaxImageBytes: 1 << 20, MaxBackfill: 1000},
		ImageMaxBytes:   1 << 20,
		MaxTextBytes:    4096,
		OutboundBuffer:  32,
		RoomIdleTimeout: time.Hour,
		SweepInterval:   time.Hour,
	}
	apiCfg := httpapi.Config{
		PingInterval: time.Hour,
		WriteTimeout: 5 * time.Second,
		LoginBurst:   100,
		LoginWindow:  time.Minute,
	}
	if tweak != nil {
		tweak(&hubCfg, &apiCfg)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authenticator, err := auth.New(testPassword, []byte("0123456789abcdef0123456789abcdef"), 1, time.Hour)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	registry := hub.NewRegistry(hubCfg, signer, keys, log)
	ctx, cancel := context.WithCancel(context.Background())
	go registry.Run(ctx)

	api := httpapi.New(apiCfg, authenticator, registry, signer, web.FS(), log)
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(func() {
		cancel()
		registry.Wait()
		ts.Close()
	})
	return &server{Server: ts, keys: keys}
}

type loginResult struct {
	Token         string `json:"token"`
	Expires       int64  `json:"exp"`
	PubKey        string `json:"pubkey"`
	KeyID         string `json:"keyid"`
	ImageMaxBytes int    `json:"image_max_bytes"`
}

func (s *server) login(t *testing.T, password string) (loginResult, int) {
	t.Helper()
	body := strings.NewReader(`{"password":` + quote(password) + `}`)
	resp, err := s.Client().Post(s.URL+"/login", "application/json", body)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return loginResult{}, resp.StatusCode
	}
	var out loginResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding login response: %v", err)
	}
	return out, resp.StatusCode
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *server) dial(t *testing.T, token string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
	conn, resp, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
		HTTPClient:   s.Client(),
		Subprotocols: []string{httpapi.Subprotocol, token},
	})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dialling /ws: %v (status %d)", err, status)
	}
	// The library's default read limit sits far below image size, on this side
	// of the connection just as much as on the server's.
	conn.SetReadLimit(4 << 20)
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func send(t *testing.T, conn *websocket.Conn, frame any) {
	t.Helper()
	b, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("marshalling frame: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("writing frame: %v", err)
	}
}

// nextMessage reads until a signed message arrives and verifies it exactly as
// the client contract requires.
func nextMessage(t *testing.T, s *server, conn *websocket.Conn) *envelope.Message {
	t.Helper()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			t.Fatalf("reading frame: %v", err)
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(data, &probe); err != nil {
			t.Fatalf("frame is not JSON: %v", err)
		}
		if _, signed := probe["h"]; !signed {
			continue
		}
		m, err := envelope.Open(data, s.keys)
		if err != nil {
			t.Fatalf("message does not verify: %v", err)
		}
		return m
	}
}

func waitFor(t *testing.T, conn *websocket.Conn, frameType string) map[string]any {
	t.Helper()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, data, err := conn.Read(ctx)
		cancel()
		if err != nil {
			t.Fatalf("reading frame: %v", err)
		}
		var v map[string]any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("frame is not JSON: %v", err)
		}
		if v["t"] == frameType {
			return v
		}
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	s := newServer(t, nil)
	if _, status := s.login(t, "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestLoginAdvertisesKeyAndCeiling(t *testing.T) {
	s := newServer(t, func(h *hub.Config, _ *httpapi.Config) { h.ImageMaxBytes = 12345 })

	out, status := s.login(t, testPassword)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Token == "" {
		t.Error("login returned no token")
	}
	if out.KeyID != "k1" {
		t.Errorf("keyid = %q, want k1", out.KeyID)
	}
	if out.ImageMaxBytes != 12345 {
		t.Errorf("image_max_bytes = %d, want 12345", out.ImageMaxBytes)
	}
	key, err := base64.StdEncoding.DecodeString(out.PubKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Errorf("pubkey = %q, want a base64 Ed25519 key", out.PubKey)
	}
	if out.Expires <= time.Now().Unix() {
		t.Error("token expiry is not in the future")
	}
}

func TestLoginRateLimited(t *testing.T) {
	s := newServer(t, func(_ *hub.Config, a *httpapi.Config) {
		a.LoginBurst = 3
		a.LoginWindow = time.Minute
	})
	for range 3 {
		if _, status := s.login(t, "wrong"); status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 within the burst", status)
		}
	}
	if _, status := s.login(t, "wrong"); status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 past the burst", status)
	}
	// The limiter bounds guessing regardless of whether the guess is right.
	if _, status := s.login(t, testPassword); status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 for a correct password past the burst", status)
	}
}

func TestWebsocketRequiresToken(t *testing.T) {
	s := newServer(t, nil)
	url := "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"

	for name, protocols := range map[string][]string{
		"no token":  {httpapi.Subprotocol},
		"bad token": {httpapi.Subprotocol, "not-a-real-token"},
	} {
		conn, resp, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
			HTTPClient:   s.Client(),
			Subprotocols: protocols,
		})
		if err == nil {
			conn.CloseNow()
			t.Errorf("%s: handshake succeeded, want rejection", name)
			continue
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status = %v, want 401", name, resp)
		}
	}
}

// The token rides as an offered subprotocol so it stays out of URLs and access
// logs, and the server must echo the one it selected or the browser fails the
// handshake.
func TestWebsocketEchoesSubprotocol(t *testing.T) {
	s := newServer(t, nil)
	out, _ := s.login(t, testPassword)
	conn := s.dial(t, out.Token)
	if got := conn.Subprotocol(); got != httpapi.Subprotocol {
		t.Fatalf("subprotocol = %q, want %q", got, httpapi.Subprotocol)
	}
}

func TestEndToEndBroadcast(t *testing.T) {
	s := newServer(t, nil)
	out, _ := s.login(t, testPassword)

	alice := s.dial(t, out.Token)
	bob := s.dial(t, out.Token)

	send(t, alice, map[string]any{"t": "join", "room": "general", "since": 0})
	send(t, bob, map[string]any{"t": "join", "room": "general", "since": 0})
	waitFor(t, alice, "joined")
	waitFor(t, bob, "joined")

	send(t, alice, map[string]any{"t": "send", "nick": "alice", "kind": "text", "p": "hello"})

	for name, conn := range map[string]*websocket.Conn{"alice": alice, "bob": bob} {
		m := nextMessage(t, s, conn)
		if m.Payload != "hello" {
			t.Errorf("%s: payload = %q, want hello", name, m.Payload)
		}
		if m.Header.Nick != "alice" || m.Header.Room != "general" || m.Header.Seq != 1 {
			t.Errorf("%s: header = %+v", name, m.Header)
		}
		if m.Header.TS == 0 {
			t.Errorf("%s: header carries no server timestamp", name)
		}
	}
}

func TestReconnectResumesFromSequence(t *testing.T) {
	s := newServer(t, nil)
	out, _ := s.login(t, testPassword)

	first := s.dial(t, out.Token)
	send(t, first, map[string]any{"t": "join", "room": "general", "since": 0})
	waitFor(t, first, "joined")
	for range 3 {
		send(t, first, map[string]any{"t": "send", "nick": "alice", "kind": "text", "p": "hello"})
	}
	for range 3 {
		nextMessage(t, s, first)
	}
	first.Close(websocket.StatusNormalClosure, "done")

	// A reconnect resuming from sequence 2 gets only what it missed.
	second := s.dial(t, out.Token)
	send(t, second, map[string]any{"t": "join", "room": "general", "since": 2})
	if frame := waitFor(t, second, "joined"); frame["seq"].(float64) != 3 {
		t.Fatalf("joined seq = %v, want 3", frame["seq"])
	}
	if got := nextMessage(t, s, second).Header.Seq; got != 3 {
		t.Fatalf("backfill seq = %d, want 3", got)
	}
}

func TestImageRoundTripsThroughTransport(t *testing.T) {
	s := newServer(t, nil)
	out, _ := s.login(t, testPassword)

	conn := s.dial(t, out.Token)
	send(t, conn, map[string]any{"t": "join", "room": "general", "since": 0})
	waitFor(t, conn, "joined")

	// Large enough that the read limit would reject it if it were left at the
	// library default of 32 KiB.
	payload := base64.StdEncoding.EncodeToString(make([]byte, 200<<10))
	send(t, conn, map[string]any{
		"t": "send", "nick": "alice", "kind": "image",
		"p": payload, "mime": "image/jpeg", "w": 800, "h": 600,
	})

	m := nextMessage(t, s, conn)
	if m.Payload != payload {
		t.Error("image payload did not survive the round trip")
	}
	if m.Header.W != 800 || m.Header.H != 600 || m.Header.Mime != "image/jpeg" {
		t.Errorf("header = %+v, want the image dimensions", m.Header)
	}
}

func TestStaticAssetsCarryContentSecurityPolicy(t *testing.T) {
	s := newServer(t, nil)
	resp, err := s.Client().Get(s.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	csp := resp.Header.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "script-src 'self'", "img-src 'self' data:"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP %q is missing %q", csp, directive)
		}
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("assets served without nosniff")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	// The policy forbids inline script, so the page must load a real file.
	if strings.Contains(string(body), "<script>") {
		t.Error("placeholder page uses inline script, which its own CSP forbids")
	}
	if !strings.Contains(string(body), "app.js") {
		t.Error("placeholder page does not reference its script")
	}
}
