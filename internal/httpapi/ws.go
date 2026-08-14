package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/slabrant/chapi/internal/hub"
)

// Subprotocol is the protocol the server selects and echoes. The browser fails
// the handshake if the server does not echo one of the offered protocols.
const Subprotocol = "chapi.v1"

// CloseTokenExpired tells a client its credential died under it. Reconnecting
// requires logging in again, which is the difference from a slow-consumer
// close.
const CloseTokenExpired = 4004

// frameOverhead is the slack above the largest payload a frame may carry: the
// JSON wrapper, the nickname, the mime type and the dimensions.
const frameOverhead = 64 << 10

// handleWebsocket authenticates the handshake and runs the connection.
//
// The token arrives via Sec-WebSocket-Protocol rather than a query parameter,
// which keeps it out of URLs and out of access logs.
func (s *Server) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	token, err := offeredToken(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.auth.Verify(token); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:   []string{Subprotocol},
		OriginPatterns: s.cfg.AllowedOrigins,
		// Deflate over base64 recovers essentially all of base64's inflation,
		// because base64 spends eight bits carrying six bits of entropy. The
		// cost is CPU: contexts are per connection, so a broadcast image is
		// compressed once per client. At this scale that is the right trade.
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		s.log.Debug("websocket handshake failed", "err", err)
		return
	}
	defer conn.CloseNow()

	if conn.Subprotocol() != Subprotocol {
		conn.Close(websocket.StatusPolicyViolation, "client did not offer "+Subprotocol)
		return
	}

	// Defaults sit far below image size, so this has to be raised deliberately
	// on the server and on any proxy in front of it.
	hubCfg := s.reg.Config()
	conn.SetReadLimit(int64(max(hubCfg.ImageMaxBytes, hubCfg.MaxTextBytes) + frameOverhead))

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	client := hub.NewClient(hubCfg.OutboundBuffer)
	session := hub.NewSession(s.reg, client)
	defer session.Close()

	go s.writePump(ctx, conn, client, token)
	s.readPump(ctx, conn, session, client)
}

// offeredToken pulls the credential out of the offered subprotocol list. The
// client offers the real subprotocol plus its token; the server selects the
// former and reads the latter.
func offeredToken(r *http.Request) (string, error) {
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, offered := range strings.Split(header, ",") {
			if offered = strings.TrimSpace(offered); offered != "" && offered != Subprotocol {
				return offered, nil
			}
		}
	}
	return "", errNoToken
}

func (s *Server) readPump(ctx context.Context, conn *websocket.Conn, session *hub.Session, client *hub.Client) {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			// Includes the close the write pump performs for a slow consumer,
			// which is how this goroutine learns to stop.
			client.Kill(hub.CloseProtocolError, "connection closed")
			return
		}
		if typ != websocket.MessageText {
			client.Kill(hub.CloseProtocolError, "binary frames are not part of this protocol")
			return
		}
		session.Handle(data)
	}
}

func (s *Server) writePump(ctx context.Context, conn *websocket.Conn, client *hub.Client, token string) {
	ticker := time.NewTicker(s.cfg.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-client.Closed():
			code, reason := client.CloseInfo()
			conn.Close(websocket.StatusCode(code), truncateReason(reason))
			return

		case b := <-client.Out():
			if err := s.write(ctx, conn, b); err != nil {
				client.Kill(hub.CloseServerError, "write failed")
				return
			}

		case <-ticker.C:
			// Tokens are verified at the handshake, but a socket outlives the
			// credential that opened it. Rechecking here is what makes an
			// epoch bump evict people who are already connected, rather than
			// only those who try to reconnect.
			if err := s.auth.Verify(token); err != nil {
				client.Kill(CloseTokenExpired, "token no longer valid")
				return
			}
			pingCtx, cancel := context.WithTimeout(ctx, s.cfg.WriteTimeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				client.Kill(hub.CloseServerError, "ping failed")
				return
			}
		}
	}
}

func (s *Server) write(ctx context.Context, conn *websocket.Conn, b []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, s.cfg.WriteTimeout)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, b)
}

// truncateReason keeps a close reason inside the 123-byte limit the protocol
// allows, so closing never fails for a long message.
func truncateReason(reason string) string {
	const limit = 123
	if len(reason) <= limit {
		return reason
	}
	return reason[:limit]
}
