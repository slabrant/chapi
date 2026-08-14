package hub

import "sync"

// Close codes the server uses. The 4000 range is reserved for applications.
//
// A client has to tell these apart: a slow-consumer close is an instruction to
// reconnect and gap-fill, while a protocol error means the last frame was
// wrong and retrying it unchanged will fail again.
const (
	CloseSlowConsumer  = 4001
	CloseServerError   = 4002
	CloseProtocolError = 4003
)

// Client is one connection's outbound queue and lifecycle.
//
// It deliberately knows nothing about websockets. The transport runs the read
// and write pumps; the hub only ever hands it bytes and, when it cannot keep
// up, closes it.
type Client struct {
	out    chan []byte
	closed chan struct{}

	once   sync.Once
	code   int
	reason string
}

// NewClient returns a client with a buffered outbound queue.
func NewClient(buffer int) *Client {
	if buffer < 1 {
		buffer = 1
	}
	return &Client{
		out:    make(chan []byte, buffer),
		closed: make(chan struct{}),
	}
}

// Out is the queue the transport's write pump drains.
func (c *Client) Out() <-chan []byte { return c.out }

// Closed is closed once the client has been killed.
func (c *Client) Closed() <-chan struct{} { return c.closed }

// CloseInfo returns the code and reason the client was killed with. It is only
// meaningful after Closed has fired.
func (c *Client) CloseInfo() (int, string) { return c.code, c.reason }

// Kill marks the connection for closure. The transport observes Closed and
// closes the socket with this code.
func (c *Client) Kill(code int, reason string) {
	c.once.Do(func() {
		c.code, c.reason = code, reason
		close(c.closed)
	})
}

// send queues bytes for the connection, disconnecting it if the queue is full.
//
// Slow consumers are disconnected, never skipped. A silently dropped message
// is a gap with nothing to trigger recovery, whereas a closed socket puts the
// client on the reconnect-and-gap-fill path that already exists. That is what
// makes disconnecting the safe choice rather than the harsh one.
func (c *Client) send(b []byte) {
	select {
	case <-c.closed:
	case c.out <- b:
	default:
		c.Kill(CloseSlowConsumer, "outbound queue full")
	}
}
