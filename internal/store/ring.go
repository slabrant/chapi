package store

import "github.com/slabrant/chapi/internal/envelope"

// deque is a FIFO of messages with amortized O(1) eviction from the front.
//
// The obvious slice-and-reslice loses the backing array to a growing head
// offset; compacting when the head passes the midpoint keeps that bounded
// without the bookkeeping of a true circular buffer.
type deque struct {
	msgs []*envelope.Message
	head int
}

func (d *deque) len() int { return len(d.msgs) - d.head }

func (d *deque) push(m *envelope.Message) { d.msgs = append(d.msgs, m) }

func (d *deque) front() *envelope.Message {
	if d.len() == 0 {
		return nil
	}
	return d.msgs[d.head]
}

func (d *deque) pop() *envelope.Message {
	m := d.front()
	if m == nil {
		return nil
	}
	d.msgs[d.head] = nil
	d.head++
	if d.head > len(d.msgs)/2 {
		n := copy(d.msgs, d.msgs[d.head:])
		clear(d.msgs[n:])
		d.msgs = d.msgs[:n]
		d.head = 0
	}
	return m
}

func (d *deque) all() []*envelope.Message { return d.msgs[d.head:] }

// Ring is a room's warm history: a long tail of text kept by count, and a
// short window of images kept by byte budget.
//
// The two are separate because they are scarce for different reasons. A few
// thousand text messages cost almost nothing; a few thousand images would cost
// gigabytes, so images are bounded by what they actually consume.
type Ring struct {
	text   deque // text and shush, capped by count
	images deque // capped by total payload bytes

	maxText       int
	maxImageBytes int
	imageBytes    int
}

// NewRing returns a ring holding at most maxText text messages and at most
// maxImageBytes of image payload.
func NewRing(maxText, maxImageBytes int) *Ring {
	return &Ring{maxText: max(maxText, 0), maxImageBytes: max(maxImageBytes, 0)}
}

// Append adds a message and evicts oldest-first until the ring is back within
// its limits.
func (r *Ring) Append(m *envelope.Message) {
	if m.Header.Kind == envelope.KindImage {
		r.images.push(m)
		r.imageBytes += len(m.Payload)
		for r.imageBytes > r.maxImageBytes && r.images.len() > 0 {
			r.imageBytes -= len(r.images.pop().Payload)
		}
		return
	}
	r.text.push(m)
	for r.text.len() > r.maxText {
		r.text.pop()
	}
}

// Since returns every retained message with a sequence above since, in
// sequence order.
//
// The two sub-rings hold different spans, so this is a merge rather than a
// concatenation: text from well before the oldest retained image is normal.
func (r *Ring) Since(since uint64) []*envelope.Message {
	text, images := r.text.all(), r.images.all()

	// Both sub-rings are append-ordered, so seek forward to the first message
	// past since rather than filtering the whole window.
	ti := seek(text, since)
	ii := seek(images, since)

	out := make([]*envelope.Message, 0, len(text)-ti+len(images)-ii)
	for ti < len(text) || ii < len(images) {
		switch {
		case ii == len(images):
			out = append(out, text[ti])
			ti++
		case ti == len(text):
			out = append(out, images[ii])
			ii++
		case text[ti].Header.Seq < images[ii].Header.Seq:
			out = append(out, text[ti])
			ti++
		default:
			out = append(out, images[ii])
			ii++
		}
	}
	return out
}

func seek(msgs []*envelope.Message, since uint64) int {
	i := 0
	for i < len(msgs) && msgs[i].Header.Seq <= since {
		i++
	}
	return i
}

// ImageBytes reports the current size of the image window.
func (r *Ring) ImageBytes() int { return r.imageBytes }

// Len reports how many messages are retained across both sub-rings.
func (r *Ring) Len() int { return r.text.len() + r.images.len() }
