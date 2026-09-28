package vuln

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
)

// Conn is a pretend client connection whose parse loop is driven by the
// remote peer's bytes (the amqp091 shape: unexported sinks inside the
// peer-fed read path that product code can never name).
type Conn struct {
	r *bufio.Reader
}

// Connect opens a client connection; every byte the codec later parses
// is sent by the remote peer.
func Connect(addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Conn{r: bufio.NewReader(c)}, nil
}

// readRecord is the pretend vulnerable parser — unexported, reachable
// only through the peer-fed read path. Its argument is the wire reader.
func readRecord(r io.Reader) (int, error) {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return 0, err
	}
	buf := make([]byte, size)
	_, err := io.ReadFull(r, buf)
	return len(buf), err
}

// Next parses the next record off the wire.
func (c *Conn) Next() (int, error) {
	return readRecord(c.r)
}

// parseConstant is only ever invoked with a package-internal constant —
// dep-internal provenance resolves a non-external origin here.
func parseConstant(n int) int { return n }

// Fixed exercises parseConstant with a literal; product code cannot
// influence the value.
func Fixed() int { return parseConstant(7) }
