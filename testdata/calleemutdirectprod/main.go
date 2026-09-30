package main

import (
	"bytes"
	"io"
	"net"

	"example.com/calleemutdep"
)

func main() {
	conn, _ := net.Dial("tcp", "127.0.0.1:5672")
	payload := make([]byte, 1)
	_, _ = io.ReadFull(conn, payload)
	var buffer bytes.Buffer
	_, _ = buffer.Write(payload)
	calleemutdep.SinkBuffer(buffer.String())
}
