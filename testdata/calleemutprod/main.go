package main

import (
	"net"

	"example.com/calleemutdep"
)

func main() {
	conn, _ := net.Dial("tcp", "127.0.0.1:5672")
	calleemutdep.Entry(conn)
	calleemutdep.EntryBuffer(conn)
	calleemutdep.EntryLength(conn)
}
