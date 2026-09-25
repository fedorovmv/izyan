package main

import "net"

// serve accepts inbound TCP connections: bytes it reads are
// remote-peer-controlled.
func serve() {
	ln, err := net.Listen("tcp", ":9090")
	if err != nil {
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { _ = c }()
	}
}

func main() { go serve() }
