package main

import (
	"io"
	"net"
	"os"
)

type Writer = io.Writer

type writerConn struct{ io.Writer }

func (writerConn) Emit([]byte) {}

type fakeReadConn struct{ io.Writer }

func (fakeReadConn) Read() bool { return true }

func record(Writer, []byte) {}

func recordBoth(io.ReadWriter, []byte) {}

func recordReader(io.Reader) {}

func recordConn(net.Conn) {}

func recordFakeRead(fakeReadConn) {}

func recordMany(...io.Writer) {}

func recordPayload(string) {}

func main() {
	conn, _ := net.Dial("tcp", "127.0.0.1:1")
	record(conn, []byte("header"))
	recordBoth(conn, []byte("payload"))
	recordReader(conn)
	recordConn(conn)
	recordFakeRead(fakeReadConn{conn})
	recordMany(conn, conn)
	writerConn.Emit(writerConn{conn}, []byte("header"))
	recordPayload(os.Args[1])
}
