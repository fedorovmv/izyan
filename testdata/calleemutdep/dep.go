package calleemutdep

import (
	"bytes"
	"encoding/binary"
	"io"
)

func Sink(string) {}

func ReadOne(r io.Reader) string {
	payload := make([]byte, 1)
	_, _ = io.ReadFull(r, payload)
	return string(payload)
}

func Entry(r io.Reader) { Sink(ReadOne(r)) }

func SinkBuffer(string) {}

func ReadBuffered(r io.Reader) string {
	var buffer bytes.Buffer
	payload := make([]byte, 1)
	_, _ = io.ReadFull(r, payload)
	_, _ = buffer.Write(payload)
	return buffer.String()
}

func EntryBuffer(r io.Reader) { SinkBuffer(ReadBuffered(r)) }

func SinkLength(uint32) {}

func ReadLength(r io.Reader) uint32 {
	length := uint32(0)
	_ = binary.Read(r, binary.BigEndian, &length)
	return length
}

func EntryLength(r io.Reader) { SinkLength(ReadLength(r)) }
