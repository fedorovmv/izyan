package main

import (
	"net"
	"net/http"
	"os"

	"example.com/dep/vuln"
)

const grpcAddr = ":9091"

var cfgAddr = "127.0.0.1:8080" // package-level var — value not resolved

type ServerConfig struct {
	Addr string
}

var serverCfg = ServerConfig{Addr: "127.0.0.1:8888"}

func main() {
	net.Listen("tcp", ":9090")  // literal → all-interfaces
	net.Listen("tcp", grpcAddr) // const → :9090
	local := "127.0.0.1:8081"
	net.Listen("tcp", local)                  // local var init → literal
	net.Listen("tcp", os.Getenv("BIND_ADDR")) // env:BIND_ADDR
	srv := &http.Server{Addr: ":8443"}
	go srv.ListenAndServe() // receiver composite → :8443

	net.Listen("tcp", cfgAddr)        // package-level var
	net.Listen("tcp", serverCfg.Addr) // struct field

	vuln.Dial("amqps://broker.internal:5671", "x") // outbound into dep module
}
