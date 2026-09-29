// ssh-server is a small command-channel SSH daemon: it accepts SSH
// connections, negotiates session channels and executes the single
// allowed `status` command for monitoring agents.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func serverConfig() (*ssh.ServerConfig, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	return cfg, nil
}

// serveChannel answers the whitelisted exec request and closes.
func serveChannel(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()
	for req := range requests {
		if req.Type == "exec" {
			req.Reply(true, nil)
			fmt.Fprintln(ch, "status: ok")
			return
		}
		req.Reply(false, nil)
	}
}

func handleConn(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		log.Printf("session from %s", sconn.RemoteAddr())
		go serveChannel(ch, reqs)
	}
}

func main() {
	cfg, err := serverConfig()
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatal(err)
	}
	log.Print("ssh status server on :2222")
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handleConn(c, cfg)
	}
}
