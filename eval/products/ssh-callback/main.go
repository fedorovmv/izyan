// ssh-callback is an SSH access gateway: public keys are authorized
// against the fleet directory via PublicKeyCallback.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

var fleetKeys = map[string]bool{}

func serverConfig() (*ssh.ServerConfig, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
			if fleetKeys[ssh.FingerprintSHA256(pub)] {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("key rejected")
		},
	}
	cfg.AddHostKey(signer)
	return cfg, nil
}

func handleConn(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	ssh.DiscardRequests(reqs)
	for nc := range chans {
		nc.Reject(ssh.UnknownChannelType, "no channels")
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
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(c, cfg)
	}
}
