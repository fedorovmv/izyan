// dns-marshal builds outbound NOTIFY messages for the authoritative
// signer: it constructs dns.Msg values and packs them — the service
// never parses inbound zone text or wire data.
package main

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

func notify(zone string, target string) error {
	m := new(dns.Msg)
	m.SetNotify(zone)
	m.RecursionDesired = false
	raw, err := m.Pack()
	if err != nil {
		return err
	}
	conn, err := net.Dial("udp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(raw)
	return err
}

func main() {
	if err := notify("example.com.", "127.0.0.1:53"); err != nil {
		log.Fatal(err)
	}
}
