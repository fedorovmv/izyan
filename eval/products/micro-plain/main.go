// micro-plain is the same fleet "micro" service running self-managed:
// a plain grpc.Server with static credentials — no xDS control plane,
// no discovery-driven filter chain.
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type statusServer struct{}

func (statusServer) Check(ctx context.Context, _ any) (any, error) {
	return "ok", nil
}

func main() {
	srv := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
