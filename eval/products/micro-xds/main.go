// micro-xds is the fleet "micro" control service: a gRPC endpoint
// managed by the xDS control plane — RBAC filters come from discovery.
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
	"google.golang.org/grpc/xds"
)

type statusServer struct{}

func (statusServer) Check(ctx context.Context, _ any) (any, error) {
	return "ok", nil
}

func main() {
	creds, err := xdscreds.NewServerCredentials(xdscreds.ServerOptions{
		FallbackCreds: insecure.NewCredentials(),
	})
	if err != nil {
		log.Fatal(err)
	}
	srv, err := xds.NewGRPCServer(grpc.Creds(creds))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
