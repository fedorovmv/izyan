// micro-xds-pkg is the fleet "micro" service running self-managed: a
// plain grpc.Server — but the xds package is linked into the build for
// shared bootstrap helpers, so the locus package is in the build graph
// while its server path is never invoked.
package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/xds"
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
