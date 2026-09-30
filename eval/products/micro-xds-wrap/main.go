// micro-xds-wrap is the fleet "micro" control service whose server
// constructor is selected through a bootstrap registry: xDS mode is
// enabled indirectly via a function value, not a direct call site.
package main

import (
	"context"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
	"google.golang.org/grpc/xds"
)

type statusServer struct{}

func (statusServer) Check(ctx context.Context, _ any) (any, error) {
	return "ok", nil
}

var serverFactories = map[string]func(...grpc.ServerOption) (*xds.GRPCServer, error){
	"xds": xds.NewGRPCServer,
}

func main() {
	creds, err := xdscreds.NewServerCredentials(xdscreds.ServerOptions{
		FallbackCreds: insecure.NewCredentials(),
	})
	if err != nil {
		log.Fatal(err)
	}
	factory := serverFactories[os.Getenv("SERVER_MODE")]
	if factory == nil {
		factory = xds.NewGRPCServer
	}
	srv, err := factory(grpc.Creds(creds))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Serve(ln))
}
