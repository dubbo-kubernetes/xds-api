// Package credentials provides the xDS-aware transport credentials and server
// constructor for Dubbo proxyless gRPC applications.
//
// Client side — inject xDS credentials into every outbound dial:
//
//	creds, err := credentials.NewClientCredentials(credentials.ClientOptions{
//		FallbackCreds: insecure.NewCredentials(),
//	})
//	conn, err := grpc.DialContext(ctx, "xds:///svc.ns.svc.cluster.local:7070",
//		grpc.WithTransportCredentials(creds))
//
// Server side — transparent plaintext ↔ mTLS switching driven by xDS:
//
//	srv := credentials.NewGRPCServer(addr, bootstrapPath)
//	pb.RegisterFooServer(srv, &impl{})
//	srv.ServeContext(ctx)
package credentials

import (
	"google.golang.org/grpc"
	googlecreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	xdscreds "github.com/kdubbo/xds-api/grpc/credentials"
	"github.com/kdubbo/xds-api/grpc/server"
)

// ClientOptions configures client-side xDS transport credentials.
// Re-exported from grpc/credentials so callers only import this package.
type ClientOptions = xdscreds.ClientOptions

// ServerOptions configures server-side xDS credentials.
// Re-exported from grpc/credentials so callers only import this package.
type ServerOptions = xdscreds.ServerOptions

// NewClientCredentials returns client-side transport credentials that
// dynamically switch between plaintext and mTLS based on the
// UpstreamTlsContext delivered by the xDS control plane (CDS).
//
// Typical usage:
//
//	creds, err := credentials.NewClientCredentials(credentials.ClientOptions{
//		FallbackCreds: insecure.NewCredentials(),
//	})
//	// handle err
//	conn, err := grpc.DialContext(ctx, "xds:///svc.ns.svc.cluster.local:7070",
//		grpc.WithTransportCredentials(creds))
func NewClientCredentials(opts ClientOptions) (googlecreds.TransportCredentials, error) {
	return xdscreds.NewClientCredentials(opts)
}

// NewServerCredentials returns server-side TLS transport credentials backed
// by file-based certificate watching. Intended for use with NewGRPCServer
// when the application manages its own grpc.Server.
func NewServerCredentials(opts ServerOptions) (googlecreds.TransportCredentials, error) {
	return xdscreds.NewServerCredentials(opts)
}

// NewGRPCServer creates a ManagedServer whose TLS mode is driven
// automatically by the xDS control plane (PeerAuthentication policies).
// Applications register services via RegisterService/RegisterHook and call
// ServeContext — zero TLS lifecycle code is needed.
//
//	srv := credentials.NewGRPCServer("0.0.0.0:17070", bootstrapPath)
//	pb.RegisterFooServer(srv, &impl{})
//	if err := srv.ServeContext(ctx); err != nil { log.Fatal(err) }
func NewGRPCServer(addr, bootstrapPath string, opts ...grpc.ServerOption) *server.ManagedServer {
	return server.NewGRPCServer(addr, bootstrapPath, opts...)
}

// FallbackInsecure returns grpc.WithTransportCredentials(insecure.NewCredentials()),
// a convenience helper for dial calls in environments without TLS.
func FallbackInsecure() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}
