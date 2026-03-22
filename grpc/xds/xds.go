// Package xds is the single-import entry point for Dubbo proxyless gRPC xDS
// support. A blank import of this package:
//
//	import _ "github.com/kdubbo/xds-api/grpc/xds"
//
// registers the following into the global gRPC runtime:
//   - xds:/// URI scheme resolver (LDS → RDS → CDS → EDS state machine)
//   - xds_weighted load-balancer (weighted round-robin over CDS subsets)
//
// No other setup is required in application code. TLS credentials must be
// supplied separately via grpc/xds/credentials.NewClientCredentials.
package xds

import (
	// Side-effect: registers the xds:/// resolver and xds_weighted balancer.
	_ "github.com/kdubbo/xds-api/grpc/resolver"
)

