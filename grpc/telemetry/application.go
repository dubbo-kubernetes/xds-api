// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
)

const MetricsAddressEnv = "DUBBO_GRPC_METRICS_ADDRESS"

type MetricsEndpoint struct {
	address  string
	listener net.Listener
	server   *http.Server
}

func (e *MetricsEndpoint) Address() string {
	return e.address
}

func (e *MetricsEndpoint) Shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func (r *Runtime) StartMetricsEndpoint(address string) (*MetricsEndpoint, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("metrics address is empty")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen for application metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", r.Handler())
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	endpoint := &MetricsEndpoint{
		address:  listener.Addr().String(),
		listener: listener,
		server:   server,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	return endpoint, nil
}

var defaultMetricsEndpoint = sync.OnceValues(func() (*MetricsEndpoint, error) {
	address := strings.TrimSpace(os.Getenv(MetricsAddressEnv))
	if address == "" {
		return nil, nil
	}
	return Default().StartMetricsEndpoint(address)
})

func ensureDefaultMetricsEndpoint() error {
	_, err := defaultMetricsEndpoint()
	return err
}

// NewServer creates an application gRPC server with native metrics enabled.
// The metrics HTTP endpoint starts automatically when MetricsAddressEnv is set.
func NewServer(options ...grpc.ServerOption) (*grpc.Server, error) {
	if err := ensureDefaultMetricsEndpoint(); err != nil {
		return nil, err
	}
	options = append(options, Default().ServerOption())
	return grpc.NewServer(options...), nil
}

// NewClient creates an application gRPC client with native metrics enabled.
// A process exposes one shared metrics endpoint for all servers and clients.
func NewClient(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	if err := ensureDefaultMetricsEndpoint(); err != nil {
		return nil, err
	}
	options = append(options, Default().ClientDialOption())
	return grpc.NewClient(target, options...)
}
