package resolver

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "github.com/dubbo-kubernetes/xds-api/core/v1"
	endpointv1 "github.com/dubbo-kubernetes/xds-api/endpoint/v1"
	discovery "github.com/dubbo-kubernetes/xds-api/service/discovery/v1"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"
)

const (
	// Scheme is the xDS resolver scheme
	Scheme = "xds"
	// Dubbo xDS API types
	clusterType  = "type.googleapis.com/cluster.v1.Cluster"
	endpointType = "type.googleapis.com/endpoint.v1.ClusterLoadAssignment"
)

func init() {
	// Register the xDS resolver builder
	resolver.Register(&xdsResolverBuilder{})
}

type xdsResolverBuilder struct{}

func (*xdsResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	log.Printf("[xds-resolver] Building resolver for target: %+v", target)

	// Parse target: xds:///service.namespace.svc.cluster.local:port
	serviceName := strings.TrimPrefix(target.URL.Path, "/")
	if serviceName == "" {
		return nil, fmt.Errorf("invalid xDS target: empty service name")
	}

	// Get bootstrap config
	bootstrapPath := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if bootstrapPath == "" {
		return nil, fmt.Errorf("GRPC_XDS_BOOTSTRAP environment variable not set")
	}

	bootstrap, err := ParseBootstrap(bootstrapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap: %w", err)
	}

	r := &xdsResolver{
		target:    serviceName,
		cc:        cc,
		serverURI: bootstrap.ServerURI,
		node:      bootstrap.Node,
		closeCh:   make(chan struct{}),
	}

	go r.watcher()

	return r, nil
}

func (*xdsResolverBuilder) Scheme() string {
	return Scheme
}

type xdsResolver struct {
	target    string
	cc        resolver.ClientConn
	serverURI string
	node      *corev1.Node
	closeCh   chan struct{}
	mu        sync.Mutex
	client    *Client
}

func (r *xdsResolver) watcher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to xDS server
	client, err := NewClient(ctx, r.serverURI, r.node)
	if err != nil {
		log.Printf("[xds-resolver] Failed to connect to xDS server: %v", err)
		r.cc.ReportError(err)
		return
	}
	defer client.Close()

	r.mu.Lock()
	r.client = client
	r.mu.Unlock()

	// Subscribe to cluster and endpoint updates
	clusterName := r.target
	if err := client.Subscribe(clusterType, []string{clusterName}); err != nil {
		log.Printf("[xds-resolver] Failed to subscribe to clusters: %v", err)
		r.cc.ReportError(err)
		return
	}

	log.Printf("[xds-resolver] Subscribed to cluster: %s", clusterName)

	// Process xDS responses
	for {
		select {
		case <-r.closeCh:
			log.Printf("[xds-resolver] Resolver closed")
			return
		default:
		}

		resp, err := client.Recv()
		if err != nil {
			log.Printf("[xds-resolver] Error receiving xDS response: %v", err)
			r.cc.ReportError(err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("[xds-resolver] Received xDS response: TypeUrl=%s, VersionInfo=%s, Nonce=%s, Resources=%d",
			resp.TypeUrl, resp.VersionInfo, resp.Nonce, len(resp.Resources))

		// Ack the response
		if err := client.Ack(resp); err != nil {
			log.Printf("[xds-resolver] Failed to ack response: %v", err)
		}

		// Process based on type
		switch resp.TypeUrl {
		case clusterType:
			// After receiving cluster, subscribe to endpoints
			if err := client.Subscribe(endpointType, []string{clusterName}); err != nil {
				log.Printf("[xds-resolver] Failed to subscribe to endpoints: %v", err)
			}

		case endpointType:
			// Parse endpoints and update resolver
			addrs := r.parseEndpoints(resp)
			if len(addrs) > 0 {
				log.Printf("[xds-resolver] Updating %d endpoints for %s", len(addrs), r.target)
				state := resolver.State{
					Addresses: addrs,
				}
				if err := r.cc.UpdateState(state); err != nil {
					log.Printf("[xds-resolver] Failed to update state: %v", err)
				}
			}
		}
	}
}

func (r *xdsResolver) parseEndpoints(resp *discovery.DiscoveryResponse) []resolver.Address {
	var addrs []resolver.Address

	for _, resource := range resp.Resources {
		// Unmarshal to ClusterLoadAssignment from dubbo xds-api
		cla := &endpointv1.ClusterLoadAssignment{}
		if err := proto.Unmarshal(resource.Value, cla); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal ClusterLoadAssignment: %v", err)
			continue
		}

		log.Printf("[xds-resolver] ClusterLoadAssignment: cluster_name=%s, endpoints=%d",
			cla.ClusterName, len(cla.Endpoints))

		// Extract endpoints from LocalityLbEndpoints
		for _, localityEp := range cla.Endpoints {
			for _, lbEp := range localityEp.LbEndpoints {
				if lbEp.GetEndpoint() == nil {
					continue
				}

				endpoint := lbEp.GetEndpoint()
				if endpoint.Address == nil {
					continue
				}

				// Get socket address
				socketAddr := endpoint.Address.GetSocketAddress()
				if socketAddr == nil {
					continue
				}

				addr := socketAddr.Address
				port := socketAddr.GetPortValue()

				if addr != "" && port > 0 {
					target := fmt.Sprintf("%s:%d", addr, port)
					log.Printf("[xds-resolver] Found endpoint: %s", target)
					addrs = append(addrs, resolver.Address{
						Addr: target,
					})
				}
			}
		}
	}

	return addrs
}

func (r *xdsResolver) ResolveNow(resolver.ResolveNowOptions) {
	// Trigger immediate resolution if needed
	log.Printf("[xds-resolver] ResolveNow called for %s", r.target)
}

func (r *xdsResolver) Close() {
	log.Printf("[xds-resolver] Closing resolver for %s", r.target)
	close(r.closeCh)
}


