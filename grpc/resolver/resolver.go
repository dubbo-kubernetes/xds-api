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
	listenerv1 "github.com/dubbo-kubernetes/xds-api/listener/v1"
	routev1 "github.com/dubbo-kubernetes/xds-api/route/v1"
	discovery "github.com/dubbo-kubernetes/xds-api/service/discovery/v1"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"
)

const (
	// Scheme is the xDS resolver scheme
	Scheme = "xds"
	// Dubbo xDS API types
	listenerType = "type.googleapis.com/listener.v1.Listener"
	routeType    = "type.googleapis.com/route.v1.RouteConfiguration"
	clusterType  = "type.googleapis.com/cluster.v1.Cluster"
	endpointType = "type.googleapis.com/endpoint.v1.ClusterLoadAssignment"
)

func init() {
	resolver.Register(&xdsResolverBuilder{})
}

type xdsResolverBuilder struct{}

func (*xdsResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	log.Printf("[xds-resolver] Building resolver for target: %+v", target)

	serviceName := strings.TrimPrefix(target.URL.Path, "/")
	if serviceName == "" {
		return nil, fmt.Errorf("invalid xDS target: empty service name")
	}

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

func (*xdsResolverBuilder) Scheme() string { return Scheme }

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

	// Step 1: Subscribe to LDS with listener name (host:port format)
	listenerName := r.target
	if err := client.Subscribe(listenerType, []string{listenerName}); err != nil {
		log.Printf("[xds-resolver] Failed to subscribe to LDS: %v", err)
		r.cc.ReportError(err)
		return
	}
	log.Printf("[xds-resolver] Subscribed to LDS: %s", listenerName)

	// State machine: track which clusters we need endpoints for
	var pendingClusters []string

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

		log.Printf("[xds-resolver] Received response: TypeUrl=%s Resources=%d", resp.TypeUrl, len(resp.Resources))

		if err := client.Ack(resp); err != nil {
			log.Printf("[xds-resolver] Failed to ack: %v", err)
		}

		switch resp.TypeUrl {
		case listenerType:
			// Extract route name from listener's ApiListener RDS config
			routeNames := extractRouteNamesFromLDS(resp)
			if len(routeNames) > 0 {
				log.Printf("[xds-resolver] LDS gave route names: %v", routeNames)
				if err := client.Subscribe(routeType, routeNames); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to RDS: %v", err)
				}
			} else {
				// Fallback: directly subscribe to CDS with outbound cluster name
				log.Printf("[xds-resolver] LDS gave no route names, falling back to direct CDS")
				clusterName := buildClusterName(r.target)
				if err := client.Subscribe(clusterType, []string{clusterName}); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to CDS: %v", err)
				}
			}

		case routeType:
			// Extract cluster names (including weighted) from route config
			clusters := extractClustersFromRDS(resp)
			if len(clusters) > 0 {
				log.Printf("[xds-resolver] RDS gave clusters: %v", clusters)
				pendingClusters = clusters
				if err := client.Subscribe(clusterType, clusters); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to CDS: %v", err)
				}
			}

		case clusterType:
			// Subscribe to EDS for each cluster
			clusters := pendingClusters
			if len(clusters) == 0 {
				clusters = []string{buildClusterName(r.target)}
			}
			log.Printf("[xds-resolver] CDS received, subscribing to EDS for: %v", clusters)
			if err := client.Subscribe(endpointType, clusters); err != nil {
				log.Printf("[xds-resolver] Failed to subscribe to EDS: %v", err)
			}

		case endpointType:
			addrs := r.parseEndpoints(resp)
			if len(addrs) > 0 {
				log.Printf("[xds-resolver] Updating %d endpoints for %s", len(addrs), r.target)
				if err := r.cc.UpdateState(resolver.State{Addresses: addrs}); err != nil {
					log.Printf("[xds-resolver] Failed to update state: %v", err)
				}
			}
		}
	}
}

// extractRouteNamesFromLDS extracts RDS route config names from LDS response.
func extractRouteNamesFromLDS(resp *discovery.DiscoveryResponse) []string {
	var routeNames []string
	for _, resource := range resp.Resources {
		lis := &listenerv1.Listener{}
		if err := proto.Unmarshal(resource.Value, lis); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal Listener: %v", err)
			continue
		}
		if lis.ApiListener == nil || lis.ApiListener.ApiListener == nil {
			continue
		}
		// ApiListener contains an HttpConnectionManager encoded as Any
		// The route config name is embedded - we extract it from the raw bytes
		// by looking for the RDS route_config_name string in the serialized HCM
		hcmBytes := lis.ApiListener.ApiListener.Value
		// Parse route name from HCM bytes: find strings that look like outbound|port||hostname
		if name := extractRouteNameFromHCM(hcmBytes); name != "" {
			routeNames = append(routeNames, name)
		}
	}
	return routeNames
}

// extractRouteNameFromHCM scans HCM bytes for the route config name.
// The route config name in Dubbo format is: outbound|port||hostname
func extractRouteNameFromHCM(data []byte) string {
	s := string(data)
	// Look for outbound|port||hostname pattern
	const prefix = "outbound|"
	if idx := strings.Index(s, prefix); idx >= 0 {
		// Find end of the string (next null byte or non-printable)
		end := idx
		for end < len(s) && s[end] >= ' ' && s[end] <= '~' {
			end++
		}
		name := s[idx:end]
		// Validate format: outbound|port||hostname
		parts := strings.Split(name, "|")
		if len(parts) == 4 && parts[0] == "outbound" {
			return name
		}
	}
	return ""
}

// extractClustersFromRDS extracts all cluster names from RDS response,
// including weighted clusters from VirtualService traffic policies.
func extractClustersFromRDS(resp *discovery.DiscoveryResponse) []string {
	clusterSet := make(map[string]struct{})
	for _, resource := range resp.Resources {
		rc := &routev1.RouteConfiguration{}
		if err := proto.Unmarshal(resource.Value, rc); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal RouteConfiguration: %v", err)
			continue
		}
		log.Printf("[xds-resolver] RouteConfiguration: name=%s, virtual_hosts=%d", rc.Name, len(rc.VirtualHosts))
		for _, vh := range rc.VirtualHosts {
			for _, route := range vh.Routes {
				if route.GetRoute() == nil {
					continue
				}
				action := route.GetRoute()
				if c := action.GetCluster(); c != "" {
					clusterSet[c] = struct{}{}
				}
				if wc := action.GetWeightedClusters(); wc != nil {
					for _, cw := range wc.Clusters {
						if cw.Name != "" {
							clusterSet[cw.Name] = struct{}{}
						}
					}
				}
			}
		}
	}
	clusters := make([]string, 0, len(clusterSet))
	for c := range clusterSet {
		clusters = append(clusters, c)
	}
	return clusters
}

// buildClusterName converts xds target (host:port) to Dubbo cluster name format.
func buildClusterName(target string) string {
	host := target
	port := ""
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		host = target[:idx]
		port = target[idx+1:]
	}
	if port == "" {
		return target
	}
	return fmt.Sprintf("outbound|%s||%s", port, host)
}

func (r *xdsResolver) parseEndpoints(resp *discovery.DiscoveryResponse) []resolver.Address {
	var addrs []resolver.Address
	for _, resource := range resp.Resources {
		cla := &endpointv1.ClusterLoadAssignment{}
		if err := proto.Unmarshal(resource.Value, cla); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal ClusterLoadAssignment: %v", err)
			continue
		}
		log.Printf("[xds-resolver] ClusterLoadAssignment: cluster_name=%s, endpoints=%d",
			cla.ClusterName, len(cla.Endpoints))
		for _, localityEp := range cla.Endpoints {
			for _, lbEp := range localityEp.LbEndpoints {
				if lbEp.GetEndpoint() == nil {
					continue
				}
				endpoint := lbEp.GetEndpoint()
				if endpoint.Address == nil {
					continue
				}
				socketAddr := endpoint.Address.GetSocketAddress()
				if socketAddr == nil {
					continue
				}
				addr := socketAddr.Address
				port := socketAddr.GetPortValue()
				if addr != "" && port > 0 {
					target := fmt.Sprintf("%s:%d", addr, port)
					log.Printf("[xds-resolver] Found endpoint: %s (cluster: %s)", target, cla.ClusterName)
					addrs = append(addrs, resolver.Address{Addr: target})
				}
			}
		}
	}
	return addrs
}

func (r *xdsResolver) ResolveNow(resolver.ResolveNowOptions) {
	log.Printf("[xds-resolver] ResolveNow called for %s", r.target)
}

func (r *xdsResolver) Close() {
	log.Printf("[xds-resolver] Closing resolver for %s", r.target)
	close(r.closeCh)
}
