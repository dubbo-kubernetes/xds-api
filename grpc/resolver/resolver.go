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
	clusterv1 "github.com/dubbo-kubernetes/xds-api/cluster/v1"
	endpointv1 "github.com/dubbo-kubernetes/xds-api/endpoint/v1"
	listenerv1 "github.com/dubbo-kubernetes/xds-api/listener/v1"
	routev1 "github.com/dubbo-kubernetes/xds-api/route/v1"
	discovery "github.com/dubbo-kubernetes/xds-api/service/discovery/v1"
	tlsv1 "github.com/dubbo-kubernetes/xds-api/extensions/transport_sockets/tls/v1"
	"google.golang.org/grpc/resolver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	Scheme       = "xds"
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
		target:         serviceName,
		cc:             cc,
		serverURI:      bootstrap.ServerURI,
		node:           bootstrap.Node,
		closeCh:        make(chan struct{}),
		clusterWeights: make(map[string]uint32),
		clusterAddrs:   make(map[string][]resolver.Address),
		clusterTLS:     make(map[string]*tlsv1.UpstreamTlsContext),
	}

	go r.watcher()
	return r, nil
}

func (*xdsResolverBuilder) Scheme() string { return Scheme }

type xdsResolver struct {
	target         string
	cc             resolver.ClientConn
	serverURI      string
	node           *corev1.Node
	closeCh        chan struct{}
	mu             sync.Mutex
	client         *Client
	// cluster weight map from RDS: cluster_name -> weight
	clusterWeights map[string]uint32
	// cluster endpoint map from EDS: cluster_name -> []Address
	clusterAddrs   map[string][]resolver.Address
	pendingClusters []string
	// cluster TLS context from CDS: cluster_name -> UpstreamTlsContext (nil means plaintext)
	clusterTLS     map[string]*tlsv1.UpstreamTlsContext
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

	listenerName := r.target
	if err := client.Subscribe(listenerType, []string{listenerName}); err != nil {
		log.Printf("[xds-resolver] Failed to subscribe to LDS: %v", err)
		r.cc.ReportError(err)
		return
	}
	log.Printf("[xds-resolver] Subscribed to LDS: %s", listenerName)

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
			routeNames := extractRouteNamesFromLDS(resp)
			if len(routeNames) > 0 {
				log.Printf("[xds-resolver] LDS gave route names: %v", routeNames)
				if err := client.Subscribe(routeType, routeNames); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to RDS: %v", err)
				}
			} else {
				log.Printf("[xds-resolver] LDS gave no route names, falling back to direct CDS")
				clusterName := buildClusterName(r.target)
				r.clusterWeights[clusterName] = 1
				if err := client.Subscribe(clusterType, []string{clusterName}); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to CDS: %v", err)
				}
			}

		case routeType:
			// Extract clusters with weights from RDS
			weights := extractClusterWeightsFromRDS(resp)
			if len(weights) > 0 {
				log.Printf("[xds-resolver] RDS gave cluster weights: %v", weights)
				r.mu.Lock()
				r.clusterWeights = weights
				// 路由规则变化时清空 endpoint 缓存，避免旧 subset 数据污染新权重计算
				r.clusterAddrs = make(map[string][]resolver.Address)
				r.mu.Unlock()
				clusters := make([]string, 0, len(weights))
				for c := range weights {
					clusters = append(clusters, c)
				}
				r.pendingClusters = clusters
				if err := client.Subscribe(clusterType, clusters); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to CDS: %v", err)
				}
			}

		case clusterType:
			// Parse TransportSocket from CDS to extract TLS configuration
			r.updateClusterTLS(resp)

			// Only subscribe to EDS for the clusters we actually need (from RDS weights)
			var edsClusters []string
			if len(r.clusterWeights) > 0 {
				// Use weighted clusters from RDS
				for c := range r.clusterWeights {
					edsClusters = append(edsClusters, c)
				}
			} else {
				edsClusters = []string{buildClusterName(r.target)}
			}
			log.Printf("[xds-resolver] CDS received, subscribing to EDS for: %v", edsClusters)
			if err := client.Subscribe(endpointType, edsClusters); err != nil {
				log.Printf("[xds-resolver] Failed to subscribe to EDS: %v", err)
			}

		case endpointType:
			// Store endpoints per cluster
			r.updateClusterAddrs(resp)
			// Build weighted address list
			addrs := r.buildWeightedAddresses()
			if len(addrs) > 0 {
				log.Printf("[xds-resolver] Updating %d weighted endpoints for %s", len(addrs), r.target)
				if err := r.cc.UpdateState(resolver.State{Addresses: addrs}); err != nil {
					log.Printf("[xds-resolver] Failed to update state: %v", err)
				}
			}
		}
	}
}

// updateClusterTLS parses TransportSocket from CDS response and stores TLS context per cluster.
func (r *xdsResolver) updateClusterTLS(resp *discovery.DiscoveryResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, resource := range resp.Resources {
		c := &clusterv1.Cluster{}
		if err := proto.Unmarshal(resource.Value, c); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal Cluster: %v", err)
			continue
		}
		if c.TransportSocket == nil {
			log.Printf("[xds-resolver] Cluster %s has no TransportSocket (plaintext)", c.Name)
			r.clusterTLS[c.Name] = nil
			continue
		}
		typedConfig := c.TransportSocket.GetTypedConfig()
		if typedConfig == nil {
			r.clusterTLS[c.Name] = nil
			continue
		}
		upstreamTLS := &tlsv1.UpstreamTlsContext{}
		if err := anypb.UnmarshalTo(typedConfig, upstreamTLS, proto.UnmarshalOptions{}); err != nil {
			log.Printf("[xds-resolver] Cluster %s TransportSocket is not UpstreamTlsContext: %v", c.Name, err)
			r.clusterTLS[c.Name] = nil
			continue
		}
		r.clusterTLS[c.Name] = upstreamTLS
		log.Printf("[xds-resolver] Cluster %s has mTLS TransportSocket (SNI=%s)", c.Name, upstreamTLS.Sni)
	}

	// Publish to global index so consumer can query TLS config by target
	globalTLSMu.Lock()
	if globalTLSIndex[r.target] == nil {
		globalTLSIndex[r.target] = make(map[string]*tlsv1.UpstreamTlsContext)
	}
	for k, v := range r.clusterTLS {
		globalTLSIndex[r.target][k] = v
	}
	globalTLSMu.Unlock()
}

// TLSContextKey is the key used to store UpstreamTlsContext in resolver.Address.BalancerAttributes.
type TLSContextKey struct{}

// globalClusterTLS stores the latest TLS context per target URL for consumer lookup.
// Key: xds target URL (e.g. "xds:///provider.grpc-app.svc.cluster.local:7070")
// Value: map[clusterName]*UpstreamTlsContext
var (
	globalTLSMu    sync.RWMutex
	globalTLSIndex = map[string]map[string]*tlsv1.UpstreamTlsContext{}
)

// GetClusterTLSForTarget returns the UpstreamTlsContext for the given xDS target URL.
// It returns the first non-nil TLS context found across all clusters for that target.
// Returns nil if no TLS context is configured (plaintext mode).
func GetClusterTLSForTarget(targetURL string) *tlsv1.UpstreamTlsContext {
	// Normalise: strip scheme prefix to get the service name used as resolver target
	service := targetURL
	if idx := strings.Index(targetURL, ":///"); idx >= 0 {
		service = targetURL[idx+4:]
	}

	globalTLSMu.RLock()
	defer globalTLSMu.RUnlock()
	for target, clusters := range globalTLSIndex {
		if target == service || strings.HasSuffix(target, service) || strings.HasSuffix(service, target) {
			for _, ctx := range clusters {
				if ctx != nil {
					return ctx
				}
			}
		}
	}
	return nil
}


func (r *xdsResolver) updateClusterAddrs(resp *discovery.DiscoveryResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, resource := range resp.Resources {
		cla := &endpointv1.ClusterLoadAssignment{}
		if err := proto.Unmarshal(resource.Value, cla); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal ClusterLoadAssignment: %v", err)
			continue
		}
		var addrs []resolver.Address
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
					addrs = append(addrs, resolver.Address{Addr: fmt.Sprintf("%s:%d", addr, port)})
				}
			}
		}
		log.Printf("[xds-resolver] Cluster %s has %d endpoints", cla.ClusterName, len(addrs))
		r.clusterAddrs[cla.ClusterName] = addrs
	}
}

// buildWeightedAddresses builds a flat address list with each cluster's endpoints
// repeated proportionally to its weight, so round_robin achieves weighted distribution.
// Each repeated entry gets a unique "#N" suffix appended to Addr so that
// EndpointMap (which keys only on addr.Addr) treats them as distinct endpoints.
// The consumer must strip this suffix in its dialer before connecting.
// TLS context from CDS is stored in BalancerAttributes under TLSContextKey{}.
func (r *xdsResolver) buildWeightedAddresses() []resolver.Address {
	if len(r.clusterWeights) == 0 || len(r.clusterAddrs) == 0 {
		return nil
	}

	// Calculate GCD to normalize weights
	weights := make([]uint32, 0, len(r.clusterWeights))
	for _, w := range r.clusterWeights {
		weights = append(weights, w)
	}
	g := weights[0]
	for _, w := range weights[1:] {
		g = gcd(g, w)
	}
	if g == 0 {
		g = 1
	}

	var addrs []resolver.Address
	seq := 0
	for cluster, weight := range r.clusterWeights {
		clusterAddrs, ok := r.clusterAddrs[cluster]
		if !ok || len(clusterAddrs) == 0 {
			continue
		}
		// Repeat each endpoint weight/gcd times
		repeat := weight / g
		if repeat == 0 {
			repeat = 1
		}
		log.Printf("[xds-resolver] cluster=%s weight=%d repeat=%d endpoints=%d",
			cluster, weight, repeat, len(clusterAddrs))

		// Look up TLS context for this cluster
		tlsCtx := r.clusterTLS[cluster]

		for i := uint32(0); i < repeat; i++ {
			for _, a := range clusterAddrs {
				// 给 Addr 加唯一序号后缀，使 EndpointMap 将每个条目视为不同 endpoint
				// consumer 的 dialer 会在建连前剥掉 #N 后缀
				a.Addr = fmt.Sprintf("%s#%d", a.Addr, seq)
				seq++
				// Attach TLS context so consumer dialer can pick it up
				if tlsCtx != nil {
					a.BalancerAttributes = a.BalancerAttributes.WithValue(TLSContextKey{}, tlsCtx)
				}
				addrs = append(addrs, a)
			}
		}
	}
	return addrs
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
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
		hcmBytes := lis.ApiListener.ApiListener.Value
		if name := extractRouteNameFromHCM(hcmBytes); name != "" {
			routeNames = append(routeNames, name)
		}
	}
	return routeNames
}

// extractRouteNameFromHCM scans HCM bytes for the route config name.
func extractRouteNameFromHCM(data []byte) string {
	s := string(data)
	const prefix = "outbound|"
	if idx := strings.Index(s, prefix); idx >= 0 {
		end := idx
		for end < len(s) && s[end] >= ' ' && s[end] <= '~' {
			end++
		}
		name := s[idx:end]
		parts := strings.Split(name, "|")
		if len(parts) == 4 && parts[0] == "outbound" {
			return name
		}
	}
	return ""
}

// extractClusterWeightsFromRDS extracts cluster names and their weights from RDS response.
func extractClusterWeightsFromRDS(resp *discovery.DiscoveryResponse) map[string]uint32 {
	weights := make(map[string]uint32)
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
					weights[c] = 1
				}
				if wc := action.GetWeightedClusters(); wc != nil {
					for _, cw := range wc.Clusters {
						if cw.Name != "" {
							w := uint32(1)
							if cw.Weight != nil {
								w = cw.Weight.GetValue()
							}
							weights[cw.Name] = w
							log.Printf("[xds-resolver] cluster=%s weight=%d", cw.Name, w)
						}
					}
				}
			}
		}
	}
	return weights
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

func (r *xdsResolver) ResolveNow(resolver.ResolveNowOptions) {
	log.Printf("[xds-resolver] ResolveNow called for %s", r.target)
}

func (r *xdsResolver) Close() {
	log.Printf("[xds-resolver] Closing resolver for %s", r.target)
	close(r.closeCh)
}
