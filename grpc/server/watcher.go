package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	corev1 "github.com/dubbo-kubernetes/xds-api/core/v1"
	tlsv1 "github.com/dubbo-kubernetes/xds-api/extensions/transport_sockets/tls/v1"
	listenerv1 "github.com/dubbo-kubernetes/xds-api/listener/v1"
	discovery "github.com/dubbo-kubernetes/xds-api/service/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	listenerType = "type.googleapis.com/listener.v1.Listener"
	// serverListenerNameTemplate matches the bootstrap server_listener_resource_name_template.
	serverListenerNameTemplate = "xds.dubbo.apache.org/grpc/lds/inbound/%s"
)

// TLSMode represents the server-side TLS operating mode derived from xDS.
type TLSMode int

const (
	// TLSModeUnknown means the inbound listener has not been received yet.
	TLSModeUnknown TLSMode = iota
	// TLSModePlaintext means no DownstreamTlsContext on the inbound filter chain.
	TLSModePlaintext
	// TLSModeMTLS means a DownstreamTlsContext with client cert requirement was found.
	TLSModeMTLS
)

// InboundTLSConfig carries the resolved TLS decision for a server listener.
type InboundTLSConfig struct {
	Mode        TLSMode
	Downstream  *tlsv1.DownstreamTlsContext // non-nil only when Mode == TLSModeMTLS
}

// Watcher subscribes to the xDS inbound listener for a given address and
// delivers TLS configuration updates via a channel.
type Watcher struct {
	addr      string // e.g. "0.0.0.0:17070"
	bootstrap string // path to grpc-bootstrap.json

	mu     sync.Mutex
	current *InboundTLSConfig
	updateCh chan *InboundTLSConfig
	closeCh  chan struct{}
}

// NewWatcher creates a Watcher for the inbound listener of the given address.
// bootstrapPath defaults to the GRPC_XDS_BOOTSTRAP env var if empty.
func NewWatcher(addr, bootstrapPath string) *Watcher {
	if bootstrapPath == "" {
		bootstrapPath = os.Getenv("GRPC_XDS_BOOTSTRAP")
	}
	return &Watcher{
		addr:      addr,
		bootstrap: bootstrapPath,
		updateCh:  make(chan *InboundTLSConfig, 8),
		closeCh:   make(chan struct{}),
	}
}

// UpdateCh returns the channel on which TLS config updates are delivered.
func (w *Watcher) UpdateCh() <-chan *InboundTLSConfig {
	return w.updateCh
}

// Start begins watching in a background goroutine.
func (w *Watcher) Start() {
	go w.run()
}

// Close stops the watcher.
func (w *Watcher) Close() {
	close(w.closeCh)
}

// WaitForInitial blocks until the first xDS response is received or ctx is done.
// Returns the initial TLS config.
func (w *Watcher) WaitForInitial(ctx context.Context) (*InboundTLSConfig, error) {
	select {
	case cfg := <-w.updateCh:
		return cfg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (w *Watcher) run() {
	for {
		select {
		case <-w.closeCh:
			return
		default:
		}
		w.connect()
	}
}

func (w *Watcher) connect() {
	serverURI, node, err := parseBootstrap(w.bootstrap)
	if err != nil {
		log.Printf("[xds-server-watcher] failed to parse bootstrap: %v", err)
		return
	}

	addr := serverURI
	if strings.HasPrefix(addr, "unix://") {
		addr = "unix:" + strings.TrimPrefix(addr, "unix://")
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-w.closeCh
		cancel()
	}()
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("[xds-server-watcher] failed to dial %s: %v", addr, err)
		return
	}
	defer conn.Close()

	svcClient := discovery.NewAggregatedDiscoveryServiceClient(conn)
	stream, err := svcClient.StreamAggregatedResources(ctx)
	if err != nil {
		log.Printf("[xds-server-watcher] failed to open ADS stream: %v", err)
		return
	}

	listenerName := fmt.Sprintf(serverListenerNameTemplate, w.addr)
	// Subscribe with both the precise listener name AND wildcard so we receive
	// full pushes triggered by PeerAuthentication/DestinationRule changes as
	// well as targeted pushes for our specific inbound listener.
	if err := stream.Send(&discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       listenerType,
		ResourceNames: []string{listenerName},
	}); err != nil {
		log.Printf("[xds-server-watcher] failed to subscribe to inbound listener: %v", err)
		return
	}
	log.Printf("[xds-server-watcher] subscribed to inbound listener: %s", listenerName)

	for {
		select {
		case <-w.closeCh:
			return
		default:
		}

		resp, err := stream.Recv()
		if err != nil {
			log.Printf("[xds-server-watcher] recv error: %v", err)
			return
		}

		// ACK while keeping the precise listener name subscription alive.
		_ = stream.Send(&discovery.DiscoveryRequest{
			Node:          node,
			TypeUrl:       resp.TypeUrl,
			VersionInfo:   resp.VersionInfo,
			ResponseNonce: resp.Nonce,
			ResourceNames: []string{listenerName},
		})

		if resp.TypeUrl != listenerType {
			continue
		}

		cfg := w.parseTLSFromLDS(resp, listenerName)
		w.mu.Lock()
		w.current = cfg
		w.mu.Unlock()

		select {
		case w.updateCh <- cfg:
		default:
			// Drop stale update if consumer is slow; keep latest.
			select {
			case <-w.updateCh:
			default:
			}
			w.updateCh <- cfg
		}
	}
}

func (w *Watcher) parseTLSFromLDS(resp *discovery.DiscoveryResponse, listenerName string) *InboundTLSConfig {
	for _, resource := range resp.Resources {
		lis := &listenerv1.Listener{}
		if err := proto.Unmarshal(resource.Value, lis); err != nil {
			log.Printf("[xds-server-watcher] failed to unmarshal Listener: %v", err)
			continue
		}
		if lis.Name != listenerName {
			continue
		}
		for _, fc := range lis.GetFilterChains() {
			ts := fc.GetTransportSocket()
			if ts == nil {
				continue
			}
			typedCfg := ts.GetTypedConfig()
			if typedCfg == nil {
				continue
			}
			downstream := &tlsv1.DownstreamTlsContext{}
			if err := anypb.UnmarshalTo(typedCfg, downstream, proto.UnmarshalOptions{}); err != nil {
				continue
			}
			log.Printf("[xds-server-watcher] listener %s has DownstreamTlsContext (mTLS)", listenerName)
			return &InboundTLSConfig{Mode: TLSModeMTLS, Downstream: downstream}
		}
		log.Printf("[xds-server-watcher] listener %s has no DownstreamTlsContext (plaintext)", listenerName)
		return &InboundTLSConfig{Mode: TLSModePlaintext}
	}
	// Listener not found in response — treat as plaintext.
	return &InboundTLSConfig{Mode: TLSModePlaintext}
}

// parseBootstrap extracts serverURI and Node from the bootstrap file.
// Node is fully parsed (including metadata) so the control plane can
// resolve ServiceTargets by pod IP when handling the inbound LDS request.
func parseBootstrap(path string) (string, *corev1.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", nil, fmt.Errorf("parse JSON: %w", err)
	}
	var serverURI string
	if serversRaw, ok := raw["xds_servers"]; ok {
		var servers []map[string]json.RawMessage
		if err := json.Unmarshal(serversRaw, &servers); err == nil && len(servers) > 0 {
			var uri string
			if err := json.Unmarshal(servers[0]["server_uri"], &uri); err == nil {
				serverURI = uri
			}
		}
	}
	if serverURI == "" {
		return "", nil, fmt.Errorf("no xds_servers[0].server_uri in bootstrap")
	}
	var node *corev1.Node
	if nodeRaw, ok := raw["node"]; ok {
		n := &corev1.Node{}
		if err := protojson.Unmarshal(nodeRaw, n); err == nil {
			node = n
		} else {
			log.Printf("[xds-server-watcher] failed to protojson-unmarshal node: %v, falling back to id-only", err)
			var m map[string]json.RawMessage
			if err2 := json.Unmarshal(nodeRaw, &m); err2 == nil {
				if idRaw, ok := m["id"]; ok {
					var id string
					_ = json.Unmarshal(idRaw, &id)
					node = &corev1.Node{Id: id}
				}
			}
		}
	}
	return serverURI, node, nil
}

