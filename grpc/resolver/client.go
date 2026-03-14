package resolver

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	corev1 "github.com/dubbo-kubernetes/xds-api/core/v1"
	discovery "github.com/dubbo-kubernetes/xds-api/service/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client is a minimal xDS ADS client backed by xds-api types.
type Client struct {
	conn   *grpc.ClientConn
	stream discovery.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	client discovery.AggregatedDiscoveryServiceClient
	node   *corev1.Node
}

// NewClient dials the xDS management server and opens an ADS stream.
func NewClient(ctx context.Context, serverURI string) (*Client, error) {
	// Strip unix:// prefix for grpc dial
	addr := serverURI
	if strings.HasPrefix(addr, "unix://") {
		addr = "unix:" + strings.TrimPrefix(addr, "unix://")
	}

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial xDS server %s: %w", addr, err)
	}

	svcClient := discovery.NewAggregatedDiscoveryServiceClient(conn)
	stream, err := svcClient.StreamAggregatedResources(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to open ADS stream: %w", err)
	}

	// Build node identity in Istio/Dubbo format: pod_name.namespace.service_account.cluster_id
	nodeID := os.Getenv("POD_NAME")
	if nodeID == "" {
		nodeID = os.Getenv("HOSTNAME")
	}
	if nodeID == "" {
		nodeID = "grpc-consumer"
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	serviceAccount := os.Getenv("SERVICE_ACCOUNT")
	if serviceAccount == "" {
		serviceAccount = "default"
	}

	clusterID := os.Getenv("CLUSTER_ID")
	if clusterID == "" {
		clusterID = "Kubernetes"
	}

	node := &corev1.Node{
		Id: fmt.Sprintf("%s.%s.%s.%s", nodeID, namespace, serviceAccount, clusterID),
	}

	log.Printf("[xds-client] ADS stream established to %s (node.id=%s)", addr, node.Id)
	return &Client{
		conn:   conn,
		stream: stream,
		client: svcClient,
		node:   node,
	}, nil
}

// Subscribe sends a DiscoveryRequest for the given typeURL and resource names.
// The Node field is included in every request so the control plane can identify the client.
func (c *Client) Subscribe(typeURL string, resourceNames []string) error {
	return c.stream.Send(&discovery.DiscoveryRequest{
		Node:          c.node,
		TypeUrl:       typeURL,
		ResourceNames: resourceNames,
	})
}

// Recv receives the next DiscoveryResponse from the ADS stream.
func (c *Client) Recv() (*discovery.DiscoveryResponse, error) {
	return c.stream.Recv()
}

// Ack acknowledges a received DiscoveryResponse.
func (c *Client) Ack(resp *discovery.DiscoveryResponse) error {
	return c.stream.Send(&discovery.DiscoveryRequest{
		Node:          c.node,
		TypeUrl:       resp.TypeUrl,
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
}

// Close shuts down the ADS stream and underlying connection.
func (c *Client) Close() {
	c.conn.Close()
}
