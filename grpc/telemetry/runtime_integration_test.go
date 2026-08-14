package telemetry

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func TestNativeGRPCStatsProduceAllStandardMetrics(t *testing.T) {
	path := writeConfig(t, `{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"]
		}}
	}`)
	clientRuntime := NewRuntime(path)
	serverRuntime := NewRuntime(path)
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(serverRuntime.ServerOption())
	healthpb.RegisterHealthServer(server, health.NewServer())
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(server.Stop)

	client, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		clientRuntime.ClientDialOption(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := healthpb.NewHealthClient(client).Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}

	for name, runtime := range map[string]*Runtime{"client": clientRuntime, "server": serverRuntime} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := runtime.WritePrometheus(&output); err != nil {
				t.Fatal(err)
			}
			for _, metric := range []string{
				"dubbo_inherent_requests_total",
				"dubbo_inherent_request_duration_seconds_count",
				"dubbo_inherent_request_size_bytes_count",
				"dubbo_inherent_response_size_bytes_count",
			} {
				if !strings.Contains(output.String(), metric) {
					t.Fatalf("%s missing from native gRPC metrics:\n%s", metric, output.String())
				}
			}
			if !strings.Contains(output.String(), `grpc_service="grpc.health.v1.Health",grpc_method="Check"`) {
				t.Fatalf("standard gRPC labels missing:\n%s", output.String())
			}
		})
	}
}
