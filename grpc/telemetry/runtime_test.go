package telemetry

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

func TestRuntimeRecordsClientAndServerWithoutRemovedStatus(t *testing.T) {
	path := writeConfig(t, `{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"],
			"rules":[{"metric":"REQUEST_COUNT","scope":"CLIENT_AND_SERVER"}]
		}}
	}`)
	runtime := NewRuntime(path)
	clientHandler := runtime.ClientStatsHandler()
	clientCtx := clientHandler.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: "/payments.Payment/Get"})
	clientHandler.HandleRPC(clientCtx, &stats.End{})

	handler := runtime.ServerStatsHandler()
	ctx := handler.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: "/payments.Payment/Get"})
	handler.HandleRPC(ctx, &stats.End{Error: status.Error(codes.PermissionDenied, "denied")})

	var output bytes.Buffer
	if err := runtime.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`reporter="client",grpc_method="/payments.Payment/Get",grpc_response_status="OK"} 1`,
		`reporter="server",grpc_method="/payments.Payment/Get",grpc_response_status="PermissionDenied"} 1`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, output.String())
		}
	}
}

func TestRuntimeRemovesGRPCResponseStatus(t *testing.T) {
	path := writeConfig(t, `{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"],
			"rules":[{
				"metric":"REQUEST_COUNT",
				"scope":"CLIENT",
				"tags":{"grpc_response_status":{"action":"REMOVE"}}
			}]
		}}
	}`)
	runtime := NewRuntime(path)
	runtime.RecordClient("/payments.Payment/Get", nil)
	runtime.RecordClient("/payments.Payment/Get", status.Error(codes.Unavailable, "retry"))

	var output bytes.Buffer
	if err := runtime.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `reporter="client",grpc_method="/payments.Payment/Get"} 2`) {
		t.Fatalf("aggregated metric missing:\n%s", output.String())
	}
	if strings.Contains(output.String(), "grpc_response_status") {
		t.Fatalf("removed tag still exported:\n%s", output.String())
	}
}

func TestRuntimeDisabledDoesNotRecord(t *testing.T) {
	path := writeConfig(t, `{"telemetry":{"metrics":{"enabled":false}}}`)
	runtime := NewRuntime(path)
	runtime.RecordClient("/payments.Payment/Get", nil)

	var output bytes.Buffer
	if err := runtime.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatalf("disabled metrics output = %q", output.String())
	}
}

func TestProviderOnlyEnablesDefaultRequestCountOnBothSides(t *testing.T) {
	config, err := parseMetricConfig([]byte(`{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"]
		}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !config.enabled || !config.client || !config.server {
		t.Fatalf("default config = %+v", config)
	}
}

func TestParseMetricConfigRejectsUnsupportedValues(t *testing.T) {
	_, err := parseMetricConfig([]byte(`{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["unknown"],
			"rules":[]
		}}
	}`))
	if err == nil {
		t.Fatal("parseMetricConfig() error = nil")
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
