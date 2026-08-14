package telemetry

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		`reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK"} 1`,
		`reporter="server",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="PermissionDenied"} 1`,
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
	if !strings.Contains(output.String(), `reporter="client",grpc_service="payments.Payment",grpc_method="Get"} 2`) {
		t.Fatalf("aggregated metric missing:\n%s", output.String())
	}
	if strings.Contains(output.String(), "grpc_response_status") {
		t.Fatalf("removed tag still exported:\n%s", output.String())
	}
}

func TestRuntimeRecordsRequiredDistributions(t *testing.T) {
	path := writeConfig(t, `{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"]
		}}
	}`)
	runtime := NewRuntime(path)
	handler := runtime.ClientStatsHandler()
	ctx := handler.TagRPC(context.Background(), &stats.RPCTagInfo{FullMethodName: "/payments.Payment/Get"})
	handler.HandleRPC(ctx, &stats.OutPayload{Length: 100})
	handler.HandleRPC(ctx, &stats.InPayload{Length: 200})
	start := time.Unix(10, 0)
	handler.HandleRPC(ctx, &stats.End{BeginTime: start, EndTime: start.Add(250 * time.Millisecond)})

	var output bytes.Buffer
	if err := runtime.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`dubbo_inherent_requests_total{reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK"} 1`,
		`dubbo_inherent_request_duration_seconds_bucket{reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK",le="0.25"} 1`,
		`dubbo_inherent_request_duration_seconds_sum{reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK"} 0.25`,
		`dubbo_inherent_request_size_bytes_bucket{reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK",le="256"} 1`,
		`dubbo_inherent_request_size_bytes_sum{reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK"} 100`,
		`dubbo_inherent_response_size_bytes_sum{reporter="client",grpc_service="payments.Payment",grpc_method="Get",grpc_response_status="OK"} 200`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, output.String())
		}
	}
}

func TestRuntimeRemovesEveryStandardLabel(t *testing.T) {
	path := writeConfig(t, `{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"],
			"rules":[{
				"metric":"REQUEST_COUNT",
				"scope":"CLIENT_AND_SERVER",
				"tags":{
					"reporter":{"action":"REMOVE"},
					"grpc_service":{"action":"REMOVE"},
					"grpc_method":{"action":"REMOVE"},
					"grpc_response_status":{"action":"REMOVE"}
				}
			}]
		}}
	}`)
	runtime := NewRuntime(path)
	runtime.RecordClient("/payments.Payment/Get", nil)
	runtime.recordServer("/payments.Payment/Get", nil)

	var output bytes.Buffer
	if err := runtime.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "dubbo_inherent_requests_total 2\n") {
		t.Fatalf("fully aggregated metric missing:\n%s", output.String())
	}
}

func TestMetricRuleScopeOnlyRestrictsSelectedMetric(t *testing.T) {
	config, err := parseMetricConfig([]byte(`{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"],
			"rules":[{"metric":"REQUEST_COUNT","scope":"CLIENT"}]
		}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if metricEnabled(&config, RequestCountMetric, "server") {
		t.Fatal("REQUEST_COUNT server must be disabled by CLIENT scope")
	}
	for _, metric := range []string{RequestDurationMetric, RequestSizeMetric, ResponseSizeMetric} {
		if !metricEnabled(&config, metric, "client") || !metricEnabled(&config, metric, "server") {
			t.Fatalf("%s must retain default CLIENT_AND_SERVER scope", metric)
		}
	}
}

func TestStandardMetricContract(t *testing.T) {
	got := StandardMetrics()
	want := map[string]MetricType{
		RequestCountMetric:    MetricTypeCounter,
		RequestDurationMetric: MetricTypeDistribution,
		RequestSizeMetric:     MetricTypeDistribution,
		ResponseSizeMetric:    MetricTypeDistribution,
	}
	if len(got) != len(want) {
		t.Fatalf("standard metrics = %d, want %d", len(got), len(want))
	}
	for _, definition := range got {
		if want[definition.Name] != definition.Type {
			t.Fatalf("%s type = %s, want %s", definition.Name, definition.Type, want[definition.Name])
		}
		if strings.Join(definition.Labels, ",") != strings.Join(standardLabels, ",") {
			t.Fatalf("%s labels = %v, want %v", definition.Name, definition.Labels, standardLabels)
		}
	}
}

func TestUsesNativeStats(t *testing.T) {
	runtime := NewRuntime("")
	if UsesNativeStats(context.Background()) {
		t.Fatal("plain context unexpectedly marked with native stats")
	}
	ctx := runtime.ClientStatsHandler().TagRPC(context.Background(), &stats.RPCTagInfo{})
	if !UsesNativeStats(ctx) {
		t.Fatal("stats context marker missing")
	}
}

func TestRuntimeFiltersPreviouslyRecordedReporterAfterScopeChange(t *testing.T) {
	runtime := NewRuntime("")
	both, err := parseMetricConfig([]byte(`{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"]
		}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime.config.Store(&both)
	runtime.RecordClient("/payments.Payment/Get", nil)
	runtime.recordServer("/payments.Payment/Get", nil)
	client, err := parseMetricConfig([]byte(`{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"],
			"rules":[{"metric":"REQUEST_COUNT","scope":"CLIENT"}]
		}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	runtime.config.Store(&client)

	var output bytes.Buffer
	if err := runtime.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `reporter="client"`) {
		t.Fatalf("client metric missing:\n%s", output.String())
	}
	if strings.Contains(output.String(), `reporter="server"`) {
		t.Fatalf("server metric exported outside current scope:\n%s", output.String())
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
	for _, definition := range standardMetricDefinitions {
		if !metricEnabled(&config, definition.Name, "client") || !metricEnabled(&config, definition.Name, "server") {
			t.Fatalf("%s default config = %+v", definition.Name, config)
		}
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

func TestParseMetricConfigRejectsUnknownStandardLabel(t *testing.T) {
	_, err := parseMetricConfig([]byte(`{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"],
			"rules":[{
				"metric":"REQUEST_COUNT",
				"scope":"CLIENT",
				"tags":{"pod":{"action":"REMOVE"}}
			}]
		}}
	}`))
	if err == nil || !strings.Contains(err.Error(), `unsupported standard label "pod"`) {
		t.Fatalf("parseMetricConfig() error = %v", err)
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
