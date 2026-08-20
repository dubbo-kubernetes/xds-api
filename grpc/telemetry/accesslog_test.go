// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestRuntimeExportsOTLPAccessLog(t *testing.T) {
	endpoint, requests := startOTLPLogsServer(t)
	path := writeConfig(t, fmt.Sprintf(`{
		"telemetry":{"logging":[{
			"providers":["otel"],
			"mode":"CLIENT",
			"filterExpression":"response.code >= 500 && reporter == 'client'",
			"tags":{"component":"payments","environment":"test"},
			"endpoint":%q
		}]}
	}`, endpoint))
	runtime := NewRuntime(path)
	t.Cleanup(runtime.Close)

	runtime.recordRPC("client", "/payment.v1.Payment/Pay", codes.Internal, 250*time.Millisecond, 0, 0)
	record := onlyOTLPLogRecord(t, waitForOTLPRequest(t, requests))
	attributes := otlpLogAttributes(record)

	for name, want := range map[string]string{
		"service":     "payment.v1.Payment",
		"method":      "Pay",
		"status":      "Internal",
		"reporter":    "client",
		"component":   "payments",
		"environment": "test",
		"rpc.system":  "grpc",
	} {
		if got := attributes[name].GetStringValue(); got != want {
			t.Fatalf("attribute %q = %q, want %q", name, got, want)
		}
	}
	if got := attributes["duration_ms"].GetDoubleValue(); got != 250 {
		t.Fatalf("duration_ms = %v, want 250", got)
	}
	if got := attributes["response.code"].GetIntValue(); got != 500 {
		t.Fatalf("response.code = %d, want 500", got)
	}
	if got := attributes["grpc.status_code"].GetIntValue(); got != int64(codes.Internal) {
		t.Fatalf("grpc.status_code = %d, want %d", got, codes.Internal)
	}
	if failed := runtime.accessLogFailed.Load(); failed != 0 {
		t.Fatalf("access log exports failed = %d", failed)
	}
}

func TestRuntimeAppliesAccessLogModeDisabledAndFilter(t *testing.T) {
	endpoint, requests := startOTLPLogsServer(t)
	path := writeConfig(t, fmt.Sprintf(`{
		"telemetry":{"logging":[
			{"providers":["otel"],"disabled":true,"mode":"CLIENT","endpoint":%q},
			{"providers":["otel"],"mode":"SERVER","filterExpression":"grpc.status_code == 13","endpoint":%q}
		]}
	}`, endpoint, endpoint))
	runtime := NewRuntime(path)
	t.Cleanup(runtime.Close)

	runtime.recordRPC("client", "/payment.v1.Payment/Pay", codes.Internal, time.Millisecond, 0, 0)
	runtime.recordRPC("server", "/payment.v1.Payment/Pay", codes.OK, time.Millisecond, 0, 0)
	runtime.recordRPC("server", "/payment.v1.Payment/Pay", codes.Internal, time.Millisecond, 0, 0)

	record := onlyOTLPLogRecord(t, waitForOTLPRequest(t, requests))
	attributes := otlpLogAttributes(record)
	if got := attributes["reporter"].GetStringValue(); got != "server" {
		t.Fatalf("reporter = %q, want server", got)
	}
	if got := attributes["status"].GetStringValue(); got != "Internal" {
		t.Fatalf("status = %q, want Internal", got)
	}
	select {
	case request := <-requests:
		t.Fatalf("unexpected additional access log: %#v", request)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestRuntimeReloadsLoggingFromProjectedSecret(t *testing.T) {
	endpoint, requests := startOTLPLogsServer(t)
	path := writeConfig(t, fmt.Sprintf(`{
		"telemetry":{"logging":[{"providers":["otel"],"disabled":true,"endpoint":%q}]}
	}`, endpoint))
	runtime := NewRuntime(path)
	t.Cleanup(runtime.Close)

	enabled := fmt.Sprintf(`{
		"telemetry":{"logging":[{"providers":["otel"],"mode":"CLIENT","tags":{"version":"new"},"endpoint":%q}]}
	}`, endpoint)
	if err := os.WriteFile(path, []byte(enabled), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.lastCheckNano.Store(0)
	runtime.recordRPC("client", "/payment.v1.Payment/Pay", codes.OK, time.Millisecond, 0, 0)

	record := onlyOTLPLogRecord(t, waitForOTLPRequest(t, requests))
	if got := otlpLogAttributes(record)["version"].GetStringValue(); got != "new" {
		t.Fatalf("reloaded tag = %q, want new", got)
	}
}

func TestParseLoggingConfigRejectsUnsupportedValues(t *testing.T) {
	for name, config := range map[string]string{
		"provider": `{"telemetry":{"logging":[{"providers":["stdout"],"endpoint":"collector:4317"}]}}`,
		"mode":     `{"telemetry":{"logging":[{"providers":["otel"],"mode":"INBOUND","endpoint":"collector:4317"}]}}`,
		"filter":   `{"telemetry":{"logging":[{"providers":["otel"],"filterExpression":"request.path.startsWith('/healthz')","endpoint":"collector:4317"}]}}`,
		"tag":      `{"telemetry":{"logging":[{"providers":["otel"],"tags":{"service":"override"},"endpoint":"collector:4317"}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRuntimeConfig([]byte(config)); err == nil {
				t.Fatalf("parseRuntimeConfig(%s) error = nil", name)
			}
		})
	}
}

func TestParseLoggingConfigDefaultsToBothReporterSides(t *testing.T) {
	_, config, err := parseRuntimeConfig([]byte(`{
		"telemetry":{"logging":[{"providers":["otel"],"endpoint":"collector:4317"}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.rules) != 1 || !config.rules[0].client || !config.rules[0].server {
		t.Fatalf("logging default = %#v, want both client and server", config)
	}
}

type recordingLogsService struct {
	collectorlogsv1.UnimplementedLogsServiceServer
	requests chan *collectorlogsv1.ExportLogsServiceRequest
}

func (s *recordingLogsService) Export(_ context.Context, request *collectorlogsv1.ExportLogsServiceRequest) (*collectorlogsv1.ExportLogsServiceResponse, error) {
	select {
	case s.requests <- request:
	default:
	}
	return &collectorlogsv1.ExportLogsServiceResponse{}, nil
}

func startOTLPLogsServer(t *testing.T) (string, <-chan *collectorlogsv1.ExportLogsServiceRequest) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service := &recordingLogsService{requests: make(chan *collectorlogsv1.ExportLogsServiceRequest, 16)}
	server := grpc.NewServer()
	collectorlogsv1.RegisterLogsServiceServer(server, service)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	return listener.Addr().String(), service.requests
}

func waitForOTLPRequest(t *testing.T, requests <-chan *collectorlogsv1.ExportLogsServiceRequest) *collectorlogsv1.ExportLogsServiceRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OTLP access log")
		return nil
	}
}

func onlyOTLPLogRecord(t *testing.T, request *collectorlogsv1.ExportLogsServiceRequest) *logsv1.LogRecord {
	t.Helper()
	if request == nil || len(request.ResourceLogs) != 1 || len(request.ResourceLogs[0].ScopeLogs) != 1 || len(request.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("unexpected OTLP request: %#v", request)
	}
	return request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
}

func otlpLogAttributes(record *logsv1.LogRecord) map[string]*commonv1.AnyValue {
	attributes := make(map[string]*commonv1.AnyValue, len(record.Attributes))
	for _, attribute := range record.Attributes {
		attributes[attribute.Key] = attribute.Value
	}
	return attributes
}

func TestCompileAccessLogFilterDocumentsSupportedSubset(t *testing.T) {
	filter, err := compileAccessLogFilter(`status == "Unavailable" || response.code >= 500 && reporter == 'server'`)
	if err != nil {
		t.Fatal(err)
	}
	if !filter.matches(accessLogRecord{reporter: "server", status: codes.Internal}) {
		t.Fatal("supported filter did not match internal server response")
	}
	if filter.matches(accessLogRecord{reporter: "client", status: codes.OK}) {
		t.Fatal("supported filter unexpectedly matched successful client response")
	}
	_, err = compileAccessLogFilter(`!has(response.code) || response.code >= 500`)
	if err == nil || !strings.Contains(err.Error(), "unsupported logging filter") {
		t.Fatalf("unsupported CEL filter error = %v", err)
	}
}
