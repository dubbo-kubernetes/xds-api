// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStartMetricsEndpointServesMetricsAndHealth(t *testing.T) {
	path := writeConfig(t, `{
		"telemetry":{"metrics":{
			"enabled":true,
			"providers":["prometheus"]
		}}
	}`)
	runtime := NewRuntime(path)
	runtime.RecordClient("/payment.v1.Payment/Pay", nil)

	endpoint, err := runtime.StartMetricsEndpoint("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = endpoint.Shutdown(ctx)
	})

	for _, test := range []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: "/healthz", wantStatus: http.StatusOK},
		{path: "/metrics", wantStatus: http.StatusOK, wantBody: "dubbo_inherent_requests_total"},
	} {
		response, err := http.Get("http://" + endpoint.Address() + test.path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != test.wantStatus {
			t.Fatalf("%s status = %d, want %d", test.path, response.StatusCode, test.wantStatus)
		}
		if !strings.Contains(string(body), test.wantBody) {
			t.Fatalf("%s body = %q, want substring %q", test.path, body, test.wantBody)
		}
	}
}
