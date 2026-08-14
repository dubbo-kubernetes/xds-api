package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

const RuntimeConfigEnv = "DUBBO_GRPC_XDS_CONFIG"

type metricConfig struct {
	enabled              bool
	client               bool
	server               bool
	removeResponseStatus bool
}

type runtimeConfig struct {
	Telemetry *struct {
		Metrics *struct {
			Enabled   bool     `json:"enabled"`
			Providers []string `json:"providers"`
			Rules     []struct {
				Metric string `json:"metric"`
				Scope  string `json:"scope"`
				Tags   map[string]struct {
					Action string `json:"action"`
				} `json:"tags"`
			} `json:"rules"`
		} `json:"metrics"`
	} `json:"telemetry"`
}

type metricKey struct {
	reporter string
	method   string
	status   codes.Code
}

type Runtime struct {
	path string

	config atomic.Pointer[metricConfig]

	reloadMu      sync.Mutex
	lastCheckNano atomic.Int64
	modTimeNano   int64
	fileSize      int64

	metricsMu sync.RWMutex
	requests  map[metricKey]uint64
}

func NewRuntime(path string) *Runtime {
	runtime := &Runtime{path: path, requests: make(map[metricKey]uint64)}
	runtime.config.Store(&metricConfig{})
	_ = runtime.Reload()
	return runtime
}

var defaultRuntime = sync.OnceValue(func() *Runtime {
	return NewRuntime(os.Getenv(RuntimeConfigEnv))
})

func Default() *Runtime {
	return defaultRuntime()
}

func (r *Runtime) Reload() error {
	if strings.TrimSpace(r.path) == "" {
		r.config.Store(&metricConfig{})
		return nil
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return fmt.Errorf("stat runtime config: %w", err)
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("read runtime config: %w", err)
	}
	config, err := parseMetricConfig(data)
	if err != nil {
		return err
	}
	r.reloadMu.Lock()
	r.modTimeNano = info.ModTime().UnixNano()
	r.fileSize = info.Size()
	r.reloadMu.Unlock()
	r.config.Store(&config)
	return nil
}

func parseMetricConfig(data []byte) (metricConfig, error) {
	var raw runtimeConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return metricConfig{}, fmt.Errorf("parse runtime telemetry: %w", err)
	}
	if raw.Telemetry == nil || raw.Telemetry.Metrics == nil || !raw.Telemetry.Metrics.Enabled {
		return metricConfig{}, nil
	}
	metrics := raw.Telemetry.Metrics
	hasPrometheus := false
	for _, provider := range metrics.Providers {
		switch provider {
		case "prometheus":
			hasPrometheus = true
		case "":
		default:
			return metricConfig{}, fmt.Errorf("unsupported metrics provider %q", provider)
		}
	}
	if !hasPrometheus {
		return metricConfig{}, nil
	}

	result := metricConfig{enabled: true}
	if len(metrics.Rules) == 0 {
		result.client = true
		result.server = true
		return result, nil
	}
	for _, rule := range metrics.Rules {
		if rule.Metric != "REQUEST_COUNT" {
			return metricConfig{}, fmt.Errorf("unsupported metric %q", rule.Metric)
		}
		switch rule.Scope {
		case "CLIENT":
			result.client = true
		case "SERVER":
			result.server = true
		case "CLIENT_AND_SERVER":
			result.client = true
			result.server = true
		default:
			return metricConfig{}, fmt.Errorf("unsupported REQUEST_COUNT scope %q", rule.Scope)
		}
		for name, override := range rule.Tags {
			if override.Action != "REMOVE" {
				return metricConfig{}, fmt.Errorf("unsupported tag action %q", override.Action)
			}
			if name == "grpc_response_status" {
				result.removeResponseStatus = true
			}
		}
	}
	return result, nil
}

func (r *Runtime) RecordClient(method string, err error) {
	r.record("client", method, status.Code(err))
}

func (r *Runtime) recordServer(method string, err error) {
	r.record("server", method, status.Code(err))
}

func (r *Runtime) record(reporter, method string, code codes.Code) {
	r.reloadIfChanged()
	config := r.config.Load()
	if config == nil || !config.enabled ||
		(reporter == "client" && !config.client) ||
		(reporter == "server" && !config.server) {
		return
	}
	key := metricKey{reporter: reporter, method: method, status: code}
	r.metricsMu.Lock()
	r.requests[key]++
	r.metricsMu.Unlock()
}

func (r *Runtime) reloadIfChanged() {
	if r.path == "" {
		return
	}
	now := time.Now().UnixNano()
	last := r.lastCheckNano.Load()
	if now-last < int64(time.Second) || !r.lastCheckNano.CompareAndSwap(last, now) {
		return
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return
	}
	r.reloadMu.Lock()
	changed := info.ModTime().UnixNano() != r.modTimeNano || info.Size() != r.fileSize
	r.reloadMu.Unlock()
	if changed {
		_ = r.Reload()
	}
}

func (r *Runtime) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := r.WritePrometheus(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func (r *Runtime) WritePrometheus(w io.Writer) error {
	config := r.config.Load()
	if config == nil || !config.enabled {
		return nil
	}
	if _, err := io.WriteString(w, "# HELP dubbo_inherent_requests_total Total completed Inherent gRPC requests.\n# TYPE dubbo_inherent_requests_total counter\n"); err != nil {
		return err
	}

	r.metricsMu.RLock()
	snapshot := make(map[metricKey]uint64, len(r.requests))
	for key, count := range r.requests {
		if key.reporter == "client" && !config.client ||
			key.reporter == "server" && !config.server {
			continue
		}
		if config.removeResponseStatus {
			key.status = codes.OK
		}
		snapshot[key] += count
	}
	r.metricsMu.RUnlock()

	keys := make([]metricKey, 0, len(snapshot))
	for key := range snapshot {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].reporter != keys[j].reporter {
			return keys[i].reporter < keys[j].reporter
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].status < keys[j].status
	})
	for _, key := range keys {
		if config.removeResponseStatus {
			if _, err := fmt.Fprintf(w, "dubbo_inherent_requests_total{reporter=%q,grpc_method=%q} %d\n",
				key.reporter, key.method, snapshot[key]); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "dubbo_inherent_requests_total{reporter=%q,grpc_method=%q,grpc_response_status=%q} %d\n",
			key.reporter, key.method, key.status.String(), snapshot[key]); err != nil {
			return err
		}
	}
	return nil
}

type rpcMethodKey struct{}

type rpcStatsHandler struct {
	runtime  *Runtime
	reporter string
}

func (r *Runtime) ServerStatsHandler() stats.Handler {
	return &rpcStatsHandler{runtime: r, reporter: "server"}
}

func (r *Runtime) ServerOption() grpc.ServerOption {
	return grpc.StatsHandler(r.ServerStatsHandler())
}

func (r *Runtime) ClientStatsHandler() stats.Handler {
	return &rpcStatsHandler{runtime: r, reporter: "client"}
}

func (r *Runtime) ClientDialOption() grpc.DialOption {
	return grpc.WithStatsHandler(r.ClientStatsHandler())
}

func (h *rpcStatsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, rpcMethodKey{}, info.FullMethodName)
}

func (*rpcStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (*rpcStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

func (h *rpcStatsHandler) HandleRPC(ctx context.Context, event stats.RPCStats) {
	end, ok := event.(*stats.End)
	if !ok {
		return
	}
	method, _ := ctx.Value(rpcMethodKey{}).(string)
	if h.reporter == "client" {
		h.runtime.RecordClient(method, end.Error)
		return
	}
	h.runtime.recordServer(method, end.Error)
}
