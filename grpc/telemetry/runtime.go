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
	enabled bool
	metrics map[string]metricReporterConfig
}

type metricReporterConfig struct {
	client metricSideConfig
	server metricSideConfig
}

type metricSideConfig struct {
	enabled       bool
	removedLabels map[string]struct{}
}

type runtimeConfig struct {
	Telemetry *runtimeTelemetryConfig `json:"telemetry"`
}

type runtimeTelemetryConfig struct {
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
	Logging []runtimeLoggingConfig `json:"logging"`
}

// runtimeLoggingConfig is the per-workload form written by dubbod into the
// projected Secret. It intentionally uses strings and maps instead of the API
// protobuf types so native applications only need this module at runtime.
type runtimeLoggingConfig struct {
	Providers        []string          `json:"providers"`
	Disabled         bool              `json:"disabled"`
	Mode             string            `json:"mode"`
	FilterExpression string            `json:"filterExpression"`
	Tags             map[string]string `json:"tags"`
	Endpoint         string            `json:"endpoint"`
}

type metricKey struct {
	reporter string
	service  string
	method   string
	status   codes.Code
}

type metricValue struct {
	requests        uint64
	requestDuration histogram
	requestSize     histogram
	responseSize    histogram
}

type Runtime struct {
	path string

	config  atomic.Pointer[metricConfig]
	logging atomic.Pointer[loggingConfig]

	reloadMu      sync.Mutex
	lastCheckNano atomic.Int64
	modTimeNano   int64
	fileSize      int64

	metricsMu sync.RWMutex
	values    map[metricKey]metricValue

	accessLogQueue       chan accessLogRecord
	accessLogStop        chan struct{}
	accessLogDone        chan struct{}
	accessLogStart       sync.Once
	accessLogStopOnce    sync.Once
	accessLogStarted     atomic.Bool
	accessLogClosed      atomic.Bool
	accessLogExportersMu sync.Mutex
	accessLogExporters   map[string]*otlpLogExporter
	accessLogDropped     atomic.Uint64
	accessLogFailed      atomic.Uint64
}

func NewRuntime(path string) *Runtime {
	runtime := &Runtime{
		path:               path,
		values:             make(map[metricKey]metricValue),
		accessLogQueue:     make(chan accessLogRecord, defaultAccessLogQueueSize),
		accessLogStop:      make(chan struct{}),
		accessLogDone:      make(chan struct{}),
		accessLogExporters: make(map[string]*otlpLogExporter),
	}
	runtime.config.Store(&metricConfig{})
	runtime.logging.Store(&loggingConfig{})
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
		r.logging.Store(&loggingConfig{})
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
	metrics, logging, err := parseRuntimeConfig(data)
	if err != nil {
		return err
	}
	r.reloadMu.Lock()
	r.modTimeNano = info.ModTime().UnixNano()
	r.fileSize = info.Size()
	r.reloadMu.Unlock()
	r.config.Store(&metrics)
	r.logging.Store(&logging)
	return nil
}

func parseMetricConfig(data []byte) (metricConfig, error) {
	var raw runtimeConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return metricConfig{}, fmt.Errorf("parse runtime telemetry: %w", err)
	}
	return parseMetricConfigFromRuntime(raw)
}

func parseRuntimeConfig(data []byte) (metricConfig, loggingConfig, error) {
	var raw runtimeConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return metricConfig{}, loggingConfig{}, fmt.Errorf("parse runtime telemetry: %w", err)
	}
	metrics, err := parseMetricConfigFromRuntime(raw)
	if err != nil {
		return metricConfig{}, loggingConfig{}, err
	}
	logging, err := parseLoggingConfig(raw.Telemetry)
	if err != nil {
		return metricConfig{}, loggingConfig{}, err
	}
	return metrics, logging, nil
}

func parseMetricConfigFromRuntime(raw runtimeConfig) (metricConfig, error) {
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

	result := metricConfig{
		enabled: true,
		metrics: make(map[string]metricReporterConfig, len(standardMetricDefinitions)),
	}
	for _, definition := range standardMetricDefinitions {
		result.metrics[definition.Name] = metricReporterConfig{
			client: metricSideConfig{enabled: true},
			server: metricSideConfig{enabled: true},
		}
	}
	if len(metrics.Rules) == 0 {
		return result, nil
	}
	configured := make(map[string]struct{}, len(metrics.Rules))
	for _, rule := range metrics.Rules {
		if _, found := standardMetricByName[rule.Metric]; !found {
			return metricConfig{}, fmt.Errorf("unsupported metric %q", rule.Metric)
		}
		reporters := result.metrics[rule.Metric]
		if _, found := configured[rule.Metric]; !found {
			reporters = metricReporterConfig{}
			configured[rule.Metric] = struct{}{}
		}
		removedLabels := make(map[string]struct{}, len(rule.Tags))
		for name, override := range rule.Tags {
			if _, found := standardLabelNames[name]; !found {
				return metricConfig{}, fmt.Errorf("unsupported standard label %q", name)
			}
			if override.Action != "REMOVE" {
				return metricConfig{}, fmt.Errorf("unsupported tag action %q", override.Action)
			}
			removedLabels[name] = struct{}{}
		}
		side := metricSideConfig{enabled: true, removedLabels: removedLabels}
		switch rule.Scope {
		case "CLIENT":
			reporters.client = side
		case "SERVER":
			reporters.server = side
		case "CLIENT_AND_SERVER":
			reporters.client = side
			reporters.server = side
		default:
			return metricConfig{}, fmt.Errorf("unsupported %s scope %q", rule.Metric, rule.Scope)
		}
		result.metrics[rule.Metric] = reporters
	}
	return result, nil
}

func (r *Runtime) RecordClient(method string, err error) {
	r.recordCount("client", method, status.Code(err))
}

func (r *Runtime) recordServer(method string, err error) {
	r.recordCount("server", method, status.Code(err))
}

func (r *Runtime) recordCount(reporter, fullMethod string, code codes.Code) {
	r.reloadIfChanged()
	config := r.config.Load()
	if !metricEnabled(config, RequestCountMetric, reporter) {
		return
	}
	service, method := splitMethod(fullMethod)
	key := metricKey{reporter: reporter, service: service, method: method, status: code}
	r.metricsMu.Lock()
	value := r.values[key]
	value.requests++
	r.values[key] = value
	r.metricsMu.Unlock()
}

func (r *Runtime) recordRPC(reporter, fullMethod string, code codes.Code, duration time.Duration, requestSize, responseSize uint64) {
	r.reloadIfChanged()
	config := r.config.Load()
	service, method := splitMethod(fullMethod)
	if config != nil && config.enabled {
		key := metricKey{reporter: reporter, service: service, method: method, status: code}
		r.metricsMu.Lock()
		value := r.values[key]
		if metricEnabled(config, RequestCountMetric, reporter) {
			value.requests++
		}
		if metricEnabled(config, RequestDurationMetric, reporter) {
			value.requestDuration.observe(duration.Seconds(), durationBuckets)
		}
		if metricEnabled(config, RequestSizeMetric, reporter) {
			value.requestSize.observe(float64(requestSize), sizeBuckets)
		}
		if metricEnabled(config, ResponseSizeMetric, reporter) {
			value.responseSize.observe(float64(responseSize), sizeBuckets)
		}
		r.values[key] = value
		r.metricsMu.Unlock()
	}
	r.recordAccessLogs(r.logging.Load(), reporter, service, method, code, duration)
}

func metricEnabled(config *metricConfig, metric, reporter string) bool {
	if config == nil || !config.enabled {
		return false
	}
	reporters, found := config.metrics[metric]
	if !found {
		return false
	}
	if reporter == "client" {
		return reporters.client.enabled
	}
	return reporter == "server" && reporters.server.enabled
}

func metricSide(config *metricConfig, metric, reporter string) metricSideConfig {
	if config == nil || !config.enabled {
		return metricSideConfig{}
	}
	reporters := config.metrics[metric]
	if reporter == "client" {
		return reporters.client
	}
	return reporters.server
}

func splitMethod(fullMethod string) (string, string) {
	trimmed := strings.TrimPrefix(fullMethod, "/")
	service, method, found := strings.Cut(trimmed, "/")
	if !found {
		return "", trimmed
	}
	return service, method
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
	r.metricsMu.RLock()
	snapshot := make(map[metricKey]metricValue, len(r.values))
	for key, value := range r.values {
		value.requestDuration.buckets = append([]uint64(nil), value.requestDuration.buckets...)
		value.requestSize.buckets = append([]uint64(nil), value.requestSize.buckets...)
		value.responseSize.buckets = append([]uint64(nil), value.responseSize.buckets...)
		snapshot[key] = value
	}
	r.metricsMu.RUnlock()

	for _, definition := range standardMetricDefinitions {
		if err := writeMetric(w, config, definition, snapshot); err != nil {
			return err
		}
	}
	return nil
}

const (
	reporterLabelBit uint8 = 1 << iota
	serviceLabelBit
	methodLabelBit
	statusLabelBit
)

type exportKey struct {
	metricKey
	labelMask uint8
}

func writeMetric(w io.Writer, config *metricConfig, definition StandardMetricDefinition, values map[metricKey]metricValue) error {
	reporters := config.metrics[definition.Name]
	if !reporters.client.enabled && !reporters.server.enabled {
		return nil
	}
	prometheusType := "counter"
	if definition.Type == MetricTypeDistribution {
		prometheusType = "histogram"
	}
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n",
		definition.PrometheusName, definition.Help, definition.PrometheusName, prometheusType); err != nil {
		return err
	}
	if definition.Type == MetricTypeCounter {
		return writeCounter(w, config, definition, values)
	}
	return writeDistribution(w, config, definition, values)
}

func writeCounter(w io.Writer, config *metricConfig, definition StandardMetricDefinition, values map[metricKey]metricValue) error {
	snapshot := make(map[exportKey]uint64, len(values))
	for key, value := range values {
		side := metricSide(config, definition.Name, key.reporter)
		if !side.enabled || value.requests == 0 {
			continue
		}
		snapshot[makeExportKey(key, side.removedLabels)] += value.requests
	}
	for _, key := range sortedExportKeys(snapshot) {
		if _, err := fmt.Fprintf(w, "%s%s %d\n", definition.PrometheusName, formatLabels(key, ""), snapshot[key]); err != nil {
			return err
		}
	}
	return nil
}

func writeDistribution(w io.Writer, config *metricConfig, definition StandardMetricDefinition, values map[metricKey]metricValue) error {
	snapshot := make(map[exportKey]histogram, len(values))
	boundaries := sizeBuckets
	for key, value := range values {
		side := metricSide(config, definition.Name, key.reporter)
		if !side.enabled {
			continue
		}
		var source histogram
		switch definition.Name {
		case RequestDurationMetric:
			source = value.requestDuration
			boundaries = durationBuckets
		case RequestSizeMetric:
			source = value.requestSize
		case ResponseSizeMetric:
			source = value.responseSize
		}
		if source.count == 0 {
			continue
		}
		exported := makeExportKey(key, side.removedLabels)
		aggregate := snapshot[exported]
		aggregate.add(source)
		snapshot[exported] = aggregate
	}
	for _, key := range sortedExportKeys(snapshot) {
		value := snapshot[key]
		for i, boundary := range boundaries {
			if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", definition.PrometheusName,
				formatLabels(key, fmt.Sprintf("%g", boundary)), value.buckets[i]); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", definition.PrometheusName,
			formatLabels(key, "+Inf"), value.count); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %g\n", definition.PrometheusName, formatLabels(key, ""), value.sum); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_count%s %d\n", definition.PrometheusName, formatLabels(key, ""), value.count); err != nil {
			return err
		}
	}
	return nil
}

func makeExportKey(key metricKey, removed map[string]struct{}) exportKey {
	result := exportKey{
		metricKey: key,
		labelMask: reporterLabelBit | serviceLabelBit | methodLabelBit | statusLabelBit,
	}
	for label := range removed {
		switch label {
		case ReporterLabel:
			result.reporter = ""
			result.labelMask &^= reporterLabelBit
		case GRPCServiceLabel:
			result.service = ""
			result.labelMask &^= serviceLabelBit
		case GRPCMethodLabel:
			result.method = ""
			result.labelMask &^= methodLabelBit
		case GRPCResponseStatusLabel:
			result.status = codes.OK
			result.labelMask &^= statusLabelBit
		}
	}
	return result
}

func sortedExportKeys[T any](snapshot map[exportKey]T) []exportKey {
	keys := make([]exportKey, 0, len(snapshot))
	for key := range snapshot {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].labelMask != keys[j].labelMask {
			return keys[i].labelMask < keys[j].labelMask
		}
		if keys[i].reporter != keys[j].reporter {
			return keys[i].reporter < keys[j].reporter
		}
		if keys[i].service != keys[j].service {
			return keys[i].service < keys[j].service
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].status < keys[j].status
	})
	return keys
}

func formatLabels(key exportKey, bucket string) string {
	labels := make([]string, 0, len(standardLabels)+1)
	if key.labelMask&reporterLabelBit != 0 {
		labels = append(labels, fmt.Sprintf("%s=%q", ReporterLabel, key.reporter))
	}
	if key.labelMask&serviceLabelBit != 0 {
		labels = append(labels, fmt.Sprintf("%s=%q", GRPCServiceLabel, key.service))
	}
	if key.labelMask&methodLabelBit != 0 {
		labels = append(labels, fmt.Sprintf("%s=%q", GRPCMethodLabel, key.method))
	}
	if key.labelMask&statusLabelBit != 0 {
		labels = append(labels, fmt.Sprintf("%s=%q", GRPCResponseStatusLabel, key.status.String()))
	}
	if bucket != "" {
		labels = append(labels, fmt.Sprintf("le=%q", bucket))
	}
	if len(labels) == 0 {
		return ""
	}
	return "{" + strings.Join(labels, ",") + "}"
}

type rpcStateKey struct{}

type rpcState struct {
	mu           sync.Mutex
	method       string
	requestSize  uint64
	responseSize uint64
}

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
	return context.WithValue(ctx, rpcStateKey{}, &rpcState{method: info.FullMethodName})
}

// UsesNativeStats reports whether the RPC context already has the native
// telemetry stats handler. Balancer fallbacks use this to avoid double counts.
func UsesNativeStats(ctx context.Context) bool {
	_, found := ctx.Value(rpcStateKey{}).(*rpcState)
	return found
}

func (*rpcStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (*rpcStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

func (h *rpcStatsHandler) HandleRPC(ctx context.Context, event stats.RPCStats) {
	state, found := ctx.Value(rpcStateKey{}).(*rpcState)
	if !found {
		return
	}
	switch value := event.(type) {
	case *stats.InPayload:
		state.mu.Lock()
		if h.reporter == "client" {
			state.responseSize += uint64(value.Length)
		} else {
			state.requestSize += uint64(value.Length)
		}
		state.mu.Unlock()
	case *stats.OutPayload:
		state.mu.Lock()
		if h.reporter == "client" {
			state.requestSize += uint64(value.Length)
		} else {
			state.responseSize += uint64(value.Length)
		}
		state.mu.Unlock()
	case *stats.End:
		state.mu.Lock()
		method := state.method
		requestSize := state.requestSize
		responseSize := state.responseSize
		state.mu.Unlock()
		duration := value.EndTime.Sub(value.BeginTime)
		if duration < 0 {
			duration = 0
		}
		h.runtime.recordRPC(h.reporter, method, status.Code(value.Error), duration, requestSize, responseSize)
	default:
		return
	}
}
