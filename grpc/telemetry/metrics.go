package telemetry

// MetricType is the aggregation model of a standard metric.
type MetricType string

const (
	MetricTypeCounter      MetricType = "COUNTER"
	MetricTypeDistribution MetricType = "DISTRIBUTION"
)

const (
	RequestCountMetric    = "REQUEST_COUNT"
	RequestDurationMetric = "REQUEST_DURATION"
	RequestSizeMetric     = "REQUEST_SIZE"
	ResponseSizeMetric    = "RESPONSE_SIZE"

	ReporterLabel           = "reporter"
	GRPCServiceLabel        = "grpc_service"
	GRPCMethodLabel         = "grpc_method"
	GRPCResponseStatusLabel = "grpc_response_status"
)

var standardLabels = []string{
	ReporterLabel,
	GRPCServiceLabel,
	GRPCMethodLabel,
	GRPCResponseStatusLabel,
}

// StandardMetricDefinition describes one metric that every enabled Inherent
// runtime can produce without an external proxy.
type StandardMetricDefinition struct {
	Name           string
	PrometheusName string
	Help           string
	Type           MetricType
	Labels         []string
}

var standardMetricDefinitions = []StandardMetricDefinition{
	{
		Name:           RequestCountMetric,
		PrometheusName: "dubbo_inherent_requests_total",
		Help:           "Total completed Inherent gRPC requests.",
		Type:           MetricTypeCounter,
		Labels:         standardLabels,
	},
	{
		Name:           RequestDurationMetric,
		PrometheusName: "dubbo_inherent_request_duration_seconds",
		Help:           "Inherent gRPC request duration in seconds.",
		Type:           MetricTypeDistribution,
		Labels:         standardLabels,
	},
	{
		Name:           RequestSizeMetric,
		PrometheusName: "dubbo_inherent_request_size_bytes",
		Help:           "Total uncompressed request message bytes per Inherent gRPC request.",
		Type:           MetricTypeDistribution,
		Labels:         standardLabels,
	},
	{
		Name:           ResponseSizeMetric,
		PrometheusName: "dubbo_inherent_response_size_bytes",
		Help:           "Total uncompressed response message bytes per Inherent gRPC request.",
		Type:           MetricTypeDistribution,
		Labels:         standardLabels,
	},
}

var standardMetricByName = func() map[string]StandardMetricDefinition {
	result := make(map[string]StandardMetricDefinition, len(standardMetricDefinitions))
	for _, definition := range standardMetricDefinitions {
		result[definition.Name] = definition
	}
	return result
}()

var standardLabelNames = func() map[string]struct{} {
	result := make(map[string]struct{}, len(standardLabels))
	for _, name := range standardLabels {
		result[name] = struct{}{}
	}
	return result
}()

// StandardMetrics returns a copy of the stable metric contract.
func StandardMetrics() []StandardMetricDefinition {
	result := make([]StandardMetricDefinition, len(standardMetricDefinitions))
	for i, definition := range standardMetricDefinitions {
		result[i] = definition
		result[i].Labels = append([]string(nil), definition.Labels...)
	}
	return result
}

var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
var sizeBuckets = []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304}

type histogram struct {
	buckets []uint64
	count   uint64
	sum     float64
}

func (h *histogram) observe(value float64, boundaries []float64) {
	if h.buckets == nil {
		h.buckets = make([]uint64, len(boundaries))
	}
	for i, boundary := range boundaries {
		if value <= boundary {
			h.buckets[i]++
		}
	}
	h.count++
	h.sum += value
}

func (h *histogram) add(other histogram) {
	if len(other.buckets) > 0 && h.buckets == nil {
		h.buckets = make([]uint64, len(other.buckets))
	}
	for i, count := range other.buckets {
		h.buckets[i] += count
	}
	h.count += other.count
	h.sum += other.sum
}
