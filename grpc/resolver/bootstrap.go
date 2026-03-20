package resolver

import (
	"encoding/json"
	"fmt"
	"os"

	corev1 "github.com/kdubbo/xds-api/core/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// BootstrapConfig holds parsed xDS bootstrap configuration.
type BootstrapConfig struct {
	ServerURI string
	Node      *corev1.Node
	// CertProviders maps provider instance name to file-watcher cert config.
	// Key matches the instance_name in UpstreamTlsContext certificate_provider_instance.
	CertProviders map[string]FileWatcherCertConfig
}

// FileWatcherCertConfig holds the resolved file paths for a certificate provider.
type FileWatcherCertConfig struct {
	CertificateFile   string `json:"certificate_file"`
	PrivateKeyFile    string `json:"private_key_file"`
	CACertificateFile string `json:"ca_certificate_file"`
}

// ParseBootstrap reads and parses the xDS bootstrap JSON file.
func ParseBootstrap(path string) (*BootstrapConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap file %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap JSON: %w", err)
	}

	cfg := &BootstrapConfig{
		CertProviders: make(map[string]FileWatcherCertConfig),
	}

	// Parse xds_servers[0].server_uri
	if serversRaw, ok := raw["xds_servers"]; ok {
		var servers []map[string]json.RawMessage
		if err := json.Unmarshal(serversRaw, &servers); err == nil && len(servers) > 0 {
			if uriRaw, ok := servers[0]["server_uri"]; ok {
				var uri string
				if err := json.Unmarshal(uriRaw, &uri); err == nil {
					cfg.ServerURI = uri
				}
			}
		}
	}
	if cfg.ServerURI == "" {
		return nil, fmt.Errorf("no xds_servers[0].server_uri found in bootstrap")
	}

	// Parse node using protojson (Node contains protobuf Struct for metadata)
	if nodeRaw, ok := raw["node"]; ok {
		node := &corev1.Node{}
		if err := protojson.Unmarshal(nodeRaw, node); err == nil {
			cfg.Node = node
		}
	}

	// Parse certificate_providers — each entry has plugin_name and config.
	// We support the "file_watcher" plugin which carries cert/key/ca file paths.
	if providersRaw, ok := raw["certificate_providers"]; ok {
		var providers map[string]struct {
			PluginName string          `json:"plugin_name"`
			Config     json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(providersRaw, &providers); err == nil {
			for name, p := range providers {
				if p.PluginName == "file_watcher" && p.Config != nil {
					var fwCfg FileWatcherCertConfig
					if err := json.Unmarshal(p.Config, &fwCfg); err == nil {
						cfg.CertProviders[name] = fwCfg
					}
				}
			}
		}
	}

	return cfg, nil
}
