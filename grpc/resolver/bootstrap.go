package resolver

import (
	"encoding/json"
	"fmt"
	"os"
)

// BootstrapConfig holds parsed xDS bootstrap configuration.
type BootstrapConfig struct {
	ServerURI string
}

// ParseBootstrap reads and parses the xDS bootstrap JSON file.
func ParseBootstrap(path string) (*BootstrapConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap file %s: %w", path, err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap JSON: %w", err)
	}
	cfg := &BootstrapConfig{}
	if servers, ok := raw["xds_servers"].([]interface{}); ok && len(servers) > 0 {
		if s, ok := servers[0].(map[string]interface{}); ok {
			if uri, ok := s["server_uri"].(string); ok {
				cfg.ServerURI = uri
			}
		}
	}
	if cfg.ServerURI == "" {
		return nil, fmt.Errorf("no xds_servers[0].server_uri found in bootstrap")
	}
	return cfg, nil
}


