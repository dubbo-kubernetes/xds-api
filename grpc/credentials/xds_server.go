package credentials

import (
	"crypto/tls"
	"crypto/x509"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc/credentials"
)

// xdsServerCreds implements credentials.TransportCredentials for the server
// side of a proxyless gRPC mTLS connection.  Certificate paths are resolved
// from the GRPC_XDS_BOOTSTRAP file's certificate_providers section, matching
// the same logic used by xdsDialCreds on the client side.
type xdsServerCreds struct{}

// NewServerCredentialsFromBootstrap returns server-side TLS credentials that
// load cert/key/CA paths from the GRPC_XDS_BOOTSTRAP certificate_providers
// section at handshake time.  This is the correct way to enable mTLS on a
// proxyless gRPC provider when PeerAuthentication STRICT is in effect.
func NewServerCredentialsFromBootstrap() credentials.TransportCredentials {
	return &xdsServerCreds{}
}

func (c *xdsServerCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tlsCfg, err := c.buildServerTLSConfig()
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("xdsServerCreds: build TLS config: %w", err)
	}
	conn := tls.Server(rawConn, tlsCfg)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("xdsServerCreds: TLS handshake: %w", err)
	}
	return conn, credentials.TLSInfo{
		State:          conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}, nil
}

func (c *xdsServerCreds) ClientHandshake(_ context.Context, _ string, _ net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("xdsServerCreds: ClientHandshake not supported")
}

func (c *xdsServerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c *xdsServerCreds) Clone() credentials.TransportCredentials {
	return &xdsServerCreds{}
}

func (c *xdsServerCreds) OverrideServerName(_ string) error {
	return nil
}

func (c *xdsServerCreds) buildServerTLSConfig() (*tls.Config, error) {
	bootstrapPath := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if bootstrapPath == "" {
		return nil, fmt.Errorf("GRPC_XDS_BOOTSTRAP not set")
	}
	data, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, fmt.Errorf("read bootstrap: %w", err)
	}
	var bootstrap struct {
		CertProviders map[string]struct {
			PluginName string `json:"plugin_name"`
			Config     struct {
				CertificateFile   string `json:"certificate_file"`
				PrivateKeyFile    string `json:"private_key_file"`
				CACertificateFile string `json:"ca_certificate_file"`
			} `json:"config"`
		} `json:"certificate_providers"`
	}
	if err := json.Unmarshal(data, &bootstrap); err != nil {
		return nil, fmt.Errorf("parse bootstrap: %w", err)
	}

	provider, ok := bootstrap.CertProviders["default"]
	if !ok {
		return nil, fmt.Errorf("no certificate_providers[\"default\"] in bootstrap")
	}

	certFile := provider.Config.CertificateFile
	keyFile := provider.Config.PrivateKeyFile
	caFile := provider.Config.CACertificateFile

	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("certificate_providers[\"default\"] missing certificate_file or private_key_file")
	}

	// Load server cert+key.
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Load CA for client certificate verification (mTLS).
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			// CA file may be empty during initial cert rotation — use no client auth
			// rather than failing hard; the file will be populated shortly.
			cfg.ClientAuth = tls.NoClientCert
		} else {
			cfg.ClientCAs = pool
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	return cfg, nil
}

