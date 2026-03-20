package credentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"

	tlsv1 "github.com/kdubbo/xds-api/extensions/transport_sockets/tls/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
)

// TLSContextKey is the BalancerAttributes key used by the xDS resolver to
// attach an UpstreamTlsContext to a resolved address.  The xdsDialCreds
// reads this key during ClientHandshake to decide whether to use TLS.
type TLSContextKey struct{}

// xdsDialCreds is a credentials.TransportCredentials that switches
// dynamically between TLS and plaintext based on the UpstreamTlsContext
// stored in resolver.Address.BalancerAttributes by the xDS resolver.
//
// This matches the behaviour described in
// https://istio.io/latest/blog/2021/proxyless-grpc/#enabling-mtls :
// the control plane pushes TLS configuration via CDS; the client
// credentials implementation inspects it per-connection.
type xdsDialCreds struct {
	certFile      string
	keyFile       string
	caFile        string
	serverName    string
	// fromBootstrap instructs ClientHandshake to resolve cert paths from
	// the GRPC_XDS_BOOTSTRAP file rather than using fixed file paths.
	fromBootstrap bool
}

// NewXDSDialCredentials returns a credentials.TransportCredentials that:
//   - Uses mTLS when the resolved address carries an UpstreamTlsContext in
//     its Attributes (set by the xDS resolver when CDS reports DUBBO_MUTUAL).
//   - Falls back to plaintext when no TLS context is present.
//
// If certFile/keyFile/caFile are empty, the credentials will attempt to read
// cert paths from the GRPC_XDS_BOOTSTRAP file's certificate_providers section
// at handshake time, using the provider instance referenced by the
// UpstreamTlsContext. This is the correct behaviour for Dubbo proxyless mTLS
// where dubbod injects cert paths into the bootstrap file.
//
// serverName — optional TLS SNI override (empty = use address host from xDS).
func NewXDSDialCredentials(certFile, keyFile, caFile, serverName string) credentials.TransportCredentials {
	return &xdsDialCreds{
		certFile:   certFile,
		keyFile:    keyFile,
		caFile:     caFile,
		serverName: serverName,
	}
}

// NewXDSDialCredentialsFromBootstrap returns credentials that automatically
// resolve certificate file paths from the GRPC_XDS_BOOTSTRAP file.
// This is the recommended constructor for Dubbo proxyless mTLS: dubbod writes
// cert paths into bootstrap.certificate_providers["default"] and the
// xDS resolver references them via UpstreamTlsContext.certificate_provider_instance.
func NewXDSDialCredentialsFromBootstrap() credentials.TransportCredentials {
	return &xdsDialCreds{fromBootstrap: true}
}

func (c *xdsDialCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// gRPC transport layer puts addr.Attributes (NOT addr.BalancerAttributes)
	// into ClientHandshakeInfo — see internal/transport/http2_client.go:
	//   connectCtx = icredentials.NewClientHandshakeInfoContext(connectCtx,
	//       credentials.ClientHandshakeInfo{Attributes: addr.Attributes})
	// So the xDS resolver must store TLSContextKey in addr.Attributes.
	hi := credentials.ClientHandshakeInfoFromContext(ctx)
	var tlsCtx *tlsv1.UpstreamTlsContext
	if hi.Attributes != nil {
		if v := hi.Attributes.Value(TLSContextKey{}); v != nil {
			tlsCtx, _ = v.(*tlsv1.UpstreamTlsContext)
		}
	}

	if tlsCtx == nil {
		// No TLS context — use plaintext.
		return insecure.NewCredentials().ClientHandshake(ctx, authority, rawConn)
	}

	// Build TLS config from the cert files.
	tlsCfg, err := c.buildTLSConfig(authority, tlsCtx)
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("xdsDialCreds: build TLS config: %w", err)
	}

	conn := tls.Client(rawConn, tlsCfg)
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- conn.Handshake() }()
	select {
	case err := <-handshakeDone:
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("xdsDialCreds: TLS handshake: %w", err)
		}
	case <-ctx.Done():
		conn.Close()
		return nil, nil, ctx.Err()
	}
	return conn, credentials.TLSInfo{
		State:          conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}, nil
}

// certFilesForContext resolves cert/key/ca file paths either from the struct
// fields or (when fromBootstrap=true) from the GRPC_XDS_BOOTSTRAP file using
// the certificate_provider_instance referenced in tlsCtx.
func (c *xdsDialCreds) certFilesForContext(tlsCtx *tlsv1.UpstreamTlsContext) (certFile, keyFile, caFile string, err error) {
	if !c.fromBootstrap {
		return c.certFile, c.keyFile, c.caFile, nil
	}

	bootstrapPath := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if bootstrapPath == "" {
		return "", "", "", fmt.Errorf("GRPC_XDS_BOOTSTRAP not set; cannot resolve cert paths")
	}
	data, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return "", "", "", fmt.Errorf("read bootstrap: %w", err)
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
		return "", "", "", fmt.Errorf("parse bootstrap: %w", err)
	}

	// Determine the provider instance name from the TLS context.
	// Default to "default" if not specified.
	instanceName := "default"
	if tlsCtx != nil && tlsCtx.CommonTlsContext != nil &&
		tlsCtx.CommonTlsContext.TlsCertificateCertificateProviderInstance != nil {
		instanceName = tlsCtx.CommonTlsContext.TlsCertificateCertificateProviderInstance.InstanceName
	}

	provider, ok := bootstrap.CertProviders[instanceName]
	if !ok {
		// Fall back to "default" provider.
		provider, ok = bootstrap.CertProviders["default"]
		if !ok {
			return "", "", "", fmt.Errorf("no certificate_providers[%q] in bootstrap", instanceName)
		}
	}

	certFile = provider.Config.CertificateFile
	keyFile = provider.Config.PrivateKeyFile

	// For the CA, use the ROOTCA provider instance if referenced, else same provider.
	caInstanceName := "default"
	if tlsCtx != nil && tlsCtx.CommonTlsContext != nil {
		if vc := tlsCtx.CommonTlsContext.GetCombinedValidationContext(); vc != nil &&
			vc.ValidationContextCertificateProviderInstance != nil {
			caInstanceName = vc.ValidationContextCertificateProviderInstance.InstanceName
		}
	}
	caProvider, ok := bootstrap.CertProviders[caInstanceName]
	if !ok {
		caProvider = provider
	}
	caFile = caProvider.Config.CACertificateFile

	return certFile, keyFile, caFile, nil
}

func (c *xdsDialCreds) buildTLSConfig(authority string, tlsCtx *tlsv1.UpstreamTlsContext) (*tls.Config, error) {
	certFile, keyFile, caFile, err := c.certFilesForContext(tlsCtx)
	if err != nil {
		return nil, err
	}

	// Load CA pool for server verification.
	var caPool *x509.CertPool
	if caFile != "" {
		pem, err := readFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			// CA file is transiently empty during cert rotation by dubbod.
			// Fall back to the system root pool rather than failing the
			// entire handshake; the file will be populated shortly.
			var sysErr error
			pool, sysErr = x509.SystemCertPool()
			if sysErr != nil {
				pool = x509.NewCertPool()
			}
		}
		caPool = pool
	} else {
		// Use system roots when no explicit CA is provided.
		pool, sysErr := x509.SystemCertPool()
		if sysErr != nil {
			pool = x509.NewCertPool()
		}
		caPool = pool
	}

	cfg := &tls.Config{
		// Proxyless mTLS uses SPIFFE URI SANs, not DNS SANs.
		// Standard Go TLS hostname verification would fail because the
		// server cert has spiffe://... URIs, not a DNS SAN matching the
		// service hostname.  We disable hostname verification and perform
		// CA-chain validation manually in VerifyPeerCertificate instead.
		InsecureSkipVerify: true, //nolint:gosec // intentional; VerifyPeerCertificate enforces CA chain
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("xdsDialCreds: server presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("xdsDialCreds: parse server cert: %w", err)
			}
			intermediates := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if ic, err := x509.ParseCertificate(raw); err == nil {
					intermediates.AddCert(ic)
				}
			}
			_, err = leaf.Verify(x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: intermediates,
				// CurrentTime zero value means use time.Now().
				// DNSName intentionally left empty — SPIFFE identity is in
				// the URI SAN, not the DNS SAN.
			})
			if err != nil {
				return fmt.Errorf("xdsDialCreds: verify server cert chain: %w", err)
			}
			return nil
		},
	}

	// Set SNI so the server can select the right certificate.
	// Priority: explicit override > SNI from xDS UpstreamTlsContext > authority host.
	switch {
	case c.serverName != "":
		cfg.ServerName = c.serverName
	case tlsCtx != nil && tlsCtx.Sni != "":
		cfg.ServerName = tlsCtx.Sni
	default:
		host, _, err := net.SplitHostPort(authority)
		if err != nil {
			host = authority
		}
		cfg.ServerName = host
	}

	// Load client certificate (mTLS).
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

func (c *xdsDialCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("xdsDialCreds: ServerHandshake not supported")
}

func (c *xdsDialCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c *xdsDialCreds) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

func (c *xdsDialCreds) OverrideServerName(name string) error {
	c.serverName = name
	return nil
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// AddressWithTLS copies addr and attaches tlsCtx into BalancerAttributes
// under TLSContextKey.  Call this from the xDS resolver when CDS reports a
// TransportSocket so the xdsDialCreds can read it during ClientHandshake.
func AddressWithTLS(addr resolver.Address, tlsCtx *tlsv1.UpstreamTlsContext) resolver.Address {
	addr.BalancerAttributes = addr.BalancerAttributes.WithValue(TLSContextKey{}, tlsCtx)
	return addr
}

