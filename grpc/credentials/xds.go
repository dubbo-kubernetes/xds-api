package credentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	tlsv1 "github.com/dubbo-kubernetes/xds-api/extensions/transport_sockets/tls/v1"
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
	certFile   string
	keyFile    string
	caFile     string
	serverName string
}

// NewXDSDialCredentials returns a credentials.TransportCredentials that:
//   - Uses mTLS (cert/key/ca files) when the resolved address carries an
//     UpstreamTlsContext in its BalancerAttributes (set by the xDS resolver
//     when CDS reports a TransportSocket with mTLS).
//   - Falls back to plaintext when no TLS context is present.
//
// certFile, keyFile — client certificate and private key for mTLS.
// caFile            — CA bundle used to verify the server certificate.
// serverName        — optional TLS SNI override (empty = use address host).
func NewXDSDialCredentials(certFile, keyFile, caFile, serverName string) credentials.TransportCredentials {
	return &xdsDialCreds{
		certFile:   certFile,
		keyFile:    keyFile,
		caFile:     caFile,
		serverName: serverName,
	}
}

func (c *xdsDialCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// xDS balancer passes the resolved Address via the context using the
	// standard gRPC mechanism: credentials.ClientHandshakeInfoFromContext.
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

func (c *xdsDialCreds) buildTLSConfig(authority string, _ *tlsv1.UpstreamTlsContext) (*tls.Config, error) {
	cfg := &tls.Config{}

	// Server name: explicit override > authority host.
	if c.serverName != "" {
		cfg.ServerName = c.serverName
	} else {
		host, _, err := net.SplitHostPort(authority)
		if err != nil {
			host = authority
		}
		cfg.ServerName = host
	}

	// Load client certificate (mTLS).
	if c.certFile != "" && c.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	// Load CA pool for server verification.
	if c.caFile != "" {
		pem, err := readFile(c.caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid CA certificate in %s", c.caFile)
		}
		cfg.RootCAs = pool
	} else {
		// Use system roots when no explicit CA is provided.
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		cfg.RootCAs = pool
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

