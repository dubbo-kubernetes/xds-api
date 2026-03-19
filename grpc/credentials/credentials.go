// Package credentials provides TLS transport credentials for gRPC backed by
// file-based certificate watching, aligned with grpc-go/credentials/tls.
package credentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// certWatcher watches certificate files and reloads them on change.
type certWatcher struct {
	mu          sync.RWMutex
	certFile    string
	keyFile     string
	caFile      string
	tlsCert     *tls.Certificate
	caPool      *x509.CertPool
	stopCh      chan struct{}
	stopped     bool
}

func newCertWatcher(certFile, keyFile, caFile string) (*certWatcher, error) {
	cw := &certWatcher{
		certFile: certFile,
		keyFile:  keyFile,
		caFile:   caFile,
		stopCh:   make(chan struct{}),
	}
	if err := cw.reload(); err != nil {
		return nil, err
	}
	go cw.watch()
	return cw, nil
}

func (cw *certWatcher) reload() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.certFile != "" && cw.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(cw.certFile, cw.keyFile)
		if err != nil {
			return fmt.Errorf("credentials: load key pair: %w", err)
		}
		cw.tlsCert = &cert
	}

	if cw.caFile != "" {
		pem, err := os.ReadFile(cw.caFile)
		if err != nil {
			return fmt.Errorf("credentials: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("credentials: no valid CA certificate in %s", cw.caFile)
		}
		cw.caPool = pool
	}
	return nil
}

func (cw *certWatcher) watch() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-cw.stopCh:
			return
		case <-ticker.C:
			_ = cw.reload()
		}
	}
}

func (cw *certWatcher) stop() {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if !cw.stopped {
		close(cw.stopCh)
		cw.stopped = true
	}
}

func (cw *certWatcher) getCert() *tls.Certificate {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.tlsCert
}

func (cw *certWatcher) getCAPool() *x509.CertPool {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.caPool
}

// ClientOptions configures client-side TLS credentials.
type ClientOptions struct {
	// CertFile and KeyFile are the client certificate and key for mTLS.
	// Leave empty for server-only TLS verification.
	CertFile string
	KeyFile  string
	// CAFile is the CA certificate used to verify the server's certificate.
	// Leave empty to use the system root CA pool.
	CAFile string
	// ServerName overrides the server name used for TLS SNI and verification.
	ServerName string
	// FallbackCreds are used when no certificate files are configured.
	FallbackCreds credentials.TransportCredentials
}

// NewClientCredentials returns client-side TLS transport credentials backed by
// file-based certificate watching.
func NewClientCredentials(opts ClientOptions) (credentials.TransportCredentials, error) {
	if opts.CertFile == "" && opts.CAFile == "" {
		if opts.FallbackCreds != nil {
			return opts.FallbackCreds, nil
		}
		return nil, errors.New("credentials: at least one of CertFile/CAFile or FallbackCreds must be set")
	}
	cw, err := newCertWatcher(opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return nil, err
	}
	return &tlsCreds{
		watcher:    cw,
		serverName: opts.ServerName,
		isClient:   true,
	}, nil
}

// ServerOptions configures server-side TLS credentials.
type ServerOptions struct {
	// CertFile and KeyFile are the server certificate and key.
	CertFile string
	KeyFile  string
	// CAFile is the CA certificate used to verify client certificates (mTLS).
	// Leave empty to skip client certificate verification.
	CAFile string
	// FallbackCreds are used when certificate files are not yet available.
	FallbackCreds credentials.TransportCredentials
}

// NewServerCredentials returns server-side TLS transport credentials backed by
// file-based certificate watching.
func NewServerCredentials(opts ServerOptions) (credentials.TransportCredentials, error) {
	if opts.CertFile == "" && opts.KeyFile == "" {
		if opts.FallbackCreds != nil {
			return opts.FallbackCreds, nil
		}
		return nil, errors.New("credentials: CertFile and KeyFile must be set or FallbackCreds provided")
	}
	cw, err := newCertWatcher(opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return nil, err
	}
	return &tlsCreds{
		watcher:  cw,
		isClient: false,
	}, nil
}

// tlsCreds implements credentials.TransportCredentials using a certWatcher.
type tlsCreds struct {
	watcher    *certWatcher
	serverName string
	isClient   bool
}

func (c *tlsCreds) buildClientTLSConfig() *tls.Config {
	cfg := &tls.Config{
		ServerName: c.serverName,
		RootCAs:    c.watcher.getCAPool(),
	}
	if cert := c.watcher.getCert(); cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

func (c *tlsCreds) buildServerTLSConfig() *tls.Config {
	cfg := &tls.Config{}
	if cert := c.watcher.getCert(); cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if pool := c.watcher.getCAPool(); pool != nil {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg
}

func (c *tlsCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if !c.isClient {
		return nil, nil, errors.New("credentials: ClientHandshake called on server credentials")
	}
	cfg := c.buildClientTLSConfig()
	if cfg.ServerName == "" {
		// Use authority (host part) as ServerName when not explicitly set
		host, _, err := net.SplitHostPort(authority)
		if err != nil {
			host = authority
		}
		cfg.ServerName = host
	}
	conn := tls.Client(rawConn, cfg)
	errCh := make(chan error, 1)
	go func() {
		errCh <- conn.Handshake()
	}()
	select {
	case err := <-errCh:
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
	case <-ctx.Done():
		conn.Close()
		return nil, nil, ctx.Err()
	}
	return conn, credentials.TLSInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}, nil
}

func (c *tlsCreds) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.isClient {
		return nil, nil, errors.New("credentials: ServerHandshake called on client credentials")
	}
	cfg := c.buildServerTLSConfig()
	conn := tls.Server(rawConn, cfg)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, credentials.TLSInfo{
		State: conn.ConnectionState(),
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	}, nil
}

func (c *tlsCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (c *tlsCreds) Clone() credentials.TransportCredentials {
	return &tlsCreds{
		watcher:    c.watcher,
		serverName: c.serverName,
		isClient:   c.isClient,
	}
}

func (c *tlsCreds) OverrideServerName(name string) error {
	c.serverName = name
	return nil
}

// Close stops the underlying certificate watcher.
func (c *tlsCreds) Close() {
	c.watcher.stop()
}





