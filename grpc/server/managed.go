package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	xdscreds "github.com/kdubbo/xds-api/grpc/credentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ManagedServer is a gRPC server whose transport credentials are managed
// automatically by the xDS control plane.  When the control plane pushes
// a PeerAuthentication STRICT policy the server transparently restarts in
// mTLS mode; when the policy is removed it restarts in plaintext mode.
//
// Applications register their service implementations exactly as with a
// plain *grpc.Server and call Serve() once.  All TLS lifecycle logic is
// handled inside this type — the application has zero awareness of mTLS.
//
// Typical usage:
//
//	srv := server.NewGRPCServer("0.0.0.0:17070", "", grpc.ChainUnaryInterceptor(...))
//	pb.RegisterMyServiceServer(srv, &myImpl{})
//	if err := srv.Serve(); err != nil { log.Fatal(err) }
type ManagedServer struct {
	addr         string
	boostrapPath string
	extraOpts    []grpc.ServerOption

	// registrations holds service registration callbacks collected before
	// Serve() is called.  Each callback receives a freshly-created *grpc.Server.
	registrations []func(*grpc.Server)
}

// NewGRPCServer returns a ManagedServer for the given listen address.
//
//   - addr          — TCP address to listen on, e.g. "0.0.0.0:17070".
//   - bootstrapPath — path to grpc-bootstrap.json; empty means read
//     GRPC_XDS_BOOTSTRAP from the environment.
//   - opts          — additional grpc.ServerOptions (interceptors, etc.).
//
// The returned server implements a superset of *grpc.Server's registration
// surface via RegisterService.  Call Serve() to start; it blocks until the
// process receives SIGINT/SIGTERM or the context passed to ServeContext is
// cancelled.
func NewGRPCServer(addr, bootstrapPath string, opts ...grpc.ServerOption) *ManagedServer {
	return &ManagedServer{
		addr:         addr,
		boostrapPath: bootstrapPath,
		extraOpts:    opts,
	}
}

// RegisterService registers a service and its implementation on the ManagedServer.
// It must be called before Serve.
func (m *ManagedServer) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	m.registrations = append(m.registrations, func(s *grpc.Server) {
		s.RegisterService(desc, impl)
	})
}

// RegisterHook registers an arbitrary callback that is invoked on each newly
// created *grpc.Server instance before it starts serving.  Use this for
// registrations that require a *grpc.Server reference directly, such as
// grpc/reflection.
func (m *ManagedServer) RegisterHook(fn func(*grpc.Server)) {
	m.registrations = append(m.registrations, fn)
}

// Serve starts the managed gRPC server and blocks until ctx is cancelled.
// It transparently restarts the underlying *grpc.Server whenever the xDS
// control plane changes the inbound TLS mode (e.g. PeerAuthentication STRICT
// is applied or removed).
func (m *ManagedServer) ServeContext(ctx context.Context) error {
	watcher := NewWatcher(m.addr, m.boostrapPath)
	watcher.Start()
	defer watcher.Close()

	// Wait up to 30 s for the initial xDS LDS push before starting the server.
	// If no push arrives we start in plaintext mode — the watcher will trigger
	// a restart as soon as the control plane responds.
	initCtx, initCancel := context.WithTimeout(ctx, 30*time.Second)
	initialCfg, err := watcher.WaitForInitial(initCtx)
	initCancel()
	if err != nil {
		log.Printf("[xds-managed-server] no initial xDS config (%v); starting plaintext", err)
	}

	currentMode := TLSModeUnknown
	if initialCfg != nil {
		currentMode = initialCfg.Mode
	}

	for {
		// stopCh signals the running server instance to shut down.
		stopCh := make(chan struct{})

		go m.runInstance(initialCfg, stopCh)

		// Block until the parent context is cancelled or a TLS mode change arrives.
		newCfg, shutdown := m.waitForModeChange(ctx, currentMode, watcher.UpdateCh())
		close(stopCh)

		if shutdown {
			log.Printf("[xds-managed-server] context cancelled, shutting down")
			return ctx.Err()
		}

		// Brief pause so the old listener releases the port before we rebind.
		time.Sleep(200 * time.Millisecond)

		currentMode = newCfg.Mode
		initialCfg = newCfg
	}
}

// Serve is a convenience wrapper around ServeContext that uses a background
// context, i.e. the server runs until the process exits.
func (m *ManagedServer) Serve() error {
	return m.ServeContext(context.Background())
}

// waitForModeChange blocks until either ctx is done (returns nil, true) or the
// update channel delivers a config whose TLS mode differs from currentMode
// (returns newCfg, false).  Same-mode updates are silently ignored.
func (m *ManagedServer) waitForModeChange(
	ctx context.Context,
	currentMode TLSMode,
	updateCh <-chan *InboundTLSConfig,
) (*InboundTLSConfig, bool) {
	for {
		select {
		case <-ctx.Done():
			return nil, true

		case newCfg, ok := <-updateCh:
			if !ok {
				return nil, true
			}
			if newCfg == nil {
				continue
			}
			if newCfg.Mode == currentMode {
				log.Printf("[xds-managed-server] xDS update: TLS mode unchanged (%v), no restart", currentMode)
				continue
			}
			log.Printf("[xds-managed-server] TLS mode changed %v → %v, restarting server", currentMode, newCfg.Mode)
			return newCfg, false
		}
	}
}

// runInstance creates a *grpc.Server with credentials matching tlsCfg,
// registers all services, and serves until stopCh is closed.
func (m *ManagedServer) runInstance(tlsCfg *InboundTLSConfig, stopCh <-chan struct{}) {
	var creds grpc.ServerOption
	if tlsCfg != nil && tlsCfg.Mode == TLSModeMTLS {
		log.Printf("[xds-managed-server] instance starting in mTLS mode")
		creds = grpc.Creds(xdscreds.NewServerCredentialsFromBootstrap())
	} else {
		log.Printf("[xds-managed-server] instance starting in plaintext mode")
		creds = grpc.Creds(insecure.NewCredentials())
	}

	opts := append([]grpc.ServerOption{creds}, m.extraOpts...)
	s := grpc.NewServer(opts...)

	for _, reg := range m.registrations {
		reg(s)
	}

	lis, err := net.Listen("tcp", m.addr)
	if err != nil {
		log.Printf("[xds-managed-server] listen %s: %v", m.addr, err)
		return
	}

	go func() {
		<-stopCh
		s.GracefulStop()
	}()

	if err := s.Serve(lis); err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("[xds-managed-server] serve error: %v", err)
		}
	}
}

// DialOptions returns the grpc.DialOption slice that must be passed to
// grpc.Dial / grpc.DialContext when connecting to an xds:/// target.
//
// It injects the xDS-aware transport credentials so the application does not
// need any TLS code.  mTLS is activated automatically when the control plane
// pushes a DUBBO_MUTUAL UpstreamTlsContext; plaintext is used otherwise.
//
// Usage:
//
//	conn, err := grpc.DialContext(ctx, "xds:///svc:7070",
//	    append(server.DialOptions(), grpc.WithBlock())...)
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(xdscreds.NewXDSDialCredentialsFromBootstrap()),
	}
}

// DialContext dials an xDS-managed gRPC endpoint and returns a *grpc.ClientConn.
// The target must use the xds:/// scheme (e.g. "xds:///svc.ns.svc.cluster.local:7070").
//
// mTLS is applied automatically when the control plane's CDS response carries
// a DUBBO_MUTUAL UpstreamTlsContext — the application passes no credentials.
func DialContext(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if !strings.HasPrefix(target, "xds:///") {
		return nil, fmt.Errorf("xds: DialContext target must use xds:/// scheme, got %q", target)
	}
	allOpts := append(DialOptions(), opts...)
	return grpc.DialContext(ctx, target, allOpts...)
}

// Dial is the non-context variant of DialContext.
func Dial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return DialContext(context.Background(), target, opts...)
}
