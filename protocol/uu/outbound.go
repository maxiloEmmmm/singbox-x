package uu

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

const Type = "uu"

// Options configures a UU controller, e.g. device_id=185 and remote_port=1080.
type Options struct {
	// DialerOptions controls authenticated cloud API and WebSocket signaling traffic.
	option.DialerOptions
	// DeviceID is selected from the signed-in account after QR login.
	DeviceID string `json:"device_id,omitempty"`
	// Account selects the controller credentials; empty uses the existing default profile.
	Account string `json:"account,omitempty"`
	// RemotePort is the peer's SOCKS5/mixed inbound on 127.0.0.1.
	RemotePort uint16 `json:"remote_port"`
}

// connectionAttempt allows concurrent callers to await one carrier without owning its lifetime.
type connectionAttempt struct {
	// done closes once the attempt publishes its result.
	done chan struct{}
	// session is the connected carrier.
	session *portSession
	// err is the failure, when no carrier could be created.
	err error
}

// Outbound delegates TCP and UDP SOCKS framing to the built-in SOCKS outbound.
type Outbound struct {
	// Adapter advertises the uu protocol and the physical dialer's dependency.
	outbound.Adapter
	// ctx cancels control, login, and forwarding on sing-box shutdown.
	ctx context.Context
	// cancel ends ctx.
	cancel context.CancelFunc
	// router configures the wrapped SOCKS outbound.
	router adapter.Router
	// logger is used by the SOCKS outbound and non-sensitive runtime diagnostics.
	logger log.ContextLogger
	// options identifies the remote mapping endpoint.
	options Options
	// cloud makes signed HTTPS and WSS requests.
	cloud cloudClient
	// transport is the HTTP socket pool and is closed with the outbound.
	transport *http.Transport
	// network supplies TUN-safe sockets to WebRTC.
	network *physicalNet
	// account is the shared private UU login profile.
	account *account
	// mu protects lifecycle resources and the carrier status.
	mu sync.Mutex
	// listener accepts only loopback connections from the local SOCKS client.
	listener net.Listener
	// control handles the privileged local panel API.
	control *http.Server
	// socks is the concrete wrapped SOCKS outbound, initialized at start.
	socks *socks.Outbound
	// session is the one active UU carrier for this outbound.
	session *portSession
	// attempt is the current connection attempt, shared across callers.
	attempt *connectionAttempt
	// lastError is the sanitized failure shown by the panel.
	lastError error
	// retryAfter briefly coalesces failed attempts from concurrent clients.
	retryAfter time.Time
}

var (
	_ adapter.Outbound  = (*Outbound)(nil)
	_ adapter.Lifecycle = (*Outbound)(nil)
)

// RegisterOutbound adds the uu type to the sing-box outbound registry.
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[Options](registry, Type, NewOutbound)
}

// NewOutbound validates the configuration without connecting, e.g. a pending device may sign in later.
func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	if options.RemotePort == 0 {
		return nil, errors.New("uu remote_port must be between 1 and 65535")
	}
	if options.DeviceID != "" && !validDeviceID(options.DeviceID) {
		return nil, errors.New("uu device_id is invalid")
	}
	profile, err := controllerProfilePath(options.Account)
	if err != nil {
		return nil, err
	}
	boxCtx, cancel := context.WithCancel(ctx)
	cloud, transport, network, err := newTransport(boxCtx, options.DialerOptions)
	if err != nil {
		cancel()
		return nil, err
	}
	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(Type, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:     boxCtx, cancel: cancel, router: router, logger: logger, options: options, cloud: cloud,
		transport: transport, network: network, account: accountFor(profile),
	}, nil
}

// newTransport shares TUN-safe network setup, e.g. both UU roles use the same account API.
func newTransport(ctx context.Context, options option.DialerOptions) (cloudClient, *http.Transport, *physicalNet, error) {
	// Bootstrap UU without depending on a sing-box DNS route that may itself use
	// the UU outbound. A configured domain resolver or detour still takes effect.
	systemResolver := options.Detour == "" && options.DomainResolver == nil
	physical, err := dialer.New(ctx, options, !systemResolver)
	if err != nil {
		return cloudClient{}, nil, nil, err
	}
	network, err := newPhysicalNet(ctx, options)
	if err != nil {
		return cloudClient{}, nil, nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			destination := M.ParseSocksaddr(address)
			if !systemResolver || !destination.IsDomain() {
				return physical.DialContext(ctx, network, destination)
			}
			resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", destination.Fqdn)
			if err != nil {
				return nil, err
			}
			return N.DialParallel(ctx, physical, network, destination, resolved, false, 0)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
	}
	cloud := cloudClient{base: cloudURL, http: &http.Client{
		Transport: transport,
		// Prevent cloud credentials from being forwarded to redirect targets.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	return cloud, transport, network, nil
}

// Start exposes the control socket and private mapping listener, e.g. start -> 127.0.0.1:random.
func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.ctx.Err(); err != nil {
		return err
	}
	if o.control != nil {
		return nil
	}
	if o.options.DeviceID == "" {
		// A newly saved node can authenticate through the control socket before it has a target.
		server, err := o.startControl()
		if err == nil {
			o.control = server
		}
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	socksOutbound, err := socks.NewOutbound(o.ctx, o.router, o.logger, o.Tag(), option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(listener.Addr().(*net.TCPAddr).Port)},
		Version:       "5",
		UDPOverTCP:    &option.UDPOverTCPOptions{Enabled: true, Version: uot.Version},
	})
	if err != nil {
		listener.Close()
		return err
	}
	server, err := o.startControl()
	if err != nil {
		listener.Close()
		return err
	}
	o.listener, o.control, o.socks = listener, server, socksOutbound.(*socks.Outbound)
	go o.acceptLoop(listener)
	return nil
}

// Close cancels all forwarding, e.g. a config reload closes its local listeners and carrier.
func (o *Outbound) Close() error {
	o.cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.listener != nil {
		_ = o.listener.Close()
		o.listener = nil
	}
	if o.control != nil {
		_ = o.control.Close()
		o.control = nil
	}
	o.transport.CloseIdleConnections()
	return nil
}

// DialContext sends TCP through SOCKS CONNECT and UDP through UoT, e.g. tcp example.com:443.
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, err := o.socksClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, network, destination)
}

// ListenPacket delegates packet framing, e.g. a UDP DNS query -> one UoT stream.
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	client, err := o.socksClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.ListenPacket(ctx, destination)
}

// socksClient waits for the shared carrier first, e.g. an unsigned outbound fails without dialing SOCKS.
func (o *Outbound) socksClient(ctx context.Context) (*socks.Outbound, error) {
	if o.options.DeviceID == "" {
		return nil, errors.New("请先为 UU 出站选择对端设备")
	}
	o.mu.Lock()
	client := o.socks
	o.mu.Unlock()
	if client == nil {
		return nil, errors.New("UU 出站尚未启动")
	}
	if _, err := o.getSession(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

// acceptLoop relays loopback clients, e.g. 3 accepted TCP connections share one FILE channel.
func (o *Outbound) acceptLoop(listener net.Listener) {
	// Cap connections waiting for an ICE handshake as well as already-open streams.
	slots := make(chan struct{}, maxFlows)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				session, err := o.getSession(o.ctx)
				if err != nil {
					_ = conn.Close()
					return
				}
				session.bridge(conn, o.options.RemotePort)
			}()
		default:
			_ = conn.Close()
		}
	}
}

// getSession joins or reuses one carrier, e.g. concurrent dials await the same attempt.
func (o *Outbound) getSession(ctx context.Context) (*portSession, error) {
	if o.options.DeviceID == "" {
		return nil, errors.New("请先为 UU 出站选择对端设备")
	}
	o.mu.Lock()
	if err := o.ctx.Err(); err != nil {
		o.mu.Unlock()
		return nil, err
	}
	if session := o.session; session != nil && session.ctx.Err() == nil {
		o.mu.Unlock()
		return session, nil
	}
	creds, err := o.account.current()
	if err != nil {
		o.mu.Unlock()
		return nil, err
	}
	if o.options.DeviceID == creds.DeviceID {
		o.mu.Unlock()
		return nil, errors.New("UU 出站不能映射到本机设备")
	}
	attempt := o.attempt
	if attempt == nil {
		if o.lastError != nil && time.Now().Before(o.retryAfter) {
			err = o.lastError
			o.mu.Unlock()
			return nil, err
		}
		attempt = &connectionAttempt{done: make(chan struct{})}
		o.attempt = attempt
		go o.connect(attempt, creds)
	}
	o.mu.Unlock()
	select {
	case <-attempt.done:
		return attempt.session, attempt.err
	case <-o.ctx.Done():
		return nil, o.ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// connect publishes the result of a carrier attempt, e.g. expired account -> QR login required.
func (o *Outbound) connect(attempt *connectionAttempt, creds credentials) {
	session, err := openPortSession(o.ctx, o.cloud, creds, o.options.DeviceID, o.network)
	if errors.Is(err, errLoginExpired) {
		o.account.expire(creds.Token)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.session, o.lastError, o.attempt = session, err, nil
	o.retryAfter = time.Now().Add(time.Second)
	attempt.session, attempt.err = session, err
	close(attempt.done)
}

// profilePath locates one role's credentials, e.g. host-credentials.json for the receiver.
func profilePath(filename string) (string, error) {
	dir := os.Getenv("SBOXCTL_UU_STATE_DIR")
	if dir == "" {
		root, err := os.UserConfigDir()
		if err != nil {
			return "", errors.New("无法确定 UU 凭据目录")
		}
		dir = filepath.Join(root, "sboxctl", "uu")
	}
	return filepath.Join(dir, filename), nil
}

// controllerProfilePath isolates connection accounts, e.g. empty -> the existing default file.
func controllerProfilePath(id string) (string, error) {
	if id == "" || id == "default" {
		return profilePath("credentials.json")
	}
	if !validAccountID(id) {
		return "", errors.New("invalid uu account ID")
	}
	return profilePath("controller-" + id + ".json")
}

// validAccountID accepts a profile key, e.g. office-2 -> true and ../office -> false.
func validAccountID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
