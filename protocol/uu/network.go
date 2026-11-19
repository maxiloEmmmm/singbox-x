package uu

import (
	"context"
	"net"
	"strings"

	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
)

// physicalNet uses sing-box's socket controls for ICE and TURN connections.
type physicalNet struct {
	// Net provides standard interface discovery and address resolution.
	*stdnet.Net
	// ctx ends socket creation when the outbound closes.
	ctx context.Context
	// control marks or protects sockets from the local TUN.
	control control.Func
}

// newPhysicalNet constructs an ICE socket factory, e.g. Linux auto-redirect -> inherit output mark.
func newPhysicalNet(ctx context.Context, options option.DialerOptions) (*physicalNet, error) {
	base, err := stdnet.NewNet()
	if err != nil {
		return nil, err
	}
	result := &physicalNet{Net: base, ctx: ctx}
	manager := service.FromContext[adapter.NetworkManager](ctx)
	if manager != nil {
		defaults := manager.DefaultOptions()
		bindInterface := options.BindInterface
		if bindInterface == "" {
			bindInterface = defaults.BindInterface
		}
		switch {
		case bindInterface != "":
			result.control = control.BindToInterface(manager.InterfaceFinder(), bindInterface, -1)
		case manager.ProtectFunc() != nil:
			result.control = manager.ProtectFunc()
		case manager.AutoDetectInterface():
			result.control = manager.AutoDetectInterfaceFunc()
		}
		mark := uint32(options.RoutingMark)
		if mark == 0 {
			mark = defaults.RoutingMark
		}
		if mark != 0 {
			result.control = control.Append(result.control, control.RoutingMark(mark))
		}
		result.control = control.Append(result.control, manager.AutoRedirectOutputMarkFunc())
	}
	if options.ProtectPath != "" {
		result.control = control.Append(result.control, control.ProtectPath(options.ProtectPath))
	}
	return result, nil
}

// allowedInterface avoids sharing local overlays as ICE routes, e.g. sbox0 -> false.
func (n *physicalNet) allowedInterface(name string) bool {
	for _, prefix := range []string{"lo", "sbox", "tun", "tailscale", "docker", "veth", "virbr", "br-"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

// ListenPacket opens the marked socket, e.g. UDP port 0 -> a local ICE socket.
func (n *physicalNet) ListenPacket(network, address string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: n.control}
	return config.ListenPacket(n.ctx, network, address)
}

// ListenUDP opens the marked local UDP socket for a host candidate.
func (n *physicalNet) ListenUDP(network string, addr *net.UDPAddr) (transport.UDPConn, error) {
	address := ":0"
	if addr != nil {
		address = addr.String()
	}
	conn, err := n.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// ListenTCP opens a marked listener, e.g. a passive ICE TCP candidate.
func (n *physicalNet) ListenTCP(network string, addr *net.TCPAddr) (transport.TCPListener, error) {
	address := ":0"
	if addr != nil {
		address = addr.String()
	}
	config := net.ListenConfig{Control: n.control}
	conn, err := config.Listen(n.ctx, network, address)
	if err != nil {
		return nil, err
	}
	return tcpListener{conn.(*net.TCPListener)}, nil
}

// tcpListener adapts Go's AcceptTCP result to Pion's TCPConn interface.
type tcpListener struct {
	// TCPListener supplies the native listening socket.
	*net.TCPListener
}

// AcceptTCP returns the next TCP peer, e.g. an ICE TCP candidate connects.
func (l tcpListener) AcceptTCP() (transport.TCPConn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Dial connects an automatically protected transport, e.g. to a TURN endpoint.
func (n *physicalNet) Dial(network, address string) (net.Conn, error) {
	dialer := net.Dialer{Control: n.control}
	return dialer.DialContext(n.ctx, network, address)
}

// DialUDP creates a protected connected UDP socket, e.g. a UDP TURN relay.
func (n *physicalNet) DialUDP(network string, local, remote *net.UDPAddr) (transport.UDPConn, error) {
	dialer := net.Dialer{Control: n.control}
	if local != nil {
		dialer.LocalAddr = local
	}
	conn, err := dialer.DialContext(n.ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// DialTCP opens a protected TCP socket, e.g. a TLS TURN relay.
func (n *physicalNet) DialTCP(network string, local, remote *net.TCPAddr) (transport.TCPConn, error) {
	dialer := net.Dialer{Control: n.control}
	if local != nil {
		dialer.LocalAddr = local
	}
	conn, err := dialer.DialContext(n.ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// CreateDialer attaches the mark to a caller-provided socket policy.
func (n *physicalNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	copy := *dialer
	copy.Control = control.Append(copy.Control, n.control)
	return n.Net.CreateDialer(&copy)
}

// CreateListenConfig attaches the mark to caller-provided listener settings.
func (n *physicalNet) CreateListenConfig(config *net.ListenConfig) transport.ListenConfig {
	copy := *config
	copy.Control = control.Append(copy.Control, n.control)
	return &copy
}
