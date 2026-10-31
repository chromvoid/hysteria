// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
)

type xrayOwnerKey struct{}

type xrayOwner struct {
	transport *xrayTransport
	ctx       context.Context
	ping      bool
}

type xrayTransport struct {
	engine   *Engine
	instance *core.Instance
	ctx      context.Context
	cancel   context.CancelFunc
	server   xnet.Destination
	ping     *internet.MemoryStreamConfig
}

var xrayDialerOnce sync.Once
var xrayDialerError error
var xraySocketOwners sync.Map // *internet.SocketConfig -> *xrayTransport

func (e *Engine) newXrayTransport(ctx context.Context, p endpoint) (vpnTransport, error) {
	addresses, err := e.dns.resolvePhysical(ctx, p.Server)
	if err != nil {
		return nil, errors.New("Could not resolve the VPN server.")
	}
	xrayDialerOnce.Do(func() {
		xrayDialerError = internet.RegisterDialerController(xraySocketController)
		if xrayDialerError == nil {
			internet.UseAlternativeSystemDialer(&xraySystemDialer{})
		}
	})
	if xrayDialerError != nil {
		return nil, errors.New("Could not configure VPN socket protection.")
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(p.PublicKey)
	shortID := make([]byte, 8)
	_, _ = hex.Decode(shortID, []byte(p.ShortID))
	security := serial.ToTypedMessage(&reality.Config{
		ServerName: p.ServerName, PublicKey: publicKey, ShortId: shortID, Fingerprint: p.Fingerprint,
		SpiderX: "/", SpiderY: make([]int64, 10),
	})
	stream := &internet.StreamConfig{
		ProtocolName: "tcp", SecurityType: security.Type, SecuritySettings: []*serial.TypedMessage{security},
		TransportSettings: []*internet.TransportConfig{{ProtocolName: "tcp", Settings: serial.ToTypedMessage(&tcp.Config{})}},
	}
	ping, err := internet.ToMemoryStreamConfig(stream)
	if err != nil {
		return nil, errors.New("Could not configure the VPN transport.")
	}
	// The XUDP worker discards its caller's context. The TCP health probe learns
	// this handler's decoded settings pointer before any UDP session is opened.
	stream.SocketSettings = &internet.SocketConfig{}
	if p.Kind == "vless_xhttp" {
		stream.ProtocolName = "splithttp"
		stream.TransportSettings = []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(&splithttp.Config{Path: p.Path, Mode: p.Mode})}}
	}
	lifetime, cancel := context.WithCancel(e.ctx)
	t := &xrayTransport{engine: e, ctx: lifetime, cancel: cancel, ping: ping,
		server: xnet.TCPDestination(xnet.IPAddress(addresses[0].IP), xnet.Port(p.Port))}
	config := &core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "vless", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: stream,
				// Keep TCP streams separate while carrying UDP, including UDP/443, over XUDP.
				MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: -1, XudpConcurrency: 8, XudpProxyUDP443: "allow"},
			}),
			ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
				Address: xnet.NewIPOrDomain(t.server.Address), Port: uint32(p.Port),
				User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: p.UUID, Flow: p.Flow, Encryption: "none"})},
			}}),
		}},
	}
	t.instance, err = core.NewWithContext(t.ownerContext(lifetime), config)
	if err != nil {
		cancel()
		return nil, errors.New("Could not configure the VPN transport.")
	}
	if err := t.instance.Start(); err != nil {
		_ = t.Close()
		return nil, errors.New("Could not start the VPN transport.")
	}
	return t, nil
}

func (t *xrayTransport) ownerContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, xrayOwnerKey{}, &xrayOwner{transport: t, ctx: ctx})
}

func (t *xrayTransport) TCPContext(ctx context.Context, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := splitAddress(address)
	if err != nil {
		return nil, err
	}
	// core.Dial dispatches asynchronously. Its stream must survive the caller's
	// dial timeout being canceled after this method returns.
	flow, cancel := context.WithCancel(t.ctx)
	conn, err := core.Dial(t.ownerContext(flow), t.instance, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	if err != nil {
		cancel()
		return nil, errors.New("The VPN TCP connection failed.")
	}
	if err := ctx.Err(); err != nil {
		cancel()
		_ = conn.Close()
		return nil, err
	}
	return &xrayStream{Conn: conn, cancel: cancel}, nil
}

// PingTCPContext measures the protected REALITY handshake to the entry server.
// It avoids core.Dial's asynchronous pipe and sends no destination payload.
func (t *xrayTransport) PingTCPContext(ctx context.Context, _ string) (net.Conn, error) {
	ctx = context.WithValue(ctx, xrayOwnerKey{}, &xrayOwner{transport: t, ctx: ctx, ping: true})
	conn, err := internet.Dial(ctx, t.server, t.ping)
	if err != nil {
		return nil, errors.New("The VPN latency check failed.")
	}
	return conn, nil
}

func (t *xrayTransport) UDP() (client.HyUDPConn, error) {
	ctx, cancel := context.WithCancel(t.ctx)
	conn, err := core.DialUDP(t.ownerContext(ctx), t.instance)
	if err != nil {
		cancel()
		return nil, errors.New("Could not open the VPN UDP session.")
	}
	u := &xrayUDP{transport: t, ctx: ctx, cancel: cancel, conn: conn, domains: make(map[string]net.Conn), received: make(chan udpResult, 64)}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		buffer := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				u.deliver(udpResult{err: err})
				return
			}
			u.deliver(udpResult{data: append([]byte(nil), buffer[:n]...), addr: addr.String()})
		}
	}()
	return u, nil
}

func (t *xrayTransport) Close() error {
	t.cancel()
	xraySocketOwners.Range(func(settings, owner any) bool {
		if owner == t {
			xraySocketOwners.CompareAndDelete(settings, t)
		}
		return true
	})
	return t.instance.Close()
}

// Upstream's default dialer logs controller errors and continues connecting.
// Invoke the registered controller directly so a protection failure stops dialing.
// Context ownership also keeps in-process server sockets outside the VPN engine.
type xraySystemDialer struct{ fallback internet.DefaultSystemDialer }

type xrayRawConn struct {
	syscall.RawConn
	engine *Engine
}

func xraySocketController(network, address string, raw syscall.RawConn) error {
	if owned, ok := raw.(*xrayRawConn); ok {
		return owned.engine.control(network, address, owned.RawConn)
	}
	return nil
}

func (d *xraySystemDialer) Dial(ctx context.Context, source xnet.Address, dest xnet.Destination, settings *internet.SocketConfig) (net.Conn, error) {
	owner, _ := ctx.Value(xrayOwnerKey{}).(*xrayOwner)
	if owner == nil {
		if settings == nil {
			return d.fallback.Dial(ctx, source, dest, nil)
		}
		value, ok := xraySocketOwners.Load(settings)
		if !ok {
			return nil, errors.New("The VPN socket owner is unavailable.")
		}
		t := value.(*xrayTransport)
		owner = &xrayOwner{transport: t, ctx: t.ctx}
	}
	t := owner.transport
	if settings != nil {
		xraySocketOwners.Store(settings, t)
	}
	if t.ctx.Err() != nil {
		if settings != nil {
			xraySocketOwners.CompareAndDelete(settings, t)
		}
		return nil, net.ErrClosed
	}
	if dest.Network != xnet.Network_TCP || !dest.Address.Family().IsIP() {
		return nil, errors.New("The VPN transport requires a resolved TCP server address.")
	}
	ctx, cancel := context.WithCancel(owner.ctx)
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	defer cancel()
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		return xraySocketController(network, address, &xrayRawConn{RawConn: raw, engine: t.engine})
	}}
	conn, err := dialer.DialContext(ctx, "tcp", dest.NetAddr())
	if err != nil {
		return nil, err
	}
	conn, err = t.engine.trackConn(conn, true, t.engine.generation.Load())
	if err != nil {
		return nil, err
	}
	// XHTTP and XUDP share raw sockets across logical streams. Closing one
	// stream must not close a socket still serving other streams.
	lifetime := t.ctx
	if owner.ping {
		lifetime = owner.ctx
	}
	return &xraySocket{Conn: conn, stop: context.AfterFunc(lifetime, func() { _ = conn.Close() })}, nil
}

func (*xraySystemDialer) DestIpAddress() net.IP { return nil }

type xraySocket struct {
	net.Conn
	stop func() bool
}

func (c *xraySocket) Close() error {
	c.stop()
	return c.Conn.Close()
}

type xrayStream struct {
	net.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func (c *xrayStream) Close() error {
	var err error
	c.once.Do(func() { c.cancel(); err = c.Conn.Close() })
	return err
}

type xrayUDP struct {
	transport *xrayTransport
	ctx       context.Context
	cancel    context.CancelFunc
	conn      net.PacketConn
	mu        sync.Mutex
	closed    bool
	domains   map[string]net.Conn
	received  chan udpResult
	wg        sync.WaitGroup
}

func (u *xrayUDP) Send(data []byte, address string) error {
	if len(data) > buf.Size {
		return errors.New("The VPN UDP datagram exceeds 8192 bytes.")
	}
	host, port, err := splitAddress(address)
	if err != nil {
		return err
	}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return net.ErrClosed
	}
	if ip := net.ParseIP(host); ip != nil {
		u.mu.Unlock()
		n, err := u.conn.WriteTo(data, &net.UDPAddr{IP: ip, Port: port})
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	// core.DialUDP accepts only numeric UDPAddr values. A domain destination
	// needs a fixed XUDP stream so resolution stays at the proxy server.
	conn := u.domains[address]
	if conn == nil {
		conn, err = core.Dial(u.transport.ownerContext(u.ctx), u.transport.instance, xnet.UDPDestination(xnet.DomainAddress(host), xnet.Port(port)))
		if err != nil {
			u.mu.Unlock()
			return errors.New("Could not open the VPN UDP session.")
		}
		u.domains[address] = conn
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			buffer := make([]byte, 65535)
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					u.deliver(udpResult{err: err})
					return
				}
				u.deliver(udpResult{data: append([]byte(nil), buffer[:n]...), addr: net.JoinHostPort(host, strconv.Itoa(port))})
			}
		}()
	}
	u.mu.Unlock()
	n, err := conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func (u *xrayUDP) deliver(result udpResult) {
	select {
	case u.received <- result:
	case <-u.ctx.Done():
	}
}

func (u *xrayUDP) Receive() ([]byte, string, error) {
	select {
	case result := <-u.received:
		return result.data, result.addr, result.err
	case <-u.ctx.Done():
		return nil, "", net.ErrClosed
	}
}

func (u *xrayUDP) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	u.cancel()
	_ = u.conn.Close()
	for _, conn := range u.domains {
		_ = conn.Close()
	}
	u.mu.Unlock()
	u.wg.Wait()
	return nil
}
