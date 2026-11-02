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
	"strings"
	"sync"
	"sync/atomic"
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
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/encoding/protowire"
)

type xrayOwnerKey struct{}

type xrayOwner struct {
	transport *xrayTransport
	ctx       context.Context
	ping      bool
}

type xrayTransport struct {
	engine     *Engine
	instance   *core.Instance
	ctx        context.Context
	cancel     context.CancelFunc
	server     xnet.Destination
	ping       *internet.MemoryStreamConfig
	ownerToken uint64
	untracked  bool
}

const xraySocketOwnerField protowire.Number = 50000

var xrayDialerOnce sync.Once
var xrayDialerError error
var xrayOwnerCounter atomic.Uint64
var xraySocketOwners sync.Map // uint64 -> *xrayTransport

func (e *Engine) newXrayTransport(ctx context.Context, p endpoint) (vpnTransport, error) {
	addresses, err := e.dns.resolvePhysical(ctx, p.Server)
	if err != nil {
		return nil, endpointStageError{stage: "resolve", err: err}
	}
	if err := connectContextError(ctx); err != nil {
		return nil, endpointStageError{stage: "resolve", err: err}
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
	var ping *internet.MemoryStreamConfig
	account := &vless.Account{Id: p.UUID, Flow: p.Flow, Encryption: "none"}
	if p.Kind == "vless_xhttp_cdn" {
		security = serial.ToTypedMessage(&xtls.Config{
			ServerName: p.ServerName, Fingerprint: p.Fingerprint, NextProtocol: []string{"h2", "http/1.1"},
		})
		stream.SecurityType, stream.SecuritySettings = security.Type, []*serial.TypedMessage{security}
		stream.ProtocolName = "splithttp"
		stream.TransportSettings = []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(&splithttp.Config{
			Host: p.ServerName, Path: p.Path, Mode: "packet-up", UplinkHTTPMethod: p.UplinkMethod, UplinkDataPlacement: p.DataPlacement,
			ScMaxEachPostBytes: &splithttp.RangeConfig{From: int32(p.MaxPostBytes), To: int32(p.MaxPostBytes)},
		})}}
		account, err = cdnVLESSAccount(p)
		if err != nil {
			return nil, err
		}
	} else {
		ping, err = internet.ToMemoryStreamConfig(stream)
		if err != nil {
			return nil, errors.New("Could not configure the VPN transport.")
		}
	}
	if p.Kind == "vless_xhttp" {
		stream.ProtocolName = "splithttp"
		stream.TransportSettings = []*internet.TransportConfig{{ProtocolName: "splithttp", Settings: serial.ToTypedMessage(&splithttp.Config{Path: p.Path, Mode: p.Mode})}}
	}
	lifetime, cancel := context.WithCancel(e.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	t := &xrayTransport{engine: e, ctx: lifetime, cancel: cancel, ping: ping, ownerToken: xrayOwnerCounter.Add(1),
		untracked: ctx.Value(probeTransportKey{}) != nil,
		server:    xnet.TCPDestination(xnet.IPAddress(addresses[0].IP), xnet.Port(p.Port))}
	// Mux workers discard their caller's context. This private protobuf field
	// carries ownership through the pinned fork's config copies to our dialer;
	// it is internal metadata, never an OS socket option or a user setting.
	stream.SocketSettings = &internet.SocketConfig{}
	stream.SocketSettings.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, xraySocketOwnerField, protowire.VarintType), t.ownerToken))
	xraySocketOwners.Store(t.ownerToken, t)
	tcpConcurrency := int32(-1)
	if p.Mux {
		tcpConcurrency = 8
	}
	config := &core.Config{
		App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag: "vless", SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
				StreamSettings: stream,
				// TCP mux follows the endpoint setting; UDP, including UDP/443, uses XUDP.
				MultiplexSettings: &proxyman.MultiplexingConfig{Enabled: true, Concurrency: tcpConcurrency, XudpConcurrency: 8, XudpProxyUDP443: "allow"},
			}),
			ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
				Address: xnet.NewIPOrDomain(t.server.Address), Port: uint32(p.Port),
				User: &protocol.User{Account: serial.ToTypedMessage(account)},
			}}),
		}},
	}
	t.instance, err = core.NewWithContext(t.ownerContext(lifetime), config)
	if err != nil {
		cancel()
		xraySocketOwners.CompareAndDelete(t.ownerToken, t)
		return nil, errors.New("Could not configure the VPN transport.")
	}
	if err := t.instance.Start(); err != nil {
		_ = t.Close()
		return nil, errors.New("Could not start the VPN transport.")
	}
	if err := connectContextError(ctx); err != nil {
		_ = t.Close()
		return nil, err
	}
	if ping == nil {
		// A CDN entry must carry data through TLS, XHTTP and VLESS; a raw
		// connection to its edge cannot verify the origin transport.
		err = probeEndpoint(ctx, t)
	} else {
		// Construction starts no network handshake. Verify REALITY here so a
		// failed entry handshake is distinct from the subsequent data probe.
		// Match VLESS outbound's five attempts and 0/200/400/600 ms retry delays,
		// while allowing the attempt deadline to interrupt the backoff as well.
		for attempt := 0; attempt < 5; attempt++ {
			if attempt > 0 {
				delay := time.NewTimer(time.Duration(attempt-1) * 200 * time.Millisecond)
				select {
				case <-delay.C:
				case <-ctx.Done():
				}
				delay.Stop()
			}
			if err = connectContextError(ctx); err != nil {
				break
			}
			handshakeCtx, finish := context.WithCancel(ctx)
			var conn net.Conn
			conn, err = t.PingTCPContext(handshakeCtx, "")
			if err == nil {
				_ = conn.Close()
			}
			finish()
			if err == nil {
				break
			}
			if deadlineErr := connectContextError(ctx); deadlineErr != nil {
				err = deadlineErr
				break
			}
		}
	}
	if err != nil {
		_ = t.Close()
		return nil, errors.New("The VPN transport connection failed.")
	}
	if err := connectContextError(ctx); err != nil {
		_ = t.Close()
		return nil, err
	}
	if !stop() {
		_ = t.Close()
		return nil, ctx.Err()
	}
	return t, nil
}

// The protobuf account expects parsed encryption fields, unlike the catalog's
// VLESS Encryption string normally processed by Xray's JSON config builder.
func cdnVLESSAccount(p endpoint) (*vless.Account, error) {
	a := &vless.Account{Id: p.UUID, Encryption: p.Encryption}
	if p.Encryption == "none" {
		return a, nil
	}
	invalid := errors.New("Could not configure VLESS encryption.")
	parts := strings.Split(p.Encryption, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return nil, invalid
	}
	switch parts[1] {
	case "native":
	case "xorpub":
		a.XorMode = 1
	case "random":
		a.XorMode = 2
	default:
		return nil, invalid
	}
	switch parts[2] {
	case "1rtt":
	case "0rtt":
		a.Seconds = 1
	default:
		return nil, invalid
	}
	keys := parts[3:]
	padding := 0
	for _, part := range keys {
		if len(part) < 20 {
			padding++
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || (len(key) != 32 && len(key) != 1184) {
			return nil, invalid
		}
	}
	if padding == len(keys) {
		return nil, invalid
	}
	a.Padding, a.Encryption = strings.Join(keys[:padding], "."), strings.Join(keys[padding:], ".")
	return a, nil
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
	if t.ping == nil {
		return nil, errors.New("The VPN transport requires a data transfer latency check.")
	}
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
	xraySocketOwners.CompareAndDelete(t.ownerToken, t)
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
		metadata := settings.ProtoReflect().GetUnknown()
		field, kind, n := protowire.ConsumeTag(metadata)
		if n < 0 || field != xraySocketOwnerField || kind != protowire.VarintType {
			return nil, errors.New("The VPN socket owner is unavailable.")
		}
		token, m := protowire.ConsumeVarint(metadata[n:])
		if m < 0 || n+m != len(metadata) {
			return nil, errors.New("The VPN socket owner is unavailable.")
		}
		value, ok := xraySocketOwners.Load(token)
		if !ok {
			return nil, errors.New("The VPN socket owner is unavailable.")
		}
		t := value.(*xrayTransport)
		owner = &xrayOwner{transport: t, ctx: t.ctx}
	}
	t := owner.transport
	if t.ctx.Err() != nil {
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
	if t.untracked {
		conn = &trackedConn{Conn: conn, engine: t.engine, count: true}
	} else {
		conn, err = t.engine.trackConn(conn, true, t.engine.generation.Load())
		if err != nil {
			return nil, err
		}
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
		if len(u.domains) >= 32 {
			u.mu.Unlock()
			return errors.New("Too many proxied UDP destinations.")
		}
		conn, err = core.Dial(u.transport.ownerContext(u.ctx), u.transport.instance, xnet.UDPDestination(xnet.DomainAddress(host), xnet.Port(port)))
		if err != nil {
			u.mu.Unlock()
			return errors.New("Could not open the VPN UDP session.")
		}
		u.domains[address] = conn
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			defer func() {
				u.mu.Lock()
				if u.domains[address] == conn {
					delete(u.domains, address)
				}
				u.mu.Unlock()
				_ = conn.Close()
			}()
			buffer := make([]byte, 65535)
			for {
				n, err := conn.Read(buffer)
				if err != nil {
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
