// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/apernet/hysteria/app/v2/internal/socks5"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// Platform protects and binds an Internet socket to the physical network before use.
type Platform interface {
	ProtectSocket(fd int64) error
}

type profile struct {
	Version      int    `json:"version"`
	Name         string `json:"name"`
	Server       string `json:"server"`
	Port         int    `json:"server_port"`
	Password     string `json:"password"`
	ObfsPassword string `json:"obfs_password"`
	ServerName   string `json:"server_name"`
	Certificate  string `json:"certificate"`
}

type mobileConfig struct {
	Profile           profile       `json:"profile"`
	Endpoints         []endpoint    `json:"endpoints"`
	PreferredEndpoint string        `json:"preferred_endpoint"`
	Routing           string        `json:"routing"`
	Rules             *routingRules `json:"rules"`
}

func parseConfig(text string) (mobileConfig, error) {
	var c mobileConfig
	if len(text) > 262144 {
		return c, errors.New("Invalid VPN configuration.")
	}
	if err := json.Unmarshal([]byte(text), &c); err != nil {
		if errors.Is(err, errInvalidRoutingRules) {
			return c, errInvalidRoutingRules
		}
		return c, errors.New("Invalid VPN configuration.")
	}
	if err := c.Rules.compile(); err != nil {
		return c, err
	}
	if c.Routing != "ALL" && c.Routing != "RUSSIAN_DIRECT" {
		return c, errors.New("Invalid VPN configuration.")
	}
	if len(c.Endpoints) == 0 {
		p := &c.Profile
		if p.Version != 1 || p.Server == "" || strings.ContainsAny(p.Server, "/\\\r\n\t ") || p.Port < 1 || p.Port > 65535 || p.Password == "" ||
			(p.ObfsPassword != "" && len(p.ObfsPassword) < 4) {
			return c, errors.New("Invalid VPN configuration.")
		}
		if p.ServerName == "" {
			p.ServerName = p.Server
		}
		if p.Certificate != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(p.Certificate)) {
			return c, errors.New("The server certificate is invalid.")
		}
	}
	if err := c.validateEndpoints(); err != nil {
		return c, err
	}
	return c, nil
}

// Validate checks the configuration without opening sockets or changing VPN state.
func Validate(configJSON string) error {
	_, err := parseConfig(configJSON)
	return err
}

type vpnTransport interface {
	TCPContext(context.Context, string) (net.Conn, error)
	UDP() (client.HyUDPConn, error)
	Close() error
}

// Engine runs the selected VPN transport and a loopback SOCKS5 endpoint for HEV.
type Engine struct {
	config   mobileConfig
	platform Platform
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener
	dns      *dnsResolver

	mu          sync.RWMutex
	hy          vpnTransport
	activeID    string
	lastGoodID  string
	closed      bool
	reconnectMu sync.Mutex
	switching   atomic.Bool
	flowMu      sync.Mutex
	flows       map[io.Closer]struct{}
	generation  atomic.Uint64
	tx          atomic.Int64
	rx          atomic.Int64
	proxyTx     atomic.Int64
	proxyRx     atomic.Int64
	download    downloadStats
}

// Start verifies an endpoint's data transfer and opens a loopback-only SOCKS endpoint.
func Start(configJSON string, platform Platform) (*Engine, error) {
	c, err := parseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	if platform == nil {
		return nil, errors.New("The VPN socket protector is required.")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{config: c, platform: platform, ctx: ctx, cancel: cancel, flows: make(map[io.Closer]struct{})}
	e.download.started = time.Now()
	e.generation.Store(1)
	e.dns = newDNSResolver(e)
	if err := e.connect(c.PreferredEndpoint); err != nil {
		_ = e.Close()
		return nil, errors.New("Could not authenticate the VPN transport. Check the profile and network.")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = e.Close()
		return nil, errors.New("Could not open the VPN packet adapter.")
	}
	e.listener = listener
	server := &socks5.Server{HyClient: &routedClient{engine: e}}
	go func() {
		_ = server.Serve(&trackedListener{Listener: listener, engine: e})
	}()
	return e, nil
}

// Tests replace the URL with a loopback server to avoid external network access.
var healthProbeURL = "https://speed.cloudflare.com/__down?bytes=65536"

func (e *Engine) connect(first string) error {
	endpoints := make([]endpoint, 0, len(e.config.Endpoints))
	for _, p := range e.config.Endpoints {
		if p.ID == first {
			endpoints = append(endpoints, p)
		}
	}
	for _, p := range e.config.Endpoints {
		if p.ID == e.config.PreferredEndpoint && p.ID != first {
			endpoints = append(endpoints, p)
		}
	}
	for _, p := range e.config.Endpoints {
		if p.ID != first && p.ID != e.config.PreferredEndpoint {
			endpoints = append(endpoints, p)
		}
	}
	for _, p := range endpoints {
		if err := e.ctx.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		transport, err := e.newTransport(ctx, p)
		if err == nil {
			err = probeEndpoint(ctx, transport)
		}
		cancel()
		if err != nil {
			if transport != nil {
				_ = transport.Close()
			}
			continue
		}
		e.mu.Lock()
		if e.closed || e.ctx.Err() != nil {
			e.mu.Unlock()
			_ = transport.Close()
			return net.ErrClosed
		}
		e.hy, e.activeID, e.lastGoodID = transport, p.ID, p.ID
		e.mu.Unlock()
		return nil
	}
	return errors.New("No VPN endpoint passed the data transfer check.")
}

func (e *Engine) newTransport(ctx context.Context, p endpoint) (vpnTransport, error) {
	if p.Kind == "hysteria2" {
		return e.newHysteriaTransport(ctx, p)
	}
	return e.newXrayTransport(ctx, p)
}

// Probe sockets belong to the transport, outside the old generation's flow set.
type probeTransportKey struct{}

func probeEndpoint(ctx context.Context, transport vpnTransport) error {
	httpTransport := &http.Transport{DisableKeepAlives: true, DisableCompression: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return transport.TCPContext(ctx, addr)
		}}
	defer httpTransport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthProbeURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: httpTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("The VPN data transfer check was rejected.")
	}
	_, err = io.CopyN(io.Discard, response.Body, 65536)
	return err
}

func (e *Engine) newHysteriaTransport(ctx context.Context, p endpoint) (vpnTransport, error) {
	addresses, err := e.dns.resolvePhysical(ctx, p.Server)
	if err != nil {
		return nil, errors.New("Could not resolve the VPN server.")
	}
	ip := addresses[0].IP
	var roots *x509.CertPool
	if p.Certificate != "" {
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM([]byte(p.Certificate))
	}
	c := &client.Config{
		ServerAddr: &net.UDPAddr{IP: ip, Port: p.Port}, Auth: p.Password,
		TLSConfig:   client.TLSConfig{ServerName: p.ServerName, RootCAs: roots},
		ConnFactory: &packetFactory{engine: e, obfsPassword: p.ObfsPassword, untracked: ctx.Value(probeTransportKey{}) != nil},
		QUICConfig: client.QUICConfig{
			InitialStreamReceiveWindow: 256 * 1024, MaxStreamReceiveWindow: 512 * 1024,
			InitialConnectionReceiveWindow: 1024 * 1024, MaxConnectionReceiveWindow: 2 * 1024 * 1024,
			MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, DisableGSO: true,
		},
	}
	hy, handshake, err := client.NewClientContext(ctx, c)
	if err != nil {
		return nil, errors.New("The VPN transport connection failed.")
	}
	if !handshake.UDPEnabled {
		_ = hy.Close()
		return nil, errors.New("The VPN server does not allow UDP.")
	}
	transport, ok := hy.(vpnTransport)
	if !ok {
		_ = hy.Close()
		return nil, errors.New("The VPN transport does not support cancellation.")
	}
	return transport, nil
}

// ActiveEndpoint returns the selected endpoint ID, or an empty string when disconnected.
func (e *Engine) ActiveEndpoint() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeID
}

// SocksPort is the loopback TCP port consumed by the native HEV adapter.
func (e *Engine) SocksPort() int64 {
	if e.listener == nil {
		return 0
	}
	return int64(e.listener.Addr().(*net.TCPAddr).Port)
}

// HEVConfig contains only local packet-adapter settings, never server credentials.
func (e *Engine) HEVConfig() string {
	return fmt.Sprintf("tunnel:\n  name: wayveil\n  mtu: 1400\n  ipv4: 172.19.0.1\n  ipv6: 'fdfe:dcba:9876::1'\nsocks5:\n  address: 127.0.0.1\n  port: %d\n  udp: udp\nmisc:\n  task-stack-size: 24576\n  tcp-buffer-size: 4096\n  max-session-count: 512\n  connect-timeout: 10000\n  tcp-read-write-timeout: 300000\n  udp-read-write-timeout: 60000\n  log-file: /dev/null\n  log-level: error\n", e.SocksPort())
}

// Check verifies fresh HTTPS over the active transport, independent of bypass rules.
func (e *Engine) Check() error {
	ctx, cancel := context.WithTimeout(e.ctx, 8*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := e.proxyTCPContext(ctx, addr)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		}
		return conn, err
	}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	response, err := (&http.Client{Transport: transport, Timeout: 8 * time.Second}).Do(request)
	if err != nil {
		return errors.New("The VPN connection check failed.")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "ip=") {
		return errors.New("The VPN connection check failed.")
	}
	return nil
}

// Ping measures a TCP open through the current VPN transport without sending payload.
func (e *Engine) Ping() (int64, error) {
	e.mu.RLock()
	hy, closed := e.hy, e.closed
	e.mu.RUnlock()
	if closed {
		return 0, errors.New("The VPN engine is closed.")
	}
	if hy == nil {
		return 0, errors.New("The VPN transport is not connected.")
	}
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()
	dial := hy.TCPContext
	if transport, ok := hy.(interface {
		PingTCPContext(context.Context, string) (net.Conn, error)
	}); ok {
		dial = transport.PingTCPContext
	}
	started := time.Now()
	conn, err := dial(ctx, "1.1.1.1:443")
	elapsed := time.Since(started)
	if err != nil {
		return 0, errors.New("The VPN latency check failed.")
	}
	_ = conn.Close()
	return max(1, int64((elapsed+time.Millisecond-1)/time.Millisecond)), nil
}

// Reconnect replaces the network transport while keeping HEV's listener address stable.
func (e *Engine) Reconnect() error {
	e.reconnectMu.Lock()
	defer e.reconnectMu.Unlock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return net.ErrClosed
	}
	hy := e.hy
	first := e.lastGoodID
	e.hy = nil
	e.activeID = ""
	e.generation.Add(1)
	e.mu.Unlock()
	e.closeFlows()
	if hy != nil {
		_ = hy.Close()
	}
	e.dns.close()
	if err := e.connect(first); err != nil {
		return errors.New("Could not reconnect the VPN transport.")
	}
	return nil
}

// TrySwitch probes an endpoint without interrupting traffic, then replaces the transport.
func (e *Engine) TrySwitch(id string) bool {
	if !e.switching.CompareAndSwap(false, true) {
		return false
	}
	defer e.switching.Store(false)
	e.mu.RLock()
	closed, active, gen := e.closed, e.activeID, e.generation.Load()
	e.mu.RUnlock()
	if closed || active == id {
		return false
	}
	var point endpoint
	for _, p := range e.config.Endpoints {
		if p.ID == id {
			point = p
			break
		}
	}
	if point.ID == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	transport, err := e.newTransport(context.WithValue(ctx, probeTransportKey{}, true), point)
	if err == nil {
		err = probeEndpoint(ctx, transport)
	}
	cancel()
	if err != nil {
		if transport != nil {
			_ = transport.Close()
		}
		return false
	}
	e.reconnectMu.Lock()
	defer e.reconnectMu.Unlock()
	e.mu.Lock()
	if e.closed || e.generation.Load() != gen {
		e.mu.Unlock()
		_ = transport.Close()
		return false
	}
	old := e.hy
	// Snapshot before publishing the new generation so new flows survive the swap.
	e.flowMu.Lock()
	flows := make([]io.Closer, 0, len(e.flows))
	for flow := range e.flows {
		flows = append(flows, flow)
	}
	e.generation.Add(1)
	e.hy, e.activeID, e.lastGoodID = transport, id, id
	e.flowMu.Unlock()
	e.mu.Unlock()
	for _, flow := range flows {
		_ = flow.Close()
	}
	if old != nil {
		_ = old.Close()
	}
	e.dns.close()
	return true
}

// Close stops listeners, accepted flows, DNS requests and the encrypted transport.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	hy := e.hy
	e.hy = nil
	e.activeID = ""
	e.cancel()
	e.generation.Add(1)
	e.mu.Unlock()
	if e.listener != nil {
		_ = e.listener.Close()
	}
	e.closeFlows()
	if hy != nil {
		_ = hy.Close()
	}
	if e.dns != nil {
		e.dns.close()
	}
	return nil
}

func (e *Engine) TxBytes() int64 { return e.tx.Load() }
func (e *Engine) RxBytes() int64 { return e.rx.Load() }

// ProxyTxBytes returns TCP and UDP payload bytes sent through the VPN since Start.
func (e *Engine) ProxyTxBytes() int64 { return e.proxyTx.Load() }

// ProxyRxBytes returns TCP and UDP payload bytes received through the VPN since Start.
func (e *Engine) ProxyRxBytes() int64 { return e.proxyRx.Load() }

// DownloadMedianBps returns the histogram midpoint for completed active seconds.
func (e *Engine) DownloadMedianBps() int64 {
	e.download.advance(e.download.now())
	return e.download.median.Load()
}

// DownloadPeakBps returns the highest VPN payload byte count in a completed active second.
func (e *Engine) DownloadPeakBps() int64 {
	e.download.advance(e.download.now())
	return e.download.peak.Load()
}

func Version() string { return "Hysteria2 2.13.0 / Wayveil HEV" }

const minimumDownloadBytes = 64 * 1024

// Eight buckets per doubling give a 9.05% step, capped at 2 GB/s.
var downloadBounds = func() [121]int64 {
	var bounds [121]int64
	for i := range bounds {
		bounds[i] = min(2_000_000_000, int64(minimumDownloadBytes*math.Exp2(float64(i)/8)))
	}
	return bounds
}()

type downloadStats struct {
	started time.Time
	clock   func() int64 // Test clock, in elapsed monotonic seconds.
	second  atomic.Int64
	readers atomic.Int64
	bytes   atomic.Int64
	median  atomic.Int64
	peak    atomic.Int64
	mu      sync.Mutex
	buckets [120]uint64
	samples uint64
}

func (d *downloadStats) now() int64 {
	if d.clock != nil {
		return d.clock()
	}
	return int64(time.Since(d.started) / time.Second)
}

func (e *Engine) recordProxyRead(n int64) {
	if n <= 0 {
		return
	}
	e.proxyRx.Add(n)
	d := &e.download
	for {
		d.readers.Add(1)
		second := d.now()
		if second <= d.second.Load() {
			d.bytes.Add(n)
			d.readers.Add(-1)
			return
		}
		d.readers.Add(-1)
		d.advance(second)
	}
}

func (d *downloadStats) advance(second int64) {
	if second <= d.second.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if second <= d.second.Load() {
		return
	}
	// Block new writers, then drain writers that already validated the old second.
	// No timer or background goroutine is needed to finish an interval.
	d.second.Store(-1)
	for d.readers.Load() != 0 {
		runtime.Gosched()
	}
	n := d.bytes.Swap(0)
	if n >= minimumDownloadBytes {
		bucket := 0
		for bucket < len(d.buckets)-1 && n >= downloadBounds[bucket+1] {
			bucket++
		}
		d.buckets[bucket]++
		d.samples++
		d.peak.Store(max(d.peak.Load(), n))
		var count uint64
		for i, samples := range d.buckets {
			count += samples
			if count >= (d.samples+1)/2 {
				d.median.Store((downloadBounds[i] + downloadBounds[i+1]) / 2)
				break
			}
		}
	}
	d.second.Store(second)
}

func (e *Engine) proxyTCP(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	return e.proxyTCPContext(ctx, addr)
}

func (e *Engine) proxyTCPContext(ctx context.Context, addr string) (net.Conn, error) {
	gen := e.generation.Load()
	e.mu.RLock()
	hy := e.hy
	e.mu.RUnlock()
	if hy == nil {
		return nil, net.ErrClosed
	}
	conn, err := hy.TCPContext(ctx, addr)
	if err != nil {
		return nil, errors.New("The VPN TCP connection failed.")
	}
	tracked, err := e.trackConn(conn, false, gen)
	if err != nil {
		return nil, err
	}
	tracked.(*trackedConn).proxy = true
	return tracked, nil
}

func (e *Engine) directTCP(ctx context.Context, addr string) (net.Conn, error) {
	gen := e.generation.Load()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("Invalid destination address.")
	}
	addresses, err := e.dns.resolvePhysical(ctx, host)
	if err != nil {
		return nil, errors.New("Could not resolve the destination.")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: e.control}
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.IP.String(), port))
		if err == nil {
			return e.trackConn(conn, true, gen)
		}
	}
	return nil, errors.New("The direct TCP connection failed.")
}

func (e *Engine) control(network, address string, raw syscall.RawConn) error {
	var protectErr error
	if err := raw.Control(func(fd uintptr) { protectErr = e.platform.ProtectSocket(int64(fd)) }); err != nil {
		return errors.New("Could not access the VPN transport socket.")
	}
	if protectErr != nil {
		return errors.New("Could not protect the VPN transport socket.")
	}
	return nil
}

func (e *Engine) addFlow(flow io.Closer, gen uint64) bool {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	if e.ctx.Err() != nil || e.generation.Load() != gen {
		return false
	}
	e.flows[flow] = struct{}{}
	return true
}

func (e *Engine) removeFlow(flow io.Closer) {
	e.flowMu.Lock()
	delete(e.flows, flow)
	e.flowMu.Unlock()
}

func (e *Engine) closeFlows() {
	e.flowMu.Lock()
	flows := make([]io.Closer, 0, len(e.flows))
	for flow := range e.flows {
		flows = append(flows, flow)
	}
	e.flowMu.Unlock()
	for _, flow := range flows {
		_ = flow.Close()
	}
}

type packetFactory struct {
	engine       *Engine
	obfsPassword string
	untracked    bool
}

func (f *packetFactory) New(addr net.Addr) (net.PacketConn, error) {
	e := f.engine
	gen := e.generation.Load()
	config := net.ListenConfig{Control: e.control}
	network, address := "udp4", "0.0.0.0:0"
	if addr.(*net.UDPAddr).IP.To4() == nil {
		network, address = "udp6", "[::]:0"
	}
	conn, err := config.ListenPacket(e.ctx, network, address)
	if err != nil {
		return nil, errors.New("Could not open the VPN transport socket.")
	}
	tracked := &trackedPacket{PacketConn: conn, engine: e}
	if !f.untracked && !e.addFlow(tracked, gen) {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if password := f.obfsPassword; password != "" {
		wrapped, err := obfs.WrapPacketConnSalamander(tracked, []byte(password))
		if err != nil {
			_ = tracked.Close()
			return nil, errors.New("The obfuscation configuration is invalid.")
		}
		return wrapped, nil
	}
	return tracked, nil
}

type trackedPacket struct {
	net.PacketConn
	engine *Engine
	once   sync.Once
}

func (c *trackedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	c.engine.rx.Add(int64(n))
	return n, addr, err
}
func (c *trackedPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	c.engine.tx.Add(int64(n))
	return n, err
}
func (c *trackedPacket) Close() error {
	var err error
	c.once.Do(func() { err = c.PacketConn.Close(); c.engine.removeFlow(c) })
	return err
}

type trackedConn struct {
	net.Conn
	engine *Engine
	count  bool
	proxy  bool
	once   sync.Once
}

func (e *Engine) trackConn(conn net.Conn, count bool, gen uint64) (net.Conn, error) {
	tracked := &trackedConn{Conn: conn, engine: e, count: count}
	if !e.addFlow(tracked, gen) {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	return tracked, nil
}
func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.count {
		c.engine.rx.Add(int64(n))
	}
	if c.proxy {
		c.engine.recordProxyRead(int64(n))
	}
	return n, err
}
func (c *trackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.count {
		c.engine.tx.Add(int64(n))
	}
	if c.proxy {
		c.engine.proxyTx.Add(int64(n))
	}
	return n, err
}
func (c *trackedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.engine.removeFlow(c) })
	return err
}

type trackedListener struct {
	net.Listener
	engine *Engine
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.engine.trackConn(conn, false, l.engine.generation.Load())
}

func splitAddress(addr string) (string, int, error) {
	host, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, errors.New("Invalid destination address.")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return "", 0, errors.New("Invalid destination address.")
	}
	return host, port, nil
}
