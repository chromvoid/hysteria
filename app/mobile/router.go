// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

type routedClient struct{ engine *Engine }

func (c *routedClient) TCP(addr string) (net.Conn, error) {
	e := c.engine
	host, port, err := splitAddress(addr)
	if err != nil {
		return nil, err
	}
	if port == 53 {
		return e.dnsTCP()
	}
	address, direct, err := e.destination(host, port)
	if err != nil {
		return nil, err
	}
	if direct {
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		defer cancel()
		return e.directTCP(ctx, address)
	}
	if e.config.Rules.hasDirect() && net.ParseIP(host) != nil {
		return e.sniffTCP(address)
	}
	return e.proxyTCP(address)
}

func (e *Engine) sniffTCP(address string) (net.Conn, error) {
	local, peer := net.Pipe()
	conn, err := e.trackConn(local, false, e.generation.Load())
	if err != nil {
		_ = peer.Close()
		return nil, err
	}
	go func() {
		defer peer.Close()
		defer conn.Close()
		payload, host := sniffDestination(peer)
		var outbound net.Conn
		var err error
		if e.config.Rules.direct(host) {
			ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
			outbound, err = e.directTCP(ctx, address)
			cancel()
		} else {
			outbound, err = e.proxyTCP(address)
		}
		if err != nil {
			return
		}
		defer outbound.Close()
		if len(payload) > 0 {
			if _, err := outbound.Write(payload); err != nil {
				return
			}
		}
		finished := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(outbound, peer); finished <- struct{}{} }()
		go func() { _, _ = io.Copy(peer, outbound); finished <- struct{}{} }()
		<-finished
	}()
	return conn, nil
}

func (c *routedClient) UDP() (client.HyUDPConn, error) {
	e := c.engine
	ctx, cancel := context.WithCancel(e.ctx)
	u := &routedUDP{engine: e, ctx: ctx, cancel: cancel, done: make(chan struct{}), received: make(chan udpResult, 64), direct: make(map[string]net.Conn), dnsSlots: make(chan struct{}, 16), sniffing: make(map[string]*udpSniff), udpDecisions: make(map[string]bool)}
	if !e.addFlow(u, e.generation.Load()) {
		cancel()
		return nil, net.ErrClosed
	}
	return u, nil
}

func (c *routedClient) Close() error { return nil }

func (e *Engine) destination(host string, port int) (string, bool, error) {
	if ip, err := netip.ParseAddr(host); err == nil && (fakeIPv4.Contains(ip.Unmap()) || fakeIPv6.Contains(ip.Unmap())) {
		domain, exists := e.dns.lookupFake(host)
		if !exists {
			return "", false, errors.New("The DNS mapping has expired.")
		}
		host = domain
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), e.config.Rules.direct(host), nil
}

func (e *Engine) dnsTCP() (net.Conn, error) {
	local, peer := net.Pipe()
	conn, err := e.trackConn(local, false, e.generation.Load())
	if err != nil {
		_ = peer.Close()
		return nil, err
	}
	go func() {
		defer peer.Close()
		defer conn.Close()
		var length [2]byte
		for {
			_ = peer.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(peer, length[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(length[:]))
			if n < 12 {
				return
			}
			query := make([]byte, n)
			if _, err := io.ReadFull(peer, query); err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
			answer, err := e.dns.exchange(ctx, query)
			cancel()
			if err != nil || len(answer) > 65535 {
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(answer)))
			if _, err := peer.Write(append(length[:], answer...)); err != nil {
				return
			}
		}
	}()
	return conn, nil
}

type udpResult struct {
	data []byte
	addr string
	err  error
}

type routedUDP struct {
	engine *Engine
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu           sync.Mutex
	sendMu       sync.Mutex
	wg           sync.WaitGroup
	closed       bool
	hy           client.HyUDPConn
	direct       map[string]net.Conn
	received     chan udpResult
	dnsSlots     chan struct{}
	sniffing     map[string]*udpSniff
	udpDecisions map[string]bool
}

func (u *routedUDP) Send(data []byte, addr string) error {
	u.sendMu.Lock()
	defer u.sendMu.Unlock()
	u.mu.Lock()
	closed := u.closed
	u.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	host, port, err := splitAddress(addr)
	if err != nil {
		return err
	}
	if port == 53 {
		select {
		case u.dnsSlots <- struct{}{}:
		default:
			return errors.New("Too many pending DNS requests.")
		}
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			<-u.dnsSlots
			return net.ErrClosed
		}
		u.wg.Add(1)
		u.mu.Unlock()
		query := append([]byte(nil), data...)
		go func() {
			defer u.wg.Done()
			defer func() { <-u.dnsSlots }()
			ctx, cancel := context.WithTimeout(u.ctx, 10*time.Second)
			defer cancel()
			answer, err := u.engine.dns.exchange(ctx, query)
			if err == nil {
				u.deliver(udpResult{data: answer, addr: addr})
			}
		}()
		return nil
	}
	address, direct, err := u.engine.destination(host, port)
	if err != nil {
		return err
	}
	if direct {
		return u.sendDirect(data, addr, address)
	}
	if u.engine.config.Rules.hasDirect() && net.ParseIP(host) != nil {
		return u.sniffUDP(data, addr, address)
	}
	hy, err := u.proxySession()
	if err != nil {
		return err
	}
	if err := hy.Send(data, address); err != nil {
		return errors.New("The VPN UDP send failed.")
	}
	return nil
}

func (u *routedUDP) proxySession() (client.HyUDPConn, error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, net.ErrClosed
	}
	if u.hy != nil {
		hy := u.hy
		u.mu.Unlock()
		return hy, nil
	}
	u.mu.Unlock()
	u.engine.mu.RLock()
	client := u.engine.hy
	u.engine.mu.RUnlock()
	if client == nil {
		return nil, net.ErrClosed
	}
	hy, err := client.UDP()
	if err != nil {
		return nil, errors.New("Could not open the VPN UDP session.")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		_ = hy.Close()
		return nil, net.ErrClosed
	}
	u.hy = hy
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		for {
			data, addr, err := hy.Receive()
			if err != nil {
				u.deliver(udpResult{err: errors.New("The VPN UDP receive failed.")})
				return
			}
			u.deliver(udpResult{data: data, addr: addr})
		}
	}()
	return hy, nil
}

func (u *routedUDP) sendDirect(data []byte, original, address string) error {
	u.mu.Lock()
	conn := u.direct[original]
	count := len(u.direct)
	u.mu.Unlock()
	if conn == nil {
		if count >= 32 {
			return errors.New("Too many direct UDP destinations.")
		}
		host, port, _ := net.SplitHostPort(address)
		ctx, cancel := context.WithTimeout(u.ctx, 10*time.Second)
		defer cancel()
		addresses, err := u.engine.dns.resolvePhysical(ctx, host)
		if err != nil {
			return errors.New("Could not resolve the UDP destination.")
		}
		dialer := net.Dialer{Timeout: 10 * time.Second, Control: u.engine.control}
		gen := u.engine.generation.Load()
		for _, candidate := range addresses {
			var err error
			conn, err = dialer.DialContext(ctx, "udp", net.JoinHostPort(candidate.IP.String(), port))
			if err == nil {
				conn, err = u.engine.trackConn(conn, true, gen)
				if err == nil {
					break
				}
			}
		}
		if conn == nil {
			return errors.New("Could not open the direct UDP socket.")
		}
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			_ = conn.Close()
			return net.ErrClosed
		}
		u.direct[original] = conn
		u.wg.Add(1)
		u.mu.Unlock()
		go func() {
			defer u.wg.Done()
			buffer := make([]byte, 65535)
			for {
				_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, err := conn.Read(buffer)
				if err != nil {
					u.mu.Lock()
					delete(u.direct, original)
					u.mu.Unlock()
					_ = conn.Close()
					return
				}
				u.deliver(udpResult{data: append([]byte(nil), buffer[:n]...), addr: original})
			}
		}()
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(data); err != nil {
		return errors.New("The direct UDP send failed.")
	}
	return nil
}

func (u *routedUDP) deliver(result udpResult) {
	select {
	case u.received <- result:
	case <-u.done:
	}
}

func (u *routedUDP) Receive() ([]byte, string, error) {
	select {
	case result := <-u.received:
		return result.data, result.addr, result.err
	case <-u.done:
		return nil, "", net.ErrClosed
	}
}

func (u *routedUDP) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	u.cancel()
	close(u.done)
	hy := u.hy
	connections := make([]net.Conn, 0, len(u.direct))
	for _, conn := range u.direct {
		connections = append(connections, conn)
	}
	u.direct = make(map[string]net.Conn)
	u.mu.Unlock()
	if hy != nil {
		_ = hy.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	u.wg.Wait()
	u.engine.removeFlow(u)
	return nil
}
