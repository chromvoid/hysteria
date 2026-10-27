// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type dnsRoundTripFunc func(*http.Request) (*http.Response, error)

func (f dnsRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func dnsQuery(t *testing.T, name string, recordType uint16) []byte {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(name, recordType)
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func dnsAnswer(t *testing.T, wire []byte) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	if err := message.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestDomainRoutingAndFakeDNS(t *testing.T) {
	for host, expected := range map[string]bool{
		"ru": true, "Example.RU.": true, "a.b.yandex.net": true, "a.xn--p1ai": true,
		"notru": false, "example.ru.evil": false, "notyandex.net": false, "example.com": false,
	} {
		if russianDomain(host) != expected {
			t.Fatalf("Unexpected routing for %q", host)
		}
	}
	d := newDNSResolver(&Engine{config: mobileConfig{Routing: "RUSSIAN_DIRECT"}})
	defer d.close()
	for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
		query := dnsQuery(t, "Example.RU.", kind)
		wire, err := d.exchange(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		response := dnsAnswer(t, wire)
		if response.Rcode != dns.RcodeSuccess || response.Id != dnsAnswer(t, query).Id || len(response.Answer) != 1 {
			t.Fatal("Fake DNS response is incomplete")
		}
		var address string
		switch answer := response.Answer[0].(type) {
		case *dns.A:
			address = answer.A.String()
			if !fakeIPv4.Contains(mustAddr(t, address)) {
				t.Fatal("IPv4 fake address escaped its pool")
			}
		case *dns.AAAA:
			address = answer.AAAA.String()
			if !fakeIPv6.Contains(mustAddr(t, address)) {
				t.Fatal("IPv6 fake address escaped its pool")
			}
		}
		if name, ok := d.lookupFake(address); !ok || name != "example.ru" {
			t.Fatal("Fake DNS reverse mapping is missing")
		}
	}
	wire, err := d.exchange(context.Background(), dnsQuery(t, "example.ru.", dns.TypeHTTPS))
	if err != nil {
		t.Fatal(err)
	}
	if len(dnsAnswer(t, wire).Answer) != 0 {
		t.Fatal("HTTPS hints must not bypass the fake address policy")
	}
}

func TestFakeDNSCapacityAndExpiry(t *testing.T) {
	d := newDNSResolver(&Engine{})
	defer d.close()
	first, err := d.fakeForDomain("first.ru")
	if err != nil {
		t.Fatal(err)
	}
	oldIP := first.ipv4.String()
	for i := 1; i < maximumFakeNames; i++ {
		if _, err := d.fakeForDomain(fmt.Sprintf("n%d.ru", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.fakeForDomain("overflow.ru"); err == nil {
		t.Fatal("Live fake mappings must not be evicted")
	}
	d.mu.Lock()
	first.expires = time.Now().Add(time.Second)
	d.mu.Unlock()
	if _, ok := d.lookupFake(oldIP); !ok {
		t.Fatal("An active fake mapping was lost")
	}
	d.mu.Lock()
	refreshedExpiry := first.expires
	d.mu.Unlock()
	if time.Until(refreshedExpiry) < 4*time.Minute {
		t.Fatal("Active UDP traffic did not extend the fake mapping lifetime")
	}
	d.mu.Lock()
	first.expires = time.Now().Add(-time.Second)
	d.mu.Unlock()
	if _, ok := d.lookupFake(oldIP); ok {
		t.Fatal("Expired fake mapping was accepted")
	}
	next, err := d.fakeForDomain("overflow.ru")
	if err != nil {
		t.Fatal(err)
	}
	if next.ipv4 == first.ipv4 || next.ipv6 == first.ipv6 {
		t.Fatal("Expired numeric addresses must not be reassigned")
	}
	if len(d.byDomain) != maximumFakeNames || len(d.byIP) != maximumFakeNames*2 {
		t.Fatal("Fake DNS tables are not bounded")
	}
}

func TestDNSForwardingAndResponseValidation(t *testing.T) {
	d := newDNSResolver(&Engine{config: mobileConfig{Routing: "ALL"}})
	defer d.close()
	query := dnsQuery(t, "example.com.", dns.TypeA)
	question := dnsAnswer(t, query)
	response := new(dns.Msg)
	response.SetReply(question)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
	pack := func() string {
		wire, err := response.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return string(wire)
	}
	payload := pack()
	calls := 0
	d.remote.Transport = dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.String() != "https://1.1.1.1/dns-query" || request.Header.Get("Content-Type") != "application/dns-message" {
			t.Fatal("Unexpected DoH endpoint or content type")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != string(query) {
			t.Fatal("The original DNS query was changed")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})
	wire, err := d.exchange(context.Background(), query)
	if err != nil || len(dnsAnswer(t, wire).Answer) != 1 || calls != 1 {
		t.Fatal("Ordinary DNS was not forwarded")
	}
	response.Id++
	payload = pack()
	if _, err := d.exchange(context.Background(), query); err == nil {
		t.Fatal("A response with the wrong transaction ID was accepted")
	}
	response.Id = question.Id
	response.Question[0].Name = "different.example."
	payload = pack()
	if _, err := d.exchange(context.Background(), query); err == nil {
		t.Fatal("A response for another name was accepted")
	}
	if _, err := d.exchange(context.Background(), []byte("invalid")); err == nil {
		t.Fatal("Malformed DNS was accepted")
	}
}

func TestDirectResolutionDoesNotAllocateFakeIPs(t *testing.T) {
	d := newDNSResolver(&Engine{config: mobileConfig{Routing: "RUSSIAN_DIRECT"}})
	defer d.close()
	calls := 0
	d.direct.Transport = dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		question := dnsAnswer(t, wire)
		response := new(dns.Msg)
		response.SetReply(question)
		if question.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.ru.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.2")}}
		} else {
			response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "example.ru.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::2")}}
		}
		answer, err := response.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(answer))), Header: make(http.Header)}, nil
	})
	addresses, err := d.resolveDirect(context.Background(), "example.ru")
	if err != nil || len(addresses) != 2 || calls != 2 {
		t.Fatal("Direct resolution did not preserve both address families")
	}
	if len(d.byDomain) != 0 {
		t.Fatal("Direct DNS allocated fake addresses")
	}
	addresses, err = d.resolveDirect(context.Background(), "2001:db8::3")
	if err != nil || len(addresses) != 1 || calls != 2 {
		t.Fatal("Numeric address resolution unexpectedly used DNS")
	}
}

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func TestConfigValidationDoesNotExposeCredentials(t *testing.T) {
	valid := mobileConfig{Profile: profile{Version: 1, Name: "Example", Server: "vpn.example", Port: 443, Password: "private-password-token", ServerName: "vpn.example"}, Routing: "ALL"}
	encode := func(value mobileConfig) string {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(wire)
	}
	if err := Validate(encode(valid)); err != nil {
		t.Fatal("A supported profile was rejected")
	}
	invalidCert := valid
	invalidCert.Profile.Certificate = "private-certificate-token"
	invalidMode := valid
	invalidMode.Routing = "INVALID"
	missingPassword := valid
	missingPassword.Profile.Password = ""
	for _, value := range []mobileConfig{invalidCert, invalidMode, missingPassword} {
		err := Validate(encode(value))
		if err == nil {
			t.Fatal("Invalid configuration was accepted")
		}
		if strings.Contains(err.Error(), "private-password-token") || strings.Contains(err.Error(), "private-certificate-token") {
			t.Fatal("Configuration validation exposed a credential")
		}
	}
}

func newTestEngine(t *testing.T, routing string) *Engine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{config: mobileConfig{Routing: routing}, ctx: ctx, cancel: cancel, flows: make(map[io.Closer]struct{})}
	e.generation.Store(1)
	e.dns = newDNSResolver(e)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestDestinationRoutingAndUnknownFakeIP(t *testing.T) {
	e := newTestEngine(t, "RUSSIAN_DIRECT")
	for _, tc := range []struct {
		host   string
		direct bool
	}{{"example.ru", true}, {"nested.YANDEX.NET.", true}, {"example.ru.evil", false}, {"192.168.1.2", true}, {"fd12::1", true}, {"1.1.1.1", false}} {
		_, direct, err := e.destination(tc.host, 443)
		if err != nil || direct != tc.direct {
			t.Fatalf("Unexpected destination policy for %q", tc.host)
		}
	}
	for _, unknown := range []string{"198.18.1.2", "fc00::1234"} {
		if _, _, err := e.destination(unknown, 443); err == nil {
			t.Fatal("An unknown fake IP was routed")
		}
	}
	entry, err := e.dns.fakeForDomain("example.ru")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{entry.ipv4.String(), entry.ipv6.String()} {
		address, direct, err := e.destination(ip, 443)
		if err != nil || !direct || address != "example.ru:443" {
			t.Fatal("Fake IP did not retain its domain bypass policy")
		}
	}
	all := newTestEngine(t, "ALL")
	if _, direct, err := all.destination("example.ru", 443); err != nil || direct {
		t.Fatal("Full-tunnel mode bypassed a public domain")
	}
}

func TestTCPDNSInterceptionAndFlowShutdown(t *testing.T) {
	e := newTestEngine(t, "RUSSIAN_DIRECT")
	conn, err := (&routedClient{engine: e}).TCP("172.19.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	query := dnsQuery(t, "example.ru.", dns.TypeA)
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, int(binary.BigEndian.Uint16(header[:])))
	if _, err := io.ReadFull(conn, answer); err != nil {
		t.Fatal(err)
	}
	if message := dnsAnswer(t, answer); message.Rcode != dns.RcodeSuccess || len(message.Answer) != 1 {
		t.Fatal("TCP DNS did not use the local routing policy")
	}
	entry := e.dns.byDomain["example.ru"]
	e.generation.Add(1)
	e.closeFlows()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Closing old flows did not unblock a DNS reader")
	}
	if domain, ok := e.dns.lookupFake(entry.ipv4.String()); !ok || domain != "example.ru" {
		t.Fatal("Closing old transport flows discarded DNS cache mappings")
	}
	local, peer := net.Pipe()
	defer peer.Close()
	if _, err := e.trackConn(local, false, 1); err == nil {
		t.Fatal("A flow from the previous transport generation was accepted")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal("Closing the engine twice failed")
	}
	e.flowMu.Lock()
	remaining := len(e.flows)
	e.flowMu.Unlock()
	if remaining != 0 {
		t.Fatal("Closed flows remained registered")
	}
}

type fragmentedSniffConn struct {
	net.Conn
	mu      sync.Mutex
	payload []byte
}

func (c *fragmentedSniffConn) Write(buffer []byte) (int, error) {
	c.mu.Lock()
	c.payload = append(c.payload, buffer...)
	c.mu.Unlock()
	total := 0
	for len(buffer) > 0 {
		next := 17
		if len(buffer) < next {
			next = len(buffer)
		}
		n, err := c.Conn.Write(buffer[:next])
		total += n
		if err != nil {
			return total, err
		}
		buffer = buffer[n:]
	}
	return total, nil
}

func (c *fragmentedSniffConn) original() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.payload...)
}

func TestTrafficSniffingPreservesClientBytes(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		original := []byte("GET / HTTP/1.1\r\nHost: Example.RU:443\r\nUser-Agent: test\r\n\r\n")
		done := make(chan error, 1)
		go func() { _, err := client.Write(original); done <- err }()
		payload, host := sniffDestination(server)
		if host != "example.ru" || !bytes.Equal(payload, original) {
			t.Fatal("HTTP classification changed client bytes or lost Host")
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("HTTP writer did not complete")
		}
	})
	t.Run("FragmentedTLS", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		fragmented := &fragmentedSniffConn{Conn: client}
		secure := tls.Client(fragmented, &tls.Config{ServerName: "Example.RU", MinVersion: tls.VersionTLS12})
		done := make(chan error, 1)
		go func() { done <- secure.Handshake() }()
		payload, host := sniffDestination(server)
		if host != "example.ru" || len(payload) == 0 || !bytes.Equal(payload, fragmented.original()) {
			t.Fatal("Fragmented ClientHello was not preserved with its SNI")
		}
		_ = client.Close()
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("TLS classifier left a blocked client")
		}
	})
}
