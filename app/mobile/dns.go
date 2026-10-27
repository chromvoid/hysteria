// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maximumDNSMessage   = 65535
	maximumFakeNames    = 8192
	fakeAnswerTTL       = 60
	fakeMappingLifetime = 5 * time.Minute
)

var russianSuffixes = []string{"ru", "su", "xn--p1ai", "yandex.net", "yastatic.net", "vk.com", "userapi.com"}
var fakeIPv4 = netip.MustParsePrefix("198.18.0.0/15")
var fakeIPv6 = netip.MustParsePrefix("fc00::/18")

type fakeName struct {
	domain  string
	ipv4    netip.Addr
	ipv6    netip.Addr
	expires time.Time
}

type dnsResolver struct {
	engine   *Engine
	remote   *http.Client
	direct   *http.Client
	mu       sync.Mutex
	byDomain map[string]*fakeName
	byIP     map[netip.Addr]*fakeName
	next     uint32
}

func newDNSResolver(e *Engine) *dnsResolver {
	d := &dnsResolver{engine: e, byDomain: make(map[string]*fakeName), byIP: make(map[netip.Addr]*fakeName), next: 1}
	d.remote = dohClient(e.proxyTCPContext)
	d.direct = dohClient(e.directTCP)
	return d
}

func dohClient(dial func(context.Context, string) (net.Conn, error)) *http.Client {
	transport := &http.Transport{
		DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return dial(ctx, addr) },
		TLSClientConfig:     &tls.Config{ServerName: "cloudflare-dns.com", MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (d *dnsResolver) close() {
	d.remote.CloseIdleConnections()
	d.direct.CloseIdleConnections()
}

func normalizedDomain(host string) string { return strings.TrimSuffix(strings.ToLower(host), ".") }

func russianDomain(host string) bool {
	host = normalizedDomain(host)
	for _, suffix := range russianSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func (d *dnsResolver) exchange(ctx context.Context, query []byte) ([]byte, error) {
	request, err := parseDNSQuery(query)
	if err != nil {
		return nil, err
	}
	question := request.Question[0]
	if d.engine.config.Routing == "RUSSIAN_DIRECT" && russianDomain(question.Name) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			entry, err := d.fakeForDomain(question.Name)
			if err != nil {
				response.Rcode = dns.RcodeServerFailure
			} else {
				header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: fakeAnswerTTL}
				if question.Qtype == dns.TypeA {
					response.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IP(entry.ipv4.AsSlice())}}
				} else {
					response.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.IP(entry.ipv6.AsSlice())}}
				}
			}
		}
		return response.Pack()
	}
	return d.doh(ctx, d.remote, query, request)
}

func parseDNSQuery(query []byte) (*dns.Msg, error) {
	if len(query) == 0 || len(query) > maximumDNSMessage {
		return nil, errors.New("Invalid DNS message.")
	}
	message := new(dns.Msg)
	if message.Unpack(query) != nil || message.Response || message.Opcode != dns.OpcodeQuery || len(message.Question) != 1 || message.Question[0].Qclass != dns.ClassINET {
		return nil, errors.New("Unsupported DNS question.")
	}
	if _, ok := dns.IsDomainName(message.Question[0].Name); !ok {
		return nil, errors.New("Invalid DNS name.")
	}
	return message, nil
}

func (d *dnsResolver) doh(ctx context.Context, client *http.Client, query []byte, message *dns.Msg) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://1.1.1.1/dns-query", bytes.NewReader(query))
	if err != nil {
		return nil, errors.New("Could not create the DNS request.")
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("DNS transport failed.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("DNS resolver rejected the request.")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumDNSMessage+1))
	if err != nil || len(payload) > maximumDNSMessage {
		return nil, errors.New("Invalid DNS response.")
	}
	answer := new(dns.Msg)
	if answer.Unpack(payload) != nil || !answer.Response || answer.Id != message.Id || answer.Opcode != message.Opcode || len(answer.Question) != 1 {
		return nil, errors.New("Invalid DNS response.")
	}
	q, expected := answer.Question[0], message.Question[0]
	if normalizedDomain(q.Name) != normalizedDomain(expected.Name) || q.Qtype != expected.Qtype || q.Qclass != expected.Qclass {
		return nil, errors.New("DNS response does not match the question.")
	}
	return payload, nil
}

func (d *dnsResolver) fakeForDomain(domain string) (*fakeName, error) {
	domain = normalizedDomain(domain)
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry := d.byDomain[domain]; entry != nil {
		if now.Before(entry.expires) {
			entry.expires = now.Add(fakeMappingLifetime)
			return entry, nil
		}
		d.removeFakeLocked(entry)
	}
	if len(d.byDomain) >= maximumFakeNames {
		for _, entry := range d.byDomain {
			if !now.Before(entry.expires) {
				d.removeFakeLocked(entry)
			}
		}
	}
	if len(d.byDomain) >= maximumFakeNames || d.next >= (1<<17)-1 {
		return nil, errors.New("The DNS mapping pool is full.")
	}
	// Never reuse a numeric address during this engine's lifetime. A stale client
	// DNS cache must not send a connection to a different domain after expiry.
	value := d.next
	d.next++
	var ipv4 [4]byte
	binary.BigEndian.PutUint32(ipv4[:], uint32(198)<<24|uint32(18)<<16|value)
	var ipv6 [16]byte
	ipv6[0] = 0xfc
	binary.BigEndian.PutUint32(ipv6[12:], value)
	entry := &fakeName{domain: domain, ipv4: netip.AddrFrom4(ipv4), ipv6: netip.AddrFrom16(ipv6), expires: now.Add(fakeMappingLifetime)}
	d.byDomain[domain] = entry
	d.byIP[entry.ipv4] = entry
	d.byIP[entry.ipv6] = entry
	return entry, nil
}

func (d *dnsResolver) removeFakeLocked(entry *fakeName) {
	delete(d.byDomain, entry.domain)
	delete(d.byIP, entry.ipv4)
	delete(d.byIP, entry.ipv6)
}

func (d *dnsResolver) lookupFake(ip string) (string, bool) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry := d.byIP[address.Unmap()]
	if entry == nil {
		return "", false
	}
	now := time.Now()
	if !now.Before(entry.expires) {
		d.removeFakeLocked(entry)
		return "", false
	}
	entry.expires = now.Add(fakeMappingLifetime)
	return entry.domain, true
}

func (d *dnsResolver) resolveDirect(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	host = normalizedDomain(host)
	if _, ok := dns.IsDomainName(dns.Fqdn(host)); !ok || host == "" {
		return nil, errors.New("Invalid DNS name.")
	}
	var addresses []net.IPAddr
	for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(host), recordType)
		query, err := message.Pack()
		if err != nil {
			continue
		}
		payload, err := d.doh(ctx, d.direct, query, message)
		if err != nil {
			continue
		}
		answer := new(dns.Msg)
		if answer.Unpack(payload) != nil || answer.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, record := range answer.Answer {
			switch record := record.(type) {
			case *dns.A:
				addresses = append(addresses, net.IPAddr{IP: record.A})
			case *dns.AAAA:
				addresses = append(addresses, net.IPAddr{IP: record.AAAA})
			}
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("DNS resolution failed.")
	}
	return addresses, nil
}
