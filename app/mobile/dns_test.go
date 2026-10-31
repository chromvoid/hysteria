// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
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
	e := newTestEngine(t, "RUSSIAN_DIRECT")
	for host, expected := range map[string]bool{
		"ru": true, "Example.RU.": true, "a.b.yandex.net": true, "a.xn--p1ai": true,
		"notru": false, "example.ru.evil": false, "notyandex.net": false, "example.com": false,
	} {
		if e.config.Rules.direct(host) != expected {
			t.Fatalf("Unexpected routing for %q", host)
		}
	}
	d := e.dns
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

func TestConfiguredDNSRoutingInBothModes(t *testing.T) {
	for _, mode := range []string{"ALL", "RUSSIAN_DIRECT"} {
		for _, tc := range []struct {
			name  string
			host  string
			rules routingRules
			fake  bool
		}{
			{"suffix", "bank.example", routingRules{DirectSuffix: []string{"bank.example"}}, true},
			{"exact", "bank.example", routingRules{DirectDomain: []string{"bank.example"}}, true},
			{"empty", "bank.example", routingRules{}, false},
			{"proxy-only", "bank.example", routingRules{ProxySuffix: []string{"bank.example"}}, false},
			{"proxy-in-suffix", "news.bank.example", routingRules{ProxySuffix: []string{"news.bank.example"}, DirectSuffix: []string{"bank.example"}}, false},
			{"proxy-over-exact", "bank.example", routingRules{ProxySuffix: []string{"bank.example"}, DirectDomain: []string{"bank.example"}}, false},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				e := newTestEngine(t, mode)
				if err := tc.rules.compile(); err != nil {
					t.Fatal(err)
				}
				e.config.Rules = &tc.rules
				calls := 0
				e.dns.remote.Transport = dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls++
					wire, err := io.ReadAll(request.Body)
					if err != nil {
						t.Fatal(err)
					}
					response := new(dns.Msg)
					response.SetReply(dnsAnswer(t, wire))
					response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: tc.host + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
					answer, err := response.Pack()
					if err != nil {
						t.Fatal(err)
					}
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(answer)), Header: make(http.Header)}, nil
				})
				wire, err := e.dns.exchange(e.ctx, dnsQuery(t, tc.host+".", dns.TypeA))
				if err != nil {
					t.Fatal(err)
				}
				response := dnsAnswer(t, wire)
				if len(response.Answer) != 1 {
					t.Fatal("Expected one DNS address")
				}
				address := response.Answer[0].(*dns.A).A.String()
				if fakeIPv4.Contains(mustAddr(t, address)) != tc.fake || (calls == 0) != tc.fake {
					t.Fatalf("Unexpected DNS route: address=%s, remote calls=%d, want fake=%v", address, calls, tc.fake)
				}
			})
		}
	}
}

func TestSharedRoutingDecisions(t *testing.T) {
	wire, err := os.ReadFile("testdata/routing-decisions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name  string
		Rules routingRules
		Cases []struct{ Host, Expected string }
	}
	if err := json.Unmarshal(wire, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if err := fixture.Rules.compile(); err != nil {
				t.Fatal(err)
			}
			for _, tc := range fixture.Cases {
				got := "proxy"
				if fixture.Rules.direct(tc.Host) {
					got = "direct"
				}
				if got != tc.Expected {
					t.Errorf("Route for %q = %s, want %s", tc.Host, got, tc.Expected)
				}
			}
		})
	}
}

func BenchmarkRoutingDecision4000(b *testing.B) {
	rules := &routingRules{DirectDomain: []string{"exact.example"}}
	for i := 0; i < 2000; i++ {
		rules.DirectSuffix = append(rules.DirectSuffix, fmt.Sprintf("site%d.example", i))
	}
	for i := 0; i < 1999; i++ {
		rules.ProxySuffix = append(rules.ProxySuffix, fmt.Sprintf("blocked%d.example", i))
	}
	if err := rules.compile(); err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		host   string
		direct bool
	}{{"m.site1999.example", true}, {"m.blocked1998.example", false}, {"exact.example", true}, {"unlisted.example", false}} {
		b.Run(tc.host, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if rules.direct(tc.host) != tc.direct {
					b.Fatal("Unexpected route")
				}
			}
		})
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
	d := newTestEngine(t, "ALL").dns
	d.direct.Transport = dnsRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("Proxied DNS used a direct resolver")
		return nil, nil
	})
	d.directFallback.Transport = d.direct.Transport
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
	d := newTestEngine(t, "RUSSIAN_DIRECT").dns
	for _, tc := range []struct {
		client     *http.Client
		serverName string
	}{{d.direct, "common.dot.dns.yandex.net"}, {d.directFallback, "cloudflare-dns.com"}, {d.remote, "cloudflare-dns.com"}} {
		config := tc.client.Transport.(*http.Transport).TLSClientConfig
		if config.ServerName != tc.serverName || config.InsecureSkipVerify {
			t.Fatalf("Unexpected DoH TLS configuration for %s", tc.serverName)
		}
	}
	d.directFallback.Transport = dnsRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("Cloudflare was contacted after a Yandex answer")
		return nil, nil
	})
	d.remote.Transport = d.directFallback.Transport
	calls := 0
	d.direct.Transport = dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.String() != "https://77.88.8.8/dns-query" || request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/dns-message" {
			t.Fatal("Unexpected direct DoH endpoint, method or content type")
		}
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
	for _, host := range []string{"192.0.2.2", "2001:db8::3"} {
		addresses, err = d.resolvePhysical(context.Background(), host)
		if err != nil || len(addresses) == 0 || calls != 2 {
			t.Fatal("Physical numeric resolution unexpectedly used DNS")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.resolvePhysical(ctx, "192.0.2.2"); !errors.Is(err, context.Canceled) {
		t.Fatal("Physical address resolution ignored cancellation")
	}
}

func TestDirectDNSFallback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		results    [3]string
		wantHosts  []string
		wantAnswer bool
	}{
		{"cloudflare", [3]string{"servfail", "transport", "answer"}, []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"}, true},
		{"nxdomain", [3]string{"nxdomain"}, []string{"77.88.8.8"}, false},
		{"empty", [3]string{"empty"}, []string{"77.88.8.8"}, false},
		{"all-fail", [3]string{"servfail", "transport", "refused"}, []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"}, false},
		{"refused-and-http", [3]string{"refused", "http", "answer"}, []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"}, true},
		{"invalid-responses", [3]string{"wrong-id", "wrong-opcode", "wrong-question"}, []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestEngine(t, "RUSSIAN_DIRECT").dns
			calls := make(map[uint16][]string)
			respond := dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				host := request.URL.Host
				if request.URL.String() != "https://"+host+"/dns-query" || request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/dns-message" {
					t.Fatal("Unexpected direct DoH endpoint, method or content type")
				}
				wire, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				question := dnsAnswer(t, wire)
				kind := question.Question[0].Qtype
				calls[kind] = append(calls[kind], host)
				index := -1
				for i, endpoint := range []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"} {
					if host == endpoint {
						index = i
					}
				}
				if index < 0 {
					t.Fatalf("Unexpected DNS resolver %s", host)
				}
				response := new(dns.Msg)
				response.SetReply(question)
				switch tc.results[index] {
				case "answer":
					header := dns.RR_Header{Name: "example.ru.", Rrtype: kind, Class: dns.ClassINET, Ttl: 60}
					if kind == dns.TypeA {
						response.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.2")}}
					} else {
						response.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::2")}}
					}
				case "servfail":
					response.Rcode = dns.RcodeServerFailure
				case "refused":
					response.Rcode = dns.RcodeRefused
				case "nxdomain":
					response.Rcode = dns.RcodeNameError
				case "empty":
				case "transport":
					return nil, errors.New("Test DNS transport failure.")
				case "http":
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(""))}, nil
				case "wrong-id":
					response.Id++
				case "wrong-opcode":
					response.Opcode = dns.OpcodeStatus
				case "wrong-question":
					response.Question[0].Name = "different.example."
				default:
					t.Fatalf("Unexpected fallback to %s", host)
				}
				answer, err := response.Pack()
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(answer))}, nil
			})
			d.direct.Transport = dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host == "1.1.1.1" {
					t.Fatal("Cloudflare used the Yandex client")
				}
				return respond(request)
			})
			d.directFallback.Transport = dnsRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host != "1.1.1.1" {
					t.Fatal("Yandex used the Cloudflare client")
				}
				return respond(request)
			})
			d.remote.Transport = dnsRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("Direct DNS used the remote resolver")
				return nil, nil
			})
			addresses, err := d.resolveDirect(context.Background(), "example.ru")
			if tc.wantAnswer {
				if err != nil || len(addresses) != 2 || addresses[0].IP.String() != "192.0.2.2" || addresses[1].IP.String() != "2001:db8::2" {
					t.Fatalf("Direct addresses = %v, error = %v", addresses, err)
				}
			} else if err == nil || err.Error() != "DNS resolution failed." || len(addresses) != 0 {
				t.Fatalf("Failed direct resolution returned %v, %v", addresses, err)
			}
			for _, kind := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if strings.Join(calls[kind], ",") != strings.Join(tc.wantHosts, ",") {
					t.Fatalf("%s resolver order = %v, want %v", dns.TypeToString[kind], calls[kind], tc.wantHosts)
				}
			}
		})
	}
}

func TestDirectDNSUsesHTTP2(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "HTTP/2 required.", http.StatusHTTPVersionNotSupported)
			return
		}
		requests.Add(1)
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(query)
		question := query.Question[0]
		header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
		if question.Qtype == dns.TypeA {
			answer.Answer = []dns.RR{&dns.A{Hdr: header, A: net.ParseIP("192.0.2.2")}}
		} else {
			answer.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::2")}}
		}
		payload, err := answer.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(payload)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	d := newTestEngine(t, "RUSSIAN_DIRECT").dns
	transport := d.direct.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		if addr != "77.88.8.8:443" {
			t.Errorf("Direct DoH destination = %q", addr)
			return nil, errors.New("Unexpected direct DoH destination.")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = server.Listener.Addr().(*net.TCPAddr).IP.String()
	d.directFallback.Transport = dnsRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("Direct HTTP/2 resolution used Cloudflare")
		return nil, errors.New("Unexpected Cloudflare request.")
	})
	d.remote.Transport = d.directFallback.Transport
	addresses, err := d.resolveDirect(context.Background(), "example.ru")
	if err != nil || len(addresses) != 2 || addresses[0].IP.String() != "192.0.2.2" || addresses[1].IP.String() != "2001:db8::2" || requests.Load() != 2 {
		t.Fatalf("Direct HTTP/2 addresses = %v, error = %v, requests = %d", addresses, err, requests.Load())
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
	valid := mobileConfig{Profile: profile{Version: 1, Name: "Example", Server: "vpn.example", Port: 443, Password: "private-password-token", ServerName: "vpn.example"}, Routing: "ALL", Rules: &routingRules{ProxySuffix: []string{}, DirectSuffix: []string{}, DirectDomain: []string{}}}
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

func TestRoutingRulesValidation(t *testing.T) {
	const base = `{"profile":{"version":1,"server":"vpn.example","server_port":443,"password":"secret"},"routing":"ALL"`
	config := func(rules string) string {
		if rules == "" {
			return base + "}"
		}
		return base + `,"rules":` + rules + "}"
	}
	check := func(t *testing.T, text string, invalid bool) {
		t.Helper()
		err := Validate(text)
		if (err != nil) != invalid {
			t.Fatalf("Validate error = %v, want invalid=%v", err, invalid)
		}
		if invalid {
			_, startErr := Start(text, nil)
			if startErr == nil || startErr.Error() != err.Error() {
				t.Fatalf("Start error = %v, want %v", startErr, err)
			}
		}
	}
	for _, tc := range []struct {
		name    string
		rules   string
		invalid bool
	}{
		{"missing-rules", "", true},
		{"null-rules", "null", true},
		{"empty-rules", "{}", false},
		{"unknown-field", `{"direct_suffix":[],"unknown":[]}`, true},
		{"rules-not-object", `[]`, true},
		{"suffix-not-array", `{"direct_suffix":"bank.example"}`, true},
		{"null-array", `{"direct_domain":null}`, true},
		{"non-string-entry", `{"proxy_suffix":[1]}`, true},
		{"single-label-exact", `{"direct_domain":["ru"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, config(tc.rules), tc.invalid) })
	}
	for _, field := range []string{"proxy_suffix", "direct_suffix"} {
		for _, name := range []string{"ru", "su", "xn--p1ai", "com", "example"} {
			t.Run(field+"/"+name, func(t *testing.T) {
				check(t, config(fmt.Sprintf(`{%q:[%q]}`, field, name)), name == "com" || name == "example")
			})
		}
	}
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tc := range []struct {
		name    string
		host    string
		invalid bool
	}{
		{"ascii-labels", "a0-b1.example", false},
		{"punycode", "xn--e1afmkfd.xn--p1ai", false},
		{"253-bytes", longest, false},
		{"254-bytes", longest + "d", true},
		{"empty", "", true},
		{"uppercase", "Bank.example", true},
		{"non-ascii", "пример.рф", true},
		{"invalid-character", "bank_name.example", true},
		{"empty-label", "bank..example", true},
		{"long-label", strings.Repeat("a", 64) + ".example", true},
		{"leading-hyphen", "-bank.example", true},
		{"trailing-hyphen", "bank-.example", true},
		{"leading-dot", ".bank.example", true},
		{"trailing-dot", "bank.example.", true},
		{"wildcard", "*.example", true},
		{"ipv4", "192.0.2.1", true},
		{"ipv6", "2001:db8::1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := json.Marshal([]string{tc.host})
			if err != nil {
				t.Fatal(err)
			}
			check(t, config(`{"direct_suffix":`+string(wire)+`}`), tc.invalid)
		})
	}
	// Count all entries, including duplicates within and across arrays.
	rules := routingRules{ProxySuffix: []string{}, DirectSuffix: []string{}, DirectDomain: []string{}}
	for i := 0; i < 4000; i++ {
		target := []*[]string{&rules.ProxySuffix, &rules.DirectSuffix, &rules.DirectDomain}[i%3]
		*target = append(*target, "same.example")
	}
	for _, count := range []int{4000, 4001} {
		t.Run(fmt.Sprintf("%d-entries", count), func(t *testing.T) {
			if count == 4001 {
				rules.DirectDomain = append(rules.DirectDomain, "same.example")
			}
			wire, err := json.Marshal(rules)
			if err != nil {
				t.Fatal(err)
			}
			check(t, config(string(wire)), count > 4000)
		})
	}
	parsed, err := parseConfig(config(`{"direct_suffix":["bank.example"]}`))
	if err != nil || len(parsed.Rules.ProxySuffix) != 0 || len(parsed.Rules.DirectDomain) != 0 {
		t.Fatalf("Omitted arrays must be empty: %v", err)
	}
	for _, size := range []int{131073, 262144, 262145} {
		t.Run(fmt.Sprintf("%d-bytes", size), func(t *testing.T) {
			text := config("{}")
			text += strings.Repeat(" ", size-len(text))
			check(t, text, size > 262144)
		})
	}
}

func newTestEngine(t *testing.T, routing string) *Engine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rules := &routingRules{}
	if routing == "RUSSIAN_DIRECT" {
		rules.DirectSuffix = []string{"ru", "su", "xn--p1ai", "yandex.net", "yastatic.net", "vk.com", "userapi.com"}
	}
	if err := rules.compile(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{config: mobileConfig{Routing: routing, Rules: rules}, ctx: ctx, cancel: cancel, flows: make(map[io.Closer]struct{})}
	e.generation.Store(1)
	e.download.started = time.Now()
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

type rejectingPlatform struct{ called chan struct{} }

func (p *rejectingPlatform) ProtectSocket(int64) error {
	p.called <- struct{}{}
	return errors.New("Test socket protection rejection.")
}

func TestALLModeSniffedSNIUsesDirectTCP(t *testing.T) {
	e := newTestEngine(t, "ALL")
	e.config.Rules = &routingRules{DirectSuffix: []string{"bank.example"}}
	if err := e.config.Rules.compile(); err != nil {
		t.Fatal(err)
	}
	platform := &rejectingPlatform{called: make(chan struct{}, 1)}
	e.platform = platform
	conn, err := (&routedClient{engine: e}).TCP("192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	secure := tls.Client(conn, &tls.Config{ServerName: "Bank.Example", MinVersion: tls.VersionTLS12})
	done := make(chan error, 1)
	go func() { done <- secure.Handshake() }()
	// Only directTCP invokes the physical socket protector. Rejecting there
	// proves SNI selected that path without opening an external connection.
	select {
	case <-platform.called:
	case <-time.After(2 * time.Second):
		t.Fatal("Sniffed SNI did not select the direct TCP socket")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("The test protector must stop the physical connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("The rejected direct dial left a blocked TLS client")
	}
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

type metricsClient struct {
	tcp func(context.Context, string) (net.Conn, error)
	udp client.HyUDPConn
}

func (c *metricsClient) TCP(addr string) (net.Conn, error) {
	return c.TCPContext(context.Background(), addr)
}
func (c *metricsClient) TCPContext(ctx context.Context, addr string) (net.Conn, error) {
	return c.tcp(ctx, addr)
}
func (c *metricsClient) UDP() (client.HyUDPConn, error) { return c.udp, nil }
func (c *metricsClient) Close() error                   { return nil }

type metricsConn struct {
	net.Conn
	closed atomic.Bool
	reads  atomic.Int64
	writes atomic.Int64
}

func (c *metricsConn) Read(b []byte) (int, error) {
	c.reads.Add(int64(len(b)))
	return len(b), nil
}
func (c *metricsConn) Write(b []byte) (int, error) {
	c.writes.Add(int64(len(b)))
	return len(b), nil
}
func (c *metricsConn) Close() error { c.closed.Store(true); return nil }

func TestPing(t *testing.T) {
	e := newTestEngine(t, "ALL")
	if _, err := e.Ping(); err == nil || err.Error() == "" {
		t.Fatal("Ping without a transport must return a readable error")
	}
	conn := &metricsConn{}
	e.hy = &metricsClient{tcp: func(ctx context.Context, addr string) (net.Conn, error) {
		if addr != "1.1.1.1:443" {
			t.Fatalf("Ping destination = %q", addr)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second {
			t.Fatal("Ping must use a five-second deadline")
		}
		select {
		case <-time.After(20 * time.Millisecond):
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	milliseconds, err := e.Ping()
	if err != nil || milliseconds < 20 || milliseconds > 1000 {
		t.Fatalf("Ping = %d ms, %v; want the delayed TCP open", milliseconds, err)
	}
	if !conn.closed.Load() || conn.reads.Load() != 0 || conn.writes.Load() != 0 {
		t.Fatal("Ping must close its stream without transferring data")
	}
	if e.ProxyRxBytes() != 0 || e.ProxyTxBytes() != 0 || e.RxBytes() != 0 || e.TxBytes() != 0 || e.DownloadMedianBps() != 0 || e.DownloadPeakBps() != 0 {
		t.Fatal("Ping affected traffic or download statistics")
	}
	e.hy = &metricsClient{tcp: func(context.Context, string) (net.Conn, error) { return &metricsConn{}, nil }}
	if milliseconds, err := e.Ping(); err != nil || milliseconds < 1 {
		t.Fatalf("Immediate Ping = %d ms, %v; want at least 1 ms", milliseconds, err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ping(); err == nil || err.Error() == "" {
		t.Fatal("Ping after Close must return a readable error")
	}
}

func TestPingCancellation(t *testing.T) {
	e := newTestEngine(t, "ALL")
	started := make(chan struct{})
	e.hy = &metricsClient{tcp: func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() { _, err := e.Ping(); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Ping did not start opening a stream")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close did not cancel Ping")
		}
	case <-time.After(time.Second):
		t.Fatal("Ping remained blocked after Close")
	}
}

type metricsPacket struct{ net.PacketConn }

func (*metricsPacket) ReadFrom(b []byte) (int, net.Addr, error)  { return len(b), &net.UDPAddr{}, nil }
func (*metricsPacket) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

type metricsUDP struct {
	received chan udpResult
	done     chan struct{}
	once     sync.Once
}

func (c *metricsUDP) Receive() ([]byte, string, error) {
	select {
	case result := <-c.received:
		return result.data, result.addr, result.err
	case <-c.done:
		return nil, "", net.ErrClosed
	}
}
func (*metricsUDP) Send([]byte, string) error { return nil }
func (c *metricsUDP) Close() error            { c.once.Do(func() { close(c.done) }); return nil }

func TestProxyAndLegacyTrafficAccounting(t *testing.T) {
	e := newTestEngine(t, "ALL")
	udp := &metricsUDP{received: make(chan udpResult, 1), done: make(chan struct{})}
	e.hy = &metricsClient{tcp: func(context.Context, string) (net.Conn, error) { return &metricsConn{}, nil }, udp: udp}
	proxy, err := e.proxyTCPContext(e.ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if _, err := proxy.Read(make([]byte, 13)); err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.Write(make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	// Direct sockets contribute payload to the existing totals; accepted local
	// sockets and proxy TCP streams must not double-count the wire transport.
	for _, count := range []bool{true, false} {
		conn, err := e.trackConn(&metricsConn{}, count, e.generation.Load())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 11)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	packet := &trackedPacket{PacketConn: &metricsPacket{}, engine: e}
	if _, _, err := packet.ReadFrom(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo(make([]byte, 8), &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if e.RxBytes() != 27 || e.TxBytes() != 13 || e.ProxyRxBytes() != 13 || e.ProxyTxBytes() != 7 {
		t.Fatalf("TCP/wire accounting: legacy rx/tx=%d/%d, proxy rx/tx=%d/%d", e.RxBytes(), e.TxBytes(), e.ProxyRxBytes(), e.ProxyTxBytes())
	}
	session, err := (&routedClient{engine: e}).UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Send(make([]byte, 17), "example.com:443"); err != nil {
		t.Fatal(err)
	}
	// Sniffed UDP uses a second send path; it must share the same accounting.
	if err := session.(*routedUDP).sendClassified(make([]byte, 19), "1.1.1.1:443", "1.1.1.1:443", false); err != nil {
		t.Fatal(err)
	}
	udp.received <- udpResult{data: make([]byte, 23), addr: "example.com:443"}
	received := make(chan error, 1)
	go func() { _, _, err := session.Receive(); received <- err }()
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Proxy UDP did not deliver its payload")
	}
	if e.RxBytes() != 27 || e.TxBytes() != 13 || e.ProxyRxBytes() != 36 || e.ProxyTxBytes() != 43 {
		t.Fatalf("UDP accounting: legacy rx/tx=%d/%d, proxy rx/tx=%d/%d", e.RxBytes(), e.TxBytes(), e.ProxyRxBytes(), e.ProxyTxBytes())
	}
}

type metricsRecordingConn struct {
	net.Conn
	rx, tx *atomic.Int64
}

func (c metricsRecordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.rx.Add(int64(n))
	return n, err
}
func (c metricsRecordingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.tx.Add(int64(n))
	return n, err
}

func TestProxyTrafficIncludesDoH(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(query)
		payload, err := answer.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	e := newTestEngine(t, "ALL")
	var rx, tx atomic.Int64
	e.hy = &metricsClient{tcp: func(ctx context.Context, addr string) (net.Conn, error) {
		if addr != "1.1.1.1:443" {
			t.Errorf("DoH destination = %q", addr)
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return metricsRecordingConn{Conn: conn, rx: &rx, tx: &tx}, nil
	}}
	transport := e.dns.remote.Transport.(*http.Transport)
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = server.Listener.Addr().(*net.TCPAddr).IP.String()
	query := dnsQuery(t, "example.com.", dns.TypeA)
	if _, err := e.dns.exchange(e.ctx, query); err != nil {
		t.Fatal(err)
	}
	e.dns.close()
	if e.ProxyRxBytes() != rx.Load() || e.ProxyTxBytes() != tx.Load() || e.ProxyRxBytes() <= int64(len(query)) || e.ProxyTxBytes() <= int64(len(query)) {
		t.Fatalf("DoH proxy rx/tx=%d/%d, stream rx/tx=%d/%d", e.ProxyRxBytes(), e.ProxyTxBytes(), rx.Load(), tx.Load())
	}
	if e.RxBytes() != 0 || e.TxBytes() != 0 {
		t.Fatal("DoH payload changed legacy wire accounting")
	}
}

func BenchmarkProxyReadAccounting(b *testing.B) {
	var buffer [4096]byte
	b.Run("baseline", func(b *testing.B) {
		conn := &metricsConn{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = conn.Read(buffer[:])
		}
	})
	b.Run("proxy", func(b *testing.B) {
		e := &Engine{}
		e.download.started = time.Now()
		conn := &trackedConn{Conn: &metricsConn{}, engine: e, proxy: true}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = conn.Read(buffer[:])
		}
	})
}

func TestDownloadActiveSeconds(t *testing.T) {
	e := newTestEngine(t, "ALL")
	var second int64
	e.download.clock = func() int64 { return second }
	if e.DownloadMedianBps() != 0 || e.DownloadPeakBps() != 0 {
		t.Fatal("An engine without active seconds must report zero speeds")
	}
	e.recordProxyRead(64*1024 - 1)
	second = 100
	if e.DownloadMedianBps() != 0 || e.DownloadPeakBps() != 0 {
		t.Fatal("A second below 64 KiB must not affect download statistics")
	}
	for _, rate := range []int64{1_000_000, 2_000_000, 2_000_000, 3_000_000, 100_000_000} {
		e.recordProxyRead(rate)
		second++
	}
	median, peak := e.DownloadMedianBps(), e.DownloadPeakBps()
	if median < 1_800_000 || median > 2_200_000 || peak != 100_000_000 {
		t.Fatalf("Download median/peak = %d/%d B/s, want approximately 2000000/100000000", median, peak)
	}
	second += 10000
	e.recordProxyRead(1)
	second++
	if e.DownloadMedianBps() != median || e.DownloadPeakBps() != peak {
		t.Fatal("Idle gaps and inactive seconds changed download statistics")
	}
	t.Run("threshold", func(t *testing.T) {
		e := newTestEngine(t, "ALL")
		var second int64
		e.download.clock = func() int64 { return second }
		e.recordProxyRead(64 * 1024)
		second++
		median := e.DownloadMedianBps()
		if median < 64*1024 || median > 64*1024*11/10 || e.DownloadPeakBps() != 64*1024 {
			t.Fatalf("Threshold median/peak = %d/%d B/s", median, e.DownloadPeakBps())
		}
	})
	t.Run("overflow-bin", func(t *testing.T) {
		e := newTestEngine(t, "ALL")
		var second int64
		e.download.clock = func() int64 { return second }
		e.recordProxyRead(3_000_000_000)
		second++
		median := e.DownloadMedianBps()
		if median < 1_800_000_000 || median > 2_000_000_000 || e.DownloadPeakBps() != 3_000_000_000 {
			t.Fatalf("Overflow median/peak = %d/%d B/s", median, e.DownloadPeakBps())
		}
	})
}

func TestConcurrentProxyReadAccounting(t *testing.T) {
	e := newTestEngine(t, "ALL")
	var second atomic.Int64
	e.download.clock = second.Load
	const streams, reads, bytes = 8, 1000, 4096
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < streams; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			conn := &trackedConn{Conn: &metricsConn{}, engine: e, proxy: true}
			var buffer [bytes]byte
			for i := 0; i < reads; i++ {
				_, _ = conn.Read(buffer[:])
			}
		}()
	}
	close(start)
	for i := 0; i < 100; i++ {
		second.Add(1)
		_ = e.DownloadMedianBps()
		_ = e.DownloadPeakBps()
		runtime.Gosched()
	}
	workers.Wait()
	second.Add(1)
	if e.ProxyRxBytes() != streams*reads*bytes {
		t.Fatalf("Parallel proxy reads = %d bytes, want %d", e.ProxyRxBytes(), streams*reads*bytes)
	}
	if e.DownloadMedianBps() == 0 || e.DownloadPeakBps() < 64*1024 {
		t.Fatal("Parallel active seconds were lost during rollovers")
	}
}
