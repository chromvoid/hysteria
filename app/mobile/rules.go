// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

var errInvalidRoutingRules = errors.New("Invalid VPN routing rules.")

type routingRules struct {
	ProxySuffix  []string `json:"proxy_suffix"`
	DirectSuffix []string `json:"direct_suffix"`
	DirectDomain []string `json:"direct_domain"`

	proxySuffix  map[string]struct{}
	directSuffix map[string]struct{}
	directDomain map[string]struct{}
}

func (r *routingRules) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errInvalidRoutingRules
	}
	*r = routingRules{}
	for name, data := range fields {
		var target *[]string
		switch name {
		case "proxy_suffix":
			target = &r.ProxySuffix
		case "direct_suffix":
			target = &r.DirectSuffix
		case "direct_domain":
			target = &r.DirectDomain
		default:
			return errInvalidRoutingRules
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, target) != nil {
			return errInvalidRoutingRules
		}
	}
	return nil
}

func (r *routingRules) compile() error {
	if r == nil {
		return errors.New("The VPN routing rules are required.")
	}
	if len(r.ProxySuffix)+len(r.DirectSuffix)+len(r.DirectDomain) > 4000 {
		return errors.New("The VPN routing rules exceed 4000 entries.")
	}
	for i, names := range [][]string{r.ProxySuffix, r.DirectSuffix, r.DirectDomain} {
		for _, name := range names {
			if !validRuleDomain(name) {
				return errors.New("A VPN routing rule has an invalid domain name.")
			}
			if !strings.Contains(name, ".") {
				if i == 2 {
					return errors.New("A VPN direct domain must contain at least two labels.")
				}
				if name != "ru" && name != "su" && name != "xn--p1ai" {
					return errors.New("A VPN routing suffix uses an unsupported single label.")
				}
			}
		}
	}
	r.proxySuffix = make(map[string]struct{}, len(r.ProxySuffix))
	r.directSuffix = make(map[string]struct{}, len(r.DirectSuffix))
	r.directDomain = make(map[string]struct{}, len(r.DirectDomain))
	for i, names := range [][]string{r.ProxySuffix, r.DirectSuffix, r.DirectDomain} {
		target := []map[string]struct{}{r.proxySuffix, r.directSuffix, r.directDomain}[i]
		for _, name := range names {
			target[name] = struct{}{}
		}
	}
	return nil
}

func validRuleDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func (r *routingRules) hasDirect() bool {
	return r != nil && (len(r.DirectSuffix) != 0 || len(r.DirectDomain) != 0)
}

func (r *routingRules) direct(host string) bool {
	host = normalizedDomain(host)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
	}
	if r == nil {
		return false
	}
	_, direct := r.directDomain[host]
	for suffix := host; ; {
		if _, proxy := r.proxySuffix[suffix]; proxy {
			return false
		}
		if _, match := r.directSuffix[suffix]; match {
			direct = true
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			return direct
		}
		suffix = suffix[dot+1:]
	}
}
