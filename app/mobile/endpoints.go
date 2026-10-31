// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

type endpoint struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Server       string `json:"server"`
	Port         int    `json:"server_port"`
	ServerName   string `json:"server_name,omitempty"`
	Password     string `json:"password,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	ShortID      string `json:"short_id,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Flow         string `json:"flow,omitempty"`
	Mux          bool   `json:"mux,omitempty"`
	Path         string `json:"path,omitempty"`
	Mode         string `json:"mode,omitempty"`
}

var errInvalidEndpoint = errors.New("Invalid VPN endpoint configuration")

func endpointFieldError(field, reason string) error {
	return fmt.Errorf("%w: %s %s.", errInvalidEndpoint, field, reason)
}

func (p *endpoint) UnmarshalJSON(wire []byte) error {
	type plain endpoint
	var value plain
	if err := json.Unmarshal(wire, &value); err != nil {
		var typeError *json.UnmarshalTypeError
		if errors.As(err, &typeError) {
			return endpointFieldError(typeError.Field, "has an invalid type")
		}
		return errInvalidEndpoint
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil || fields == nil {
		return errInvalidEndpoint
	}
	if value.Kind != "hysteria2" && value.Kind != "vless_reality" && value.Kind != "vless_xhttp" {
		return endpointFieldError("kind", "must be hysteria2, vless_reality or vless_xhttp")
	}
	for field, valueJSON := range fields {
		if string(valueJSON) == "null" {
			return endpointFieldError(field, "must not be null")
		}
		allowed := false
		switch field {
		case "id", "kind", "server", "server_port", "server_name":
			allowed = true
		case "password", "obfs_password", "certificate":
			allowed = value.Kind == "hysteria2"
		case "uuid", "public_key", "short_id", "fingerprint", "mux":
			allowed = value.Kind == "vless_reality" || value.Kind == "vless_xhttp"
		case "flow":
			allowed = value.Kind == "vless_reality"
		case "path", "mode":
			allowed = value.Kind == "vless_xhttp"
		}
		if !allowed {
			return endpointFieldError(field, "is not supported for this endpoint kind")
		}
	}
	*p = endpoint(value)
	return nil
}

func (c *mobileConfig) validateEndpoints() error {
	if len(c.Endpoints) == 0 {
		p := c.Profile
		c.Endpoints = []endpoint{{
			ID: "hysteria2", Kind: "hysteria2", Server: p.Server, Port: p.Port,
			ServerName: p.ServerName, Password: p.Password, ObfsPassword: p.ObfsPassword,
			Certificate: p.Certificate,
		}}
		return nil // The legacy profile was already validated by parseConfig.
	}
	ids := make(map[string]bool, len(c.Endpoints))
	for i := range c.Endpoints {
		p := &c.Endpoints[i]
		if p.ID == "" {
			return endpointFieldError("id", "is required")
		}
		if ids[p.ID] {
			return endpointFieldError("id", "must be unique")
		}
		ids[p.ID] = true
		if p.Server == "" || strings.ContainsAny(p.Server, "/\\\r\n\t ") || (strings.ContainsAny(p.Server, ":[]") && net.ParseIP(p.Server) == nil) {
			return endpointFieldError("server", "must be a hostname or IP address")
		}
		if p.Port < 1 || p.Port > 65535 {
			return endpointFieldError("server_port", "must be between 1 and 65535")
		}
		if strings.ContainsAny(p.ServerName, "/\\\r\n\t ") {
			return endpointFieldError("server_name", "must be a hostname")
		}
		switch p.Kind {
		case "hysteria2":
			if p.ServerName == "" {
				p.ServerName = p.Server
			}
			if p.Password == "" {
				return endpointFieldError("password", "is required")
			}
			if p.ObfsPassword != "" && len(p.ObfsPassword) < 4 {
				return endpointFieldError("obfs_password", "must contain at least 4 bytes")
			}
			if p.Certificate != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(p.Certificate)) {
				return endpointFieldError("certificate", "must contain a PEM certificate")
			}
		case "vless_reality", "vless_xhttp":
			if err := p.validateVLESS(); err != nil {
				return err
			}
		default:
			return endpointFieldError("kind", "must be hysteria2, vless_reality or vless_xhttp")
		}
	}
	return nil
}

func (p *endpoint) validateVLESS() error {
	if p.ServerName == "" {
		return endpointFieldError("server_name", "is required for REALITY")
	}
	if len(p.UUID) != 36 || p.UUID[8] != '-' || p.UUID[13] != '-' || p.UUID[18] != '-' || p.UUID[23] != '-' {
		return endpointFieldError("uuid", "must be a UUID")
	}
	if value, err := hex.DecodeString(strings.ReplaceAll(p.UUID, "-", "")); err != nil || len(value) != 16 {
		return endpointFieldError("uuid", "must be a UUID")
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(p.PublicKey)
	if err != nil || len(p.PublicKey) != 43 || len(publicKey) != 32 {
		return endpointFieldError("public_key", "must be a 32-byte base64url X25519 key")
	}
	if _, err := hex.DecodeString(p.ShortID); err != nil || len(p.ShortID) > 16 {
		return endpointFieldError("short_id", "must contain 0 to 16 hexadecimal characters with even length")
	}
	if p.Fingerprint == "" {
		p.Fingerprint = "firefox"
	}
	switch p.Fingerprint {
	case "chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized":
	default:
		return endpointFieldError("fingerprint", "is not supported")
	}
	if p.Mux {
		return endpointFieldError("mux", "must be false")
	}
	if p.Kind == "vless_reality" {
		if p.Flow != "" && p.Flow != "xtls-rprx-vision" {
			return endpointFieldError("flow", "must be empty or xtls-rprx-vision")
		}
	} else {
		if p.Path == "" || !strings.HasPrefix(p.Path, "/") || strings.ContainsAny(p.Path, "\r\n\t ?#") {
			return endpointFieldError("path", "must be an absolute HTTP path")
		}
		switch p.Mode {
		case "auto", "packet-up", "stream-up", "stream-one":
		default:
			return endpointFieldError("mode", "must be auto, packet-up, stream-up or stream-one")
		}
	}
	return nil
}
