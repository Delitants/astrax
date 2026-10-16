// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	ScopeRead           = "read"
	ScopeStreamsControl = "streams:control"
	ScopeAdmin          = "admin"
)

type ExternalAPISettings struct {
	Enabled        bool     `json:"enabled"`
	ListenAddress  string   `json:"listen_address"`
	Port           int      `json:"port"`
	TLS            bool     `json:"tls"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
}

// Enabled describes configuration; Running describes the actual listener.
type ExternalAPIStatus struct {
	Enabled       bool   `json:"enabled"`
	Running       bool   `json:"running"`
	ListenAddress string `json:"listen_address"`
	Port          int    `json:"port"`
	TLS           bool   `json:"tls"`
	BaseURL       string `json:"base_url,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

func DefaultExternalAPISettings() ExternalAPISettings {
	return ExternalAPISettings{ListenAddress: "127.0.0.1", Port: 8090}
}

func (s ExternalAPISettings) Validate() error {
	_, err := s.Normalized()
	return err
}

// Normalized returns owned origin storage. It never resolves or binds an address;
// collision checks and active-token requirements belong to listener Apply.
func (s ExternalAPISettings) Normalized() (ExternalAPISettings, error) {
	if !validAPIHost(s.ListenAddress) {
		return ExternalAPISettings{}, fmt.Errorf("external_api.listen_address must be an IP address or hostname without a port")
	}
	if s.Port < 1 || s.Port > 65535 {
		return ExternalAPISettings{}, fmt.Errorf("external_api.port must be between 1 and 65535")
	}
	var origins []string
	for i, raw := range s.AllowedOrigins {
		origin, err := normalizeAPIOrigin(raw)
		if err != nil {
			return ExternalAPISettings{}, fmt.Errorf("external_api.allowed_origins[%d]: %w", i, err)
		}
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}
	s.AllowedOrigins = origins
	return s, nil
}

func validAPIHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "\r\n\t /\\") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	hostname := strings.TrimSuffix(host, ".")
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeAPIOrigin(raw string) (string, error) {
	invalid := fmt.Errorf("must be an exact HTTP(S) origin without credentials, path, query or fragment")
	if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", invalid
	}
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Opaque != "" || u.User != nil || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.ContainsAny(raw, "?#") {
		return "", invalid
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if (scheme != "http" && scheme != "https") || !validAPIHost(host) || strings.Contains(host, "%") {
		return "", invalid
	}
	// net/url may split the last IPv6 component as a port without brackets.
	// Reject that ambiguous authority instead of changing the operator's origin.
	if strings.Contains(host, ":") && !strings.HasPrefix(u.Host, "[") {
		return "", invalid
	}
	if strings.HasPrefix(u.Host, "[") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return "", invalid
		}
		host = address.String()
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", invalid
		}
		port = strconv.Itoa(n)
		if scheme == "http" && n == 80 || scheme == "https" && n == 443 {
			port = ""
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		// URL origins require IPv6 brackets even when the default port is omitted.
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// APITokenRecord is persistence-only; HTTP responses must use View instead.
type APITokenRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"hash"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type APITokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (r APITokenRecord) View() APITokenView {
	v := APITokenView{ID: r.ID, Name: r.Name, Prefix: r.Prefix, Scopes: slices.Clone(r.Scopes), CreatedAt: r.CreatedAt}
	if r.LastUsedAt != nil {
		value := *r.LastUsedAt
		v.LastUsedAt = &value
	}
	if r.RevokedAt != nil {
		value := *r.RevokedAt
		v.RevokedAt = &value
	}
	return v
}

type CreateAPITokenRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

func (r CreateAPITokenRequest) Validate() error {
	name := strings.TrimSpace(r.Name)
	if !utf8.ValidString(r.Name) || name == "" || utf8.RuneCountInString(name) > 128 || strings.IndexFunc(r.Name, unicode.IsControl) >= 0 {
		return fmt.Errorf("name must contain 1-128 characters without control characters")
	}
	if len(r.Scopes) == 0 {
		return fmt.Errorf("scopes must contain at least one scope")
	}
	seen := make(map[string]bool, 3)
	for _, scope := range r.Scopes {
		switch scope {
		case ScopeRead, ScopeStreamsControl, ScopeAdmin:
		default:
			return fmt.Errorf("scopes contains an unsupported scope")
		}
		if seen[scope] {
			return fmt.Errorf("scopes must not contain duplicates")
		}
		seen[scope] = true
	}
	return nil
}
