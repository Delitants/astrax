// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Admission is the address set that may be reserved before runtime starts.
type Admission struct {
	HTTPAddr          string
	HTTPSAddr         string
	RedirectHTTPSAddr string
	HTTPSIdentities   BrowserIdentities
	StartHTTPS        bool
}

// BrowserIdentities is a snapshot of exact, usable names in the admitted TLS certificate.
type BrowserIdentities struct {
	DNSNames    []string
	IPAddresses []netip.Addr
}

func (ids BrowserIdentities) AllowsDNS(name string) bool {
	for _, allowed := range ids.DNSNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func (ids BrowserIdentities) AllowsIP(ip netip.Addr) bool {
	for _, allowed := range ids.IPAddresses {
		if ip == allowed {
			return true
		}
	}
	return false
}

// EnrollmentState distinguishes a pending setup from revoked or corrupt state.
func (m *Manager) EnrollmentState() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stateCurrentLocked() {
		return false, errInvalidState
	}
	return m.state.Phase == "enrolled", nil
}

// AdmitManagement never permits plaintext management outside literal loopback.
func AdmitManagement(httpAddr, httpsAddr string, enrolled bool, tlsConfig *tls.Config, explicitHTTP bool) (Admission, error) {
	httpHost, httpPort, err := parseManagementAddress(httpAddr)
	if err != nil {
		return Admission{}, fmt.Errorf("HTTP management address: %w", err)
	}
	if httpHost == "" || httpHost == "0.0.0.0" || httpHost == "::" {
		if explicitHTTP {
			return Admission{}, fmt.Errorf("--listen must be a literal loopback address, not a wildcard")
		}
		if httpHost == "::" {
			httpHost = "::1"
		} else {
			httpHost = "127.0.0.1"
		}
	}
	ip, err := netip.ParseAddr(httpHost)
	if err != nil || !ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" {
		return Admission{}, fmt.Errorf("plaintext management requires a literal loopback IP address")
	}
	result := Admission{HTTPAddr: net.JoinHostPort(ip.String(), httpPort)}
	if !enrolled || httpsAddr == "" {
		return result, nil
	}
	httpsHost, httpsPort, err := parseManagementAddress(httpsAddr)
	if err != nil {
		return Admission{}, fmt.Errorf("HTTPS management address: %w", err)
	}
	if httpsHost == "" {
		return Admission{}, fmt.Errorf("HTTPS management address must have a literal IP host")
	}
	httpsIP, err := netip.ParseAddr(httpsHost)
	if err != nil || httpsIP.Is4In6() || httpsIP.Zone() != "" {
		return Admission{}, fmt.Errorf("HTTPS management address must have a literal IP host")
	}
	if httpsIP.IsUnspecified() {
		return Admission{}, fmt.Errorf("HTTPS management requires a concrete IP address to verify the certificate; set control_listen_https or --https-listen")
	}
	identities, err := validManagementCertificate(tlsConfig)
	if err != nil {
		return Admission{}, err
	}
	if !httpsIP.IsLoopback() {
		var names []string
		for _, name := range identities.DNSNames {
			if name != "localhost" {
				names = append(names, name)
			}
		}
		identities.DNSNames = names
	}
	redirectHost := ""
	if identities.AllowsIP(httpsIP) {
		redirectHost = httpsIP.String()
	} else if len(identities.DNSNames) != 0 {
		redirectHost = identities.DNSNames[0]
	}
	if redirectHost == "" {
		return Admission{}, fmt.Errorf("HTTPS management certificate has no exact browser identity for this listener")
	}
	result.HTTPSAddr = net.JoinHostPort(httpsIP.String(), httpsPort)
	if result.HTTPSAddr == result.HTTPAddr {
		return Admission{}, fmt.Errorf("HTTP and HTTPS management listeners cannot use the same address")
	}
	result.RedirectHTTPSAddr = net.JoinHostPort(redirectHost, httpsPort)
	result.HTTPSIdentities = identities
	result.StartHTTPS = true
	return result, nil
}

func parseManagementAddress(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("use host:port with a literal IP: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", "", fmt.Errorf("port must be between 1 and 65535")
	}
	return host, port, nil
}

func validManagementCertificate(cfg *tls.Config) (BrowserIdentities, error) {
	if cfg == nil || len(cfg.Certificates) != 1 || cfg.GetCertificate != nil || cfg.GetConfigForClient != nil {
		return BrowserIdentities{}, fmt.Errorf("HTTPS management requires one fixed configured certificate")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		return BrowserIdentities{}, fmt.Errorf("HTTPS management requires TLS 1.2 or newer")
	}
	cert := cfg.Certificates[0]
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return BrowserIdentities{}, fmt.Errorf("HTTPS management certificate or private key missing")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return BrowserIdentities{}, fmt.Errorf("parse HTTPS management certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return BrowserIdentities{}, fmt.Errorf("HTTPS management certificate is not currently valid")
	}
	serverUsage := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		serverUsage = serverUsage || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !serverUsage {
		return BrowserIdentities{}, fmt.Errorf("HTTPS management certificate cannot authenticate a server")
	}
	ids := BrowserIdentities{}
	for _, raw := range leaf.DNSNames {
		name := strings.ToLower(raw)
		if validExactDNSName(name) && leaf.VerifyHostname(name) == nil && !ids.AllowsDNS(name) {
			ids.DNSNames = append(ids.DNSNames, name)
		}
	}
	for _, raw := range leaf.IPAddresses {
		ip, ok := netip.AddrFromSlice(raw)
		if ok && !ip.IsUnspecified() && !ip.Is4In6() && leaf.VerifyHostname(ip.String()) == nil && !ids.AllowsIP(ip) {
			ids.IPAddresses = append(ids.IPAddresses, ip)
		}
	}
	return ids, nil
}

func validExactDNSName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
