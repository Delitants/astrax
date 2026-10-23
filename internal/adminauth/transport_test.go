// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"crypto/tls"
	"os"
	"testing"

	"astrax/internal/cert"
)

func TestManagementTransportHTTPAdmission(t *testing.T) {
	tests := []struct {
		name, address, want string
		explicit, reject    bool
	}{
		{"legacy IPv4 wildcard", "0.0.0.0:8080", "127.0.0.1:8080", false, false},
		{"legacy empty host", ":8080", "127.0.0.1:8080", false, false},
		{"legacy IPv6 wildcard", "[::]:8080", "[::1]:8080", false, false},
		{"noncanonical IPv6 loopback", "[0:0:0:0:0:0:0:1]:8080", "[::1]:8080", true, false},
		{"explicit wildcard", "0.0.0.0:8080", "", true, true},
		{"explicit LAN", "192.0.2.10:8080", "", true, true},
		{"configured LAN", "192.0.2.10:8080", "", false, true},
		{"localhost suffix", "localhost.example:8080", "", false, true},
		{"localhost DNS", "localhost:8080", "", false, true},
		{"IPv4 spelling trick", "127.1:8080", "", false, true},
		{"IPv4 mapped IPv6", "[::ffff:127.0.0.1]:8080", "", false, true},
		{"IPv6 zone", "[::1%lo0]:8080", "", false, true},
		{"missing host and port", ":", "", false, true},
		{"port zero", "127.0.0.1:0", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AdmitManagement(tt.address, "", false, nil, tt.explicit)
			if (err != nil) != tt.reject {
				t.Fatalf("AdmitManagement(%q) error = %v, reject = %v", tt.address, err, tt.reject)
			}
			if !tt.reject && (got.HTTPAddr != tt.want || got.StartHTTPS) {
				t.Fatalf("admission = %+v, want HTTP %q and no HTTPS", got, tt.want)
			}
		})
	}
}

func TestManagementTransportEnrollmentStateFailsClosedAfterTamper(t *testing.T) {
	config, manager, _ := newTestManager(t)
	if err := os.Chmod(SetupSecretPath(config), 0644); err != nil {
		t.Fatal(err)
	}
	if enrolled, err := manager.EnrollmentState(); err == nil || enrolled {
		t.Fatalf("invalid state treated as enrolled: enrolled=%v err=%v", enrolled, err)
	}
}

func TestManagementTransportUnenrolledHTTPSDisabled(t *testing.T) {
	got, err := AdmitManagement("127.0.0.1:8080", "0.0.0.0:8443", false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.StartHTTPS || got.HTTPSAddr != "" {
		t.Fatalf("unenrolled HTTPS admitted: %+v", got)
	}
}

func TestManagementTransportEnrolledHTTPSRequiresCertificate(t *testing.T) {
	if _, err := AdmitManagement("127.0.0.1:8080", "192.0.2.10:8443", true, nil, false); err == nil {
		t.Fatal("LAN HTTPS admitted without certificate")
	}
	if _, err := AdmitManagement("127.0.0.1:8080", "192.0.2.10:8443", true, &tls.Config{}, false); err == nil {
		t.Fatal("LAN HTTPS admitted with empty TLS config")
	}
}

func TestManagementTransportRejectsWildcardHTTPSWithoutAdvertisedIdentity(t *testing.T) {
	certManager := cert.New(t.TempDir())
	if err := certManager.GenerateSelfSigned([]string{"127.0.0.1"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := certManager.TLSConfigWithVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}
	for _, httpsAddr := range []string{"0.0.0.0:8443", "[::]:8443"} {
		t.Run(httpsAddr, func(t *testing.T) {
			if admitted, err := AdmitManagement("127.0.0.1:8080", httpsAddr, true, tlsConfig, false); err == nil || admitted.StartHTTPS {
				t.Fatalf("wildcard HTTPS admitted with loopback-only certificate: %+v, %v", admitted, err)
			}
		})
	}
	wildcardCert := cert.New(t.TempDir())
	if err := wildcardCert.GenerateSelfSigned([]string{"0.0.0.0"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	wildcardTLS, err := wildcardCert.TLSConfigWithVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}
	if admitted, err := AdmitManagement("127.0.0.1:8080", "0.0.0.0:8443", true, wildcardTLS, false); err == nil || admitted.StartHTTPS {
		t.Fatalf("wildcard HTTPS admitted with wildcard certificate: %+v, %v", admitted, err)
	}
	admitted, err := AdmitManagement("127.0.0.1:8080", "127.0.0.1:8443", true, tlsConfig, false)
	if err != nil || !admitted.StartHTTPS {
		t.Fatalf("matching concrete HTTPS address rejected: %+v, %v", admitted, err)
	}
}

func TestManagementTransportCertificateBrowserIdentities(t *testing.T) {
	for _, tc := range []struct {
		name, bind string
		sans       []string
		redirect   string
	}{
		{"IP and DNS", "192.0.2.10:8443", []string{"192.0.2.10", "astrax.example"}, "192.0.2.10:8443"},
		{"DNS only", "192.0.2.10:8443", []string{"astrax.example"}, "astrax.example:8443"},
		{"localhost", "127.0.0.1:8443", []string{"localhost"}, "localhost:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := cert.New(t.TempDir())
			if err := manager.GenerateSelfSigned(tc.sans, 30, "test"); err != nil {
				t.Fatal(err)
			}
			cfg, err := manager.TLSConfigWithVersion("1.2")
			if err != nil {
				t.Fatal(err)
			}
			got, err := AdmitManagement("127.0.0.1:8080", tc.bind, true, cfg, false)
			if err != nil {
				t.Fatal(err)
			}
			if !got.StartHTTPS || got.HTTPSAddr != tc.bind || got.RedirectHTTPSAddr != tc.redirect {
				t.Fatalf("admission = %+v", got)
			}
		})
	}
}

func TestManagementTransportCanonicalIPv6HTTPSAddress(t *testing.T) {
	manager := cert.New(t.TempDir())
	if err := manager.GenerateSelfSigned([]string{"::1"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	cfg, err := manager.TLSConfigWithVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}
	got, err := AdmitManagement("[0:0:0:0:0:0:0:1]:8080", "[0:0:0:0:0:0:0:1]:8443", true, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StartHTTPS || got.HTTPAddr != "[::1]:8080" || got.HTTPSAddr != "[::1]:8443" || got.RedirectHTTPSAddr != "[::1]:8443" {
		t.Fatalf("IPv6 admission = %+v", got)
	}
}

func TestManagementTransportRejectsNonExactCertificateIdentity(t *testing.T) {
	for _, sans := range [][]string{{"*.example"}, {"198.51.100.20"}, {"0.0.0.0"}} {
		manager := cert.New(t.TempDir())
		if err := manager.GenerateSelfSigned(sans, 30, "test"); err != nil {
			t.Fatal(err)
		}
		cfg, err := manager.TLSConfigWithVersion("1.2")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := AdmitManagement("127.0.0.1:8080", "192.0.2.10:8443", true, cfg, false); err == nil || got.StartHTTPS {
			t.Fatalf("SANs %v admitted: %+v %v", sans, got, err)
		}
	}
}

func TestManagementTransportRejectsLANRedirectToLocalhost(t *testing.T) {
	manager := cert.New(t.TempDir())
	if err := manager.GenerateSelfSigned([]string{"localhost"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	cfg, err := manager.TLSConfigWithVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := AdmitManagement("127.0.0.1:8080", "192.0.2.10:8443", true, cfg, false); err == nil || got.StartHTTPS {
		t.Fatalf("LAN redirect to client-local host admitted: %+v %v", got, err)
	}
}
