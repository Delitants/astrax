// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"astrax/internal/adminauth"
	"astrax/internal/cert"
	"astrax/internal/store"
)

func httpsManagementFixture(t *testing.T, sans []string) (*Server, string, string) {
	bind := "192.0.2.10:8443"
	if len(sans) == 1 && sans[0] == "localhost" {
		bind = "127.0.0.1:8443"
	}
	return httpsManagementFixtureWithBind(t, sans, bind)
}

func httpsManagementFixtureWithBind(t *testing.T, sans []string, bind string) (*Server, string, string) {
	t.Helper()
	return managementFixtureWithBinds(t, sans, "127.0.0.1:8080", bind)
}

func managementFixtureWithBinds(t *testing.T, sans []string, httpBind, httpsBind string) (*Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	st, err := store.NewWithOptions(path, store.Options{DisableRuntime: true, AdapterDetector: staticHTTPDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	auth, session := enrollTestAdmin(t, path)
	manager := cert.New(t.TempDir())
	if err := manager.GenerateSelfSigned(sans, 30, "test"); err != nil {
		t.Fatal(err)
	}
	cfg, err := manager.TLSConfigWithVersion("1.2")
	if err != nil {
		t.Fatal(err)
	}
	admission, err := adminauth.AdmitManagement(httpBind, httpsBind, true, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithManagementTransport(st, os.DirFS(filepath.Join("..", "..")), manager, auth, admission)
	if err != nil {
		t.Fatal(err)
	}
	return s, session.Token, session.CSRFToken
}

func TestManagementCanonicalIPv6BrowserOrigin(t *testing.T) {
	bind := "[0:0:0:0:0:0:0:1]"
	s, token, csrf := managementFixtureWithBinds(t, []string{"::1"}, bind+":8080", bind+":8443")
	for _, tc := range []struct {
		name, scheme, port string
	}{
		{"HTTP", "http", "8080"},
		{"HTTPS", "https", "8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := tc.scheme + "://[::1]:" + tc.port
			request := func(path, host, requestOrigin string) *http.Request {
				r := httptest.NewRequest(http.MethodPost, origin+path, nil)
				r.Host = host
				r.Header.Set("Origin", requestOrigin)
				r.Header.Set("X-Forwarded-Host", "[::1]:"+tc.port)
				r.Header.Set("X-Forwarded-Proto", tc.scheme)
				if tc.scheme == "https" {
					r.TLS = &tls.ConnectionState{}
				}
				port := 8080
				if tc.scheme == "https" {
					port = 8443
				}
				return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("::1"), Port: port}))
			}
			login := request("/api/v1/auth/login", "[::1]:"+tc.port, origin)
			login.Body = io.NopCloser(strings.NewReader(`{"username":"admin","password":"` + testAdminPassword + `"}`))
			login.Header.Set("Content-Type", "application/json")
			if got := serveManagement(s, login); got.Code != http.StatusOK {
				t.Fatalf("canonical listener login = %d %s", got.Code, got.Body.String())
			}
			mutation := request("/api/v1/dvb-groups", "[::1]:"+tc.port, origin)
			mutation.Body = io.NopCloser(strings.NewReader(`{"name":"IPv6 ` + tc.name + ` group"}`))
			mutation.Header.Set("Content-Type", "application/json")
			mutation.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
			mutation.Header.Set(managementCSRFHeader, csrf)
			if got := serveManagement(s, mutation); got.Code != http.StatusCreated {
				t.Fatalf("canonical listener mutation = %d %s", got.Code, got.Body.String())
			}
			for _, forgery := range []struct{ name, host, origin string }{
				{"Host", "evil.example:" + tc.port, origin},
				{"Origin", "[::1]:" + tc.port, tc.scheme + "://evil.example:" + tc.port},
			} {
				t.Run("forged "+forgery.name, func(t *testing.T) {
					r := request("/api/v1/events", forgery.host, forgery.origin)
					r.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
					r.Header.Set(managementCSRFHeader, csrf)
					if got := serveManagement(s, r); got.Code != http.StatusForbidden {
						t.Fatalf("forged %s = %d", forgery.name, got.Code)
					}
				})
			}
		})
	}
}

func httpsManagementRequest(method, path, host, sni, origin string) *http.Request {
	r := httptest.NewRequest(method, "https://"+host+path, nil)
	r.Host = host
	r.TLS = &tls.ConnectionState{ServerName: sni}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8443}))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestManagementHTTPSCertifiedDNSLoginAndMutation(t *testing.T) {
	for _, sans := range [][]string{{"192.0.2.10", "astrax.example"}, {"astrax.example"}} {
		s, token, csrf := httpsManagementFixture(t, sans)
		login := httpsManagementRequest(http.MethodPost, "/api/v1/auth/login", "astrax.example:8443", "astrax.example", "https://astrax.example:8443")
		login.Body = io.NopCloser(strings.NewReader(`{"username":"admin","password":"` + testAdminPassword + `"}`))
		login.Header.Set("Content-Type", "application/json")
		if got := serveManagement(s, login); got.Code != http.StatusOK || len(got.Result().Cookies()) != 1 || !got.Result().Cookies()[0].Secure {
			t.Fatalf("DNS login with SANs %v: %d %s", sans, got.Code, got.Body.String())
		}
		mutation := httpsManagementRequest(http.MethodPost, "/api/v1/dvb-groups", "astrax.example:8443", "astrax.example", "https://astrax.example:8443")
		mutation.Body = io.NopCloser(strings.NewReader(`{"name":"DNS group"}`))
		mutation.Header.Set("Content-Type", "application/json")
		mutation.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
		mutation.Header.Set(managementCSRFHeader, csrf)
		if got := serveManagement(s, mutation); got.Code != http.StatusCreated {
			t.Fatalf("DNS mutation with SANs %v: %d %s", sans, got.Code, got.Body.String())
		}
		referer := httpsManagementRequest(http.MethodPost, "/api/v1/dvb-groups", "astrax.example:8443", "astrax.example", "")
		referer.Body = io.NopCloser(strings.NewReader(`{"name":"Referer group"}`))
		referer.Header.Set("Content-Type", "application/json")
		referer.Header.Set("Referer", "https://astrax.example:8443/index.html")
		referer.Header.Set(managementCSRFHeader, csrf)
		referer.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
		if got := serveManagement(s, referer); got.Code != http.StatusCreated {
			t.Fatalf("DNS Referer mutation with SANs %v: %d %s", sans, got.Code, got.Body.String())
		}
		if groups := s.store.ListDVBGroups(); len(groups) != 2 {
			t.Fatalf("DNS mutations did not persist: %+v", groups)
		}
	}
}

func TestManagementHTTPSRejectsForgedBrowserIdentity(t *testing.T) {
	s, token, csrf := httpsManagementFixture(t, []string{"192.0.2.10", "astrax.example"})
	for _, tc := range []struct{ name, host, sni, origin string }{
		{"wrong SNI", "astrax.example:8443", "evil.example", "https://astrax.example:8443"},
		{"missing SNI", "astrax.example:8443", "", "https://astrax.example:8443"},
		{"forged Host", "evil.example:8443", "astrax.example", "https://evil.example:8443"},
		{"forged Origin", "astrax.example:8443", "astrax.example", "https://evil.example:8443"},
		{"IP Host with DNS SNI", "192.0.2.10:8443", "astrax.example", "https://192.0.2.10:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httpsManagementRequest(http.MethodPost, "/api/v1/events", tc.host, tc.sni, tc.origin)
			r.Header.Set("X-Forwarded-Host", "astrax.example:8443")
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set(managementCSRFHeader, csrf)
			r.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
			if got := serveManagement(s, r); got.Code != http.StatusForbidden {
				t.Fatalf("forgery = %d", got.Code)
			}
			if tc.name != "forged Origin" {
				read := httpsManagementRequest(http.MethodGet, "/api/v1/status", tc.host, tc.sni, "")
				read.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
				if got := serveManagement(s, read); got.Code != http.StatusForbidden {
					t.Fatalf("forged read = %d", got.Code)
				}
			}
		})
	}
	badReferer := httpsManagementRequest(http.MethodPost, "/api/v1/events", "astrax.example:8443", "astrax.example", "")
	badReferer.Header.Set("Referer", "https://evil.example:8443/index.html")
	badReferer.Header.Set(managementCSRFHeader, csrf)
	badReferer.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
	if got := serveManagement(s, badReferer); got.Code != http.StatusForbidden {
		t.Fatalf("forged Referer = %d", got.Code)
	}
	badCSRF := httpsManagementRequest(http.MethodPost, "/api/v1/events", "astrax.example:8443", "astrax.example", "https://astrax.example:8443")
	badCSRF.Header.Set(managementCSRFHeader, "wrong")
	badCSRF.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
	if got := serveManagement(s, badCSRF); got.Code != http.StatusForbidden {
		t.Fatalf("forged CSRF = %d", got.Code)
	}
}

func TestManagementHTTPSIPAndLoopbackHTTPBrowserIdentity(t *testing.T) {
	s, token, csrf := httpsManagementFixture(t, []string{"192.0.2.10", "astrax.example"})
	ip := httpsManagementRequest(http.MethodPost, "/api/v1/events", "192.0.2.10:8443", "", "https://192.0.2.10:8443")
	ip.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
	ip.Header.Set(managementCSRFHeader, csrf)
	if got := serveManagement(s, ip); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("certified IP mutation = %d", got.Code)
	}
	local := rawManagementRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`"}`))
	local.Host = "localhost:8080"
	local.Header.Set("Origin", "http://localhost:8080")
	local.Header.Set("Content-Type", "application/json")
	if got := serveManagement(s, local); got.Code != http.StatusOK {
		t.Fatalf("localhost loopback HTTP login = %d %s", got.Code, got.Body.String())
	}
	localMutation := rawManagementRequest(http.MethodPost, "/api/v1/events", nil)
	localMutation.Host = "localhost:8080"
	localMutation.Header.Set("Origin", "http://localhost:8080")
	localMutation.Header.Set(managementCSRFHeader, csrf)
	localMutation.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
	if got := serveManagement(s, localMutation); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("localhost loopback HTTP mutation = %d", got.Code)
	}
	forged := rawManagementRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`"}`))
	forged.Host = "astrax.example:8080"
	forged.Header.Set("Origin", "http://astrax.example:8080")
	forged.Header.Set("Content-Type", "application/json")
	if got := serveManagement(s, forged); got.Code != http.StatusForbidden {
		t.Fatalf("LAN-style HTTP host = %d", got.Code)
	}
}

func TestManagementHTTPSLocalhostLoopbackName(t *testing.T) {
	s, _, _ := httpsManagementFixture(t, []string{"localhost"})
	r := httpsManagementRequest(http.MethodPost, "/api/v1/auth/login", "localhost:8443", "localhost", "https://localhost:8443")
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}))
	r.Body = io.NopCloser(strings.NewReader(`{"username":"admin","password":"` + testAdminPassword + `"}`))
	r.Header.Set("Content-Type", "application/json")
	if got := serveManagement(s, r); got.Code != http.StatusOK {
		t.Fatalf("localhost HTTPS login = %d %s", got.Code, got.Body.String())
	}
}
