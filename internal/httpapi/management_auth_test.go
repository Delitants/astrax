// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"astrax/internal/adminauth"
	"astrax/internal/cert"
	"astrax/internal/model"
	"astrax/internal/store"
)

const testAdminPassword = "Correct-Horse-Battery-2026!"

var testAdminSessions sync.Map // *Server -> adminauth.Session

func enrollTestAdmin(t *testing.T, configPath string) (*adminauth.Manager, adminauth.Session) {
	t.Helper()
	m, err := adminauth.Open(configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	secret, err := os.ReadFile(adminauth.SetupSecretPath(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Enroll(strings.TrimSpace(string(secret)), testAdminPassword); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login("127.0.0.1", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	return m, session
}

func registerTestAdmin(t *testing.T, s *Server, session adminauth.Session) {
	t.Helper()
	testAdminSessions.Store(s, session)
	t.Cleanup(func() { testAdminSessions.Delete(s) })
}

func managementTestRequest(t *testing.T, s *Server, r *http.Request) *http.Request {
	t.Helper()
	sessionValue, ok := testAdminSessions.Load(s)
	if !ok {
		t.Fatal("no enrolled test session")
	}
	session := sessionValue.(adminauth.Session)
	r.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("X-AstraX-CSRF", session.CSRFToken)
	}
	r.Host = "127.0.0.1:8080"
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
}

func rawManagementRequest(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, body)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
	return r
}

func managementAuthFixture(t *testing.T) (*Server, *adminauth.Manager, adminauth.Session) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	st, err := store.NewWithOptions(path, store.Options{DisableRuntime: true, AdapterDetector: staticHTTPDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	m, session := enrollTestAdmin(t, path)
	s, err := New(st, os.DirFS(filepath.Join("..", "..")), cert.New(t.TempDir()), m)
	if err != nil {
		t.Fatal(err)
	}
	registerTestAdmin(t, s, session)
	return s, m, session
}

func serveManagement(s *Server, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestManagementAuthProtectsCompleteMux(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	for _, path := range []string{
		"/api/v1/status", "/openapi.json", "/api/v1/epg", "/api/v1/events", "/api/v1/events?scope=external",
		"/api/v1/streams/one/start", "/api/v1/certificates/status", "/api/v1/api/try", "/api/v1/missing", "/missing-static.js",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if got := serveManagement(s, rawManagementRequest(method, path, nil)); got.Code != 401 {
				t.Errorf("%s %s = %d, want 401", method, path, got.Code)
			}
		}
	}
	for _, path := range []string{"/", "/index.html", "/login", "/setup", "/dvb-streams.js"} {
		if got := serveManagement(s, rawManagementRequest(http.MethodGet, path, nil)); got.Code != 200 {
			t.Errorf("public %s = %d", path, got.Code)
		}
	}
	for _, path := range []string{"/api/v1/streams/one/start", "/api/v1/certificates/generate", "/api/v1/api/try"} {
		if got := serveManagement(s, rawManagementRequest(http.MethodPost, path, nil)); got.Code != 401 {
			t.Errorf("unauthenticated POST %s = %d", path, got.Code)
		}
	}
}

func TestManagementAuthSessionCookieAndRevocation(t *testing.T) {
	s, m, session := managementAuthFixture(t)
	login := rawManagementRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`"}`))
	login.Header.Set("Origin", "http://127.0.0.1:8080")
	login.Header.Set("Content-Type", "application/json")
	w := serveManagement(s, login)
	if w.Code != 200 {
		t.Fatalf("login=%d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("auth response hardening missing")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Secure {
		t.Fatalf("insecure HTTP cookie: %+v", cookies)
	}
	logout := rawManagementRequest("POST", "/api/v1/auth/logout", nil)
	logout.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	logout.Header.Set("Origin", "http://127.0.0.1:8080")
	logout.Header.Set("X-AstraX-CSRF", session.CSRFToken)
	if got := serveManagement(s, logout); got.Code != 200 {
		t.Fatalf("logout=%d", got.Code)
	}
	if _, ok := m.VerifySession(session.Token); ok {
		t.Fatal("logout did not revoke")
	}
}

func TestManagementAuthSetupAndPasswordChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	st, err := store.NewWithOptions(path, store.Options{DisableRuntime: true, AdapterDetector: staticHTTPDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	m, err := adminauth.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	s, err := New(st, os.DirFS(filepath.Join("..", "..")), cert.New(t.TempDir()), m)
	if err != nil {
		t.Fatal(err)
	}
	if got := serveManagement(s, rawManagementRequest("GET", "/api/v1/auth/session", nil)); got.Code != 401 || !strings.Contains(got.Body.String(), `"setup_pending":true`) {
		t.Fatalf("pending inspection: %d %s", got.Code, got.Body.String())
	}
	secret, err := os.ReadFile(adminauth.SetupSecretPath(path))
	if err != nil {
		t.Fatal(err)
	}
	setup := rawManagementRequest("POST", "/api/v1/auth/setup", strings.NewReader(`{"secret":"`+strings.TrimSpace(string(secret))+`","password":"`+testAdminPassword+`"}`))
	setup.Header.Set("Content-Type", "application/json")
	setup.Header.Set("Origin", "http://127.0.0.1:8080")
	got := serveManagement(s, setup)
	if got.Code != 200 || len(got.Result().Cookies()) != 1 {
		t.Fatalf("setup: %d %s", got.Code, got.Body.String())
	}
	if _, err := os.Stat(adminauth.SetupSecretPath(path)); !os.IsNotExist(err) {
		t.Fatalf("setup secret remains: %v", err)
	}
	first := got.Result().Cookies()[0]
	second, err := m.Login("127.0.0.1", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	change := rawManagementRequest("POST", "/api/v1/auth/password", strings.NewReader(`{"old_password":"`+testAdminPassword+`","new_password":"New-Long-Secure-2026!"}`))
	change.Header.Set("Content-Type", "application/json")
	change.Header.Set("Origin", "http://127.0.0.1:8080")
	change.Header.Set("X-AstraX-CSRF", result.CSRFToken)
	change.AddCookie(first)
	if got := serveManagement(s, change); got.Code != 200 || len(got.Result().Cookies()) != 1 || got.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("password change: %d %s", got.Code, got.Body.String())
	}
	if _, ok := m.VerifySession(second.Token); ok {
		t.Fatal("other session survived password change")
	}
	if _, err := m.Login("127.0.0.1", testAdminPassword); err == nil {
		t.Fatal("old password accepted")
	}
	if _, err := m.Login("127.0.0.1", "New-Long-Secure-2026!"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}

func TestManagementAuthBoundsLoginBody(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	r := rawManagementRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"`+strings.Repeat("x", 5000)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	if got := serveManagement(s, r); got.Code != 413 {
		t.Fatalf("oversized login = %d", got.Code)
	}
}

func TestManagementAuthBoundsAllMutationBodies(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	r := managementTestRequest(t, s, httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(strings.Repeat("x", maxManagementBody+1))))
	if got := serveManagement(s, r); got.Code != 413 {
		t.Fatalf("oversized management body = %d", got.Code)
	}
}

func TestManagementAuthBoundsChunkedLogoutBody(t *testing.T) {
	s, _, session := managementAuthFixture(t)
	r := rawManagementRequest("POST", "/api/v1/auth/logout", strings.NewReader(strings.Repeat("x", maxAuthBody+1)))
	r.ContentLength = -1
	r.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("X-AstraX-CSRF", session.CSRFToken)
	if got := serveManagement(s, r); got.Code != 413 {
		t.Fatalf("oversized chunked logout = %d", got.Code)
	}
}

func TestManagementCSRFOriginAndForgedHeaders(t *testing.T) {
	s, _, session := managementAuthFixture(t)
	for name, mutate := range map[string]func(*http.Request){
		"missing origin": func(r *http.Request) {},
		"cross origin":   func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") },
		"missing csrf":   func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8080") },
		"forged forwarded": func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example")
			r.Header.Set("X-Forwarded-Host", "evil.example")
			r.Header.Set("X-AstraX-CSRF", session.CSRFToken)
		},
		"wrong csrf": func(r *http.Request) {
			r.Header.Set("Origin", "http://127.0.0.1:8080")
			r.Header.Set("X-AstraX-CSRF", "wrong")
		},
		"duplicate origin": func(r *http.Request) {
			r.Header.Add("Origin", "http://127.0.0.1:8080")
			r.Header.Add("Origin", "http://evil.example")
			r.Header.Set("X-AstraX-CSRF", session.CSRFToken)
		},
		"duplicate csrf": func(r *http.Request) {
			r.Header.Set("Origin", "http://127.0.0.1:8080")
			r.Header.Add("X-AstraX-CSRF", session.CSRFToken)
			r.Header.Add("X-AstraX-CSRF", "wrong")
		},
		"forged host": func(r *http.Request) {
			r.Host = "evil.example"
			r.Header.Set("Origin", "http://evil.example")
			r.Header.Set("X-AstraX-CSRF", session.CSRFToken)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := rawManagementRequest("POST", "/api/v1/events", nil)
			r.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
			mutate(r)
			if got := serveManagement(s, r); got.Code != 403 {
				t.Fatalf("got %d", got.Code)
			}
		})
	}
	good := rawManagementRequest("POST", "/api/v1/auth/logout", nil)
	good.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	good.Header.Set("Referer", "http://127.0.0.1:8080/index.html")
	good.Header.Set("X-AstraX-CSRF", session.CSRFToken)
	if got := serveManagement(s, good); got.Code != 200 {
		t.Fatalf("referer fallback=%d", got.Code)
	}
}

func TestManagementCSRFDefaultPortOrigin(t *testing.T) {
	s, _, session := managementAuthFixture(t)
	for _, tc := range []struct {
		scheme string
		port   int
	}{{"http", 80}, {"https", 443}} {
		active := s
		token, csrf := session.Token, session.CSRFToken
		if tc.scheme == "https" {
			active, token, csrf = httpsManagementFixtureWithBind(t, []string{"127.0.0.1"}, "127.0.0.1:443")
		}
		r := rawManagementRequest("POST", "/api/v1/events", nil)
		r.Host = "127.0.0.1"
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: tc.port}))
		if tc.scheme == "https" {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Origin", tc.scheme+"://127.0.0.1")
		r.Header.Set("X-AstraX-CSRF", csrf)
		r.AddCookie(&http.Cookie{Name: managementCookieName, Value: token})
		if got := serveManagement(active, r); got.Code != 405 {
			t.Errorf("%s default port mutation = %d", tc.scheme, got.Code)
		}
	}
}

func TestManagementAuthGenericFailureAndLogRedaction(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	var logged bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(old) })
	var firstBody string
	for _, username := range []string{"admin", "nobody"} {
		r := rawManagementRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+username+`","password":"secret-marker"}`))
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("Content-Type", "application/json")
		w := serveManagement(s, r)
		if w.Code != 401 || strings.Contains(w.Body.String(), username) {
			t.Fatalf("login failure: %d %s", w.Code, w.Body.String())
		}
		if firstBody == "" {
			firstBody = w.Body.String()
		} else if w.Body.String() != firstBody {
			t.Fatal("unknown user and wrong password differ")
		}
	}
	serveManagement(s, rawManagementRequest("GET", "/api/v1/secret-marker?password=secret-marker", nil))
	if strings.Contains(logged.String(), "secret-marker") {
		t.Fatal("credential or untrusted path leaked to log")
	}
}

func TestExternalAuthSeparation(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	_, token, err := s.store.CreateAPIToken(model.CreateAPITokenRequest{Name: "external", Scopes: []string{model.ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	r := rawManagementRequest("GET", "/api/v1/status", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if got := serveManagement(s, r); got.Code != 401 {
		t.Fatalf("management bearer=%d", got.Code)
	}
	if got := externalRequest(s.ExternalHandler(), "GET", "/api/v1/status", token, ""); got.Code != 200 {
		t.Fatalf("external bearer=%d", got.Code)
	}
}

func TestManagementAuthRequiresManager(t *testing.T) {
	_, err := New(nil, os.DirFS(filepath.Join("..", "..")), cert.New(t.TempDir()), nil)
	if err == nil {
		t.Fatal("nil admin auth accepted")
	}
}
