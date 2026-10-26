// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"astrax/internal/adminauth"
	"astrax/internal/model"
)

func userRequest(session adminauth.Session, method, path, body string) *http.Request {
	r := rawManagementRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:9000"
	r.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	r.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set(managementCSRFHeader, session.CSRFToken)
	}
	return r
}

func TestManagementNamedAccountsAndPermissions(t *testing.T) {
	s, m, admin := managementAuthFixture(t)
	sessions := map[string]adminauth.Session{"administrator": admin}
	for _, role := range []adminauth.Role{adminauth.RoleOperator, adminauth.RoleViewer} {
		payload := `{"username":"` + string(role) + `","password":"Separate-Passphrase_2026!","role":"` + string(role) + `"}`
		w := serveManagement(s, userRequest(admin, "POST", "/api/v1/users", payload))
		if w.Code != 201 {
			t.Fatalf("create %s=%d %s", role, w.Code, w.Body.String())
		}
		login := userRequest(admin, "POST", "/api/v1/auth/login", `{"username":"`+string(role)+`","password":"Separate-Passphrase_2026!"}`)
		login.Header.Del("Cookie")
		w = serveManagement(s, login)
		if w.Code != 200 {
			t.Fatalf("login %s=%d %s", role, w.Code, w.Body.String())
		}
		var response struct {
			User adminauth.User `json:"user"`
			CSRF string         `json:"csrf_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.User.Username != string(role) || response.User.Role != role {
			t.Fatalf("wrong principal: %+v", response.User)
		}
		sessions[string(role)] = adminauth.Session{Token: w.Result().Cookies()[0].Value, CSRFToken: response.CSRF, User: response.User}
	}
	if _, err := s.store.AddStream(model.Stream{Name: "Protected network channel", InputURL: "http://example.invalid/private?password=hidden-input", OutputURL: "srt://127.0.0.1:9999?passphrase=hidden-output", Protocol: "srt"}); err != nil {
		t.Fatal(err)
	}
	for role, session := range sessions {
		read := serveManagement(s, userRequest(session, "GET", "/api/v1/streams", ""))
		if read.Code != 200 {
			t.Fatalf("%s stream read=%d", role, read.Code)
		}
		if role != "administrator" && (strings.Contains(read.Body.String(), "hidden-") || strings.Contains(read.Body.String(), "input_url")) {
			t.Fatalf("%s credentials exposed: %s", role, read.Body.String())
		}
		if role == "administrator" {
			continue
		}
		for _, path := range []string{"/api/v1/users", "/api/v1/settings", "/api/v1/softcams", "/api/v1/logs", "/api/v1/adapter-profiles", "/api/v1/certificates/status", "/api/v1/api/tokens", "/openapi.json"} {
			if w := serveManagement(s, userRequest(session, "GET", path, "")); w.Code != 403 {
				t.Errorf("%s can read %s: %d", role, path, w.Code)
			}
		}
		for _, test := range []struct{ method, path, body string }{{"POST", "/api/v1/users", `{}`}, {"PUT", "/api/v1/settings", `{}`}, {"POST", "/api/v1/dvb-cards/refresh", `{}`}, {"POST", "/api/v1/dvb-cards/dvb36.0/restart", `{}`}, {"POST", "/api/v1/control/restart", `{}`}, {"POST", "/api/v1/dvb-streams/bulk", `{"action":"delete","ids":["one"]}`}} {
			if w := serveManagement(s, userRequest(session, test.method, test.path, test.body)); w.Code != 403 {
				t.Errorf("%s may mutate %s: %d %s", role, test.path, w.Code, w.Body.String())
			}
		}
		for _, prefix := range []string{"streams", "dvb-streams"} {
			w := serveManagement(s, userRequest(session, "POST", "/api/v1/"+prefix+"/missing/stop", `{}`))
			if role == "viewer" && w.Code != 403 || role == "operator" && w.Code == 403 {
				t.Errorf("%s control permission=%d %s", role, w.Code, w.Body.String())
			}
		}
	}
	// Account changes revoke only the target user, not the administrator or another user.
	w := serveManagement(s, userRequest(admin, "PUT", "/api/v1/users/operator", `{"enabled":false}`))
	if w.Code != 200 {
		t.Fatalf("disable=%d %s", w.Code, w.Body.String())
	}
	if m.SessionActive(sessions["operator"].Token) || !m.SessionActive(sessions["viewer"].Token) || !m.SessionActive(admin.Token) {
		t.Fatal("incorrect per-user revocation")
	}
	if w := serveManagement(s, userRequest(admin, "PUT", "/api/v1/users/admin", `{"role":"viewer"}`)); w.Code != 409 {
		t.Fatalf("last admin demotion=%d %s", w.Code, w.Body.String())
	}
	if w := serveManagement(s, userRequest(admin, "GET", "/api/v1/users", "")); w.Code != 200 || strings.Contains(w.Body.String(), "password") || strings.Contains(w.Body.String(), "salt") {
		t.Fatalf("user list leaked credentials: %d %s", w.Code, w.Body.String())
	}
}

func TestManagementViewerSSEIsRedactedAndRevokedOnRoleChange(t *testing.T) {
	s, m, admin := managementAuthFixture(t)
	if _, err := m.CreateUser(admin.Token, "watcher", "Separate-Passphrase_2026!", adminauth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	viewer, err := m.LoginUser("viewer-source", "watcher", "Separate-Passphrase_2026!")
	if err != nil {
		t.Fatal(err)
	}
	s.store.AddLog("info", "hidden-log-credential")
	if _, err := s.store.AddStream(model.Stream{Name: "Observed", InputURL: "http://example.invalid/hidden-stream", OutputURL: "udp://127.0.0.1:9999", Protocol: "udp"}); err != nil {
		t.Fatal(err)
	}
	r := userRequest(viewer, "GET", "/api/v1/events?snapshot=1&scope=external", "")
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(context.WithValue(ctx, http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}))
	w := &firstFlushRecorder{ResponseRecorder: httptest.NewRecorder(), firstFlush: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); s.Handler().ServeHTTP(w, r) }()
	waitForSSE(t, w.firstFlush)
	role := adminauth.RoleOperator
	if _, err := m.UpdateUser(admin.Token, "watcher", adminauth.UserUpdate{Role: &role}); err != nil {
		t.Fatal(err)
	}
	waitForSSE(t, done)
	if strings.Contains(w.Body.String(), "hidden-") || strings.Contains(w.Body.String(), `"logs"`) || strings.Contains(w.Body.String(), `"input_url"`) {
		t.Fatalf("monitoring SSE leaked: %s", w.Body.String())
	}
}

func TestManagementAccountsRequireCSRFAndNamedLogin(t *testing.T) {
	s, _, admin := managementAuthFixture(t)
	r := userRequest(admin, "POST", "/api/v1/users", `{"username":"other","password":"Separate-Passphrase_2026!","role":"viewer"}`)
	r.Header.Del(managementCSRFHeader)
	if w := serveManagement(s, r); w.Code != 403 {
		t.Fatalf("account creation without CSRF=%d", w.Code)
	}
	for _, username := range []string{"", "missing"} {
		r := userRequest(admin, "POST", "/api/v1/auth/login", `{"username":"`+username+`","password":"`+testAdminPassword+`"}`)
		if w := serveManagement(s, r); w.Code != 401 {
			t.Errorf("login with %q=%d", username, w.Code)
		}
	}
}

func TestManagementWrongCurrentPasswordKeepsSession(t *testing.T) {
	s, m, admin := managementAuthFixture(t)
	w := serveManagement(s, userRequest(admin, "POST", "/api/v1/auth/password", `{"old_password":"wrong","new_password":"Separate-Passphrase_2026!"}`))
	if w.Code != 400 || !m.SessionActive(admin.Token) {
		t.Fatalf("password correction should not sign out a valid user: %d %s", w.Code, w.Body.String())
	}
}

type monitoringFrameRecorder struct {
	*firstFlushRecorder
	frame chan struct{}
	once  sync.Once
}

func (w *monitoringFrameRecorder) Write(data []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(data)
	if strings.Contains(string(data), "observed-channel") {
		w.once.Do(func() { close(w.frame) })
	}
	return n, err
}

func TestManagementViewerResourceEventsNeverRevealURLs(t *testing.T) {
	s, m, admin := managementAuthFixture(t)
	if _, err := m.CreateUser(admin.Token, "watcher", "Separate-Passphrase_2026!", adminauth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	viewer, err := m.LoginUser("viewer-source", "watcher", "Separate-Passphrase_2026!")
	if err != nil {
		t.Fatal(err)
	}
	r := userRequest(viewer, "GET", "/api/v1/events", "")
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	w := &monitoringFrameRecorder{firstFlushRecorder: &firstFlushRecorder{ResponseRecorder: httptest.NewRecorder(), firstFlush: make(chan struct{})}, frame: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); s.Handler().ServeHTTP(w, r.WithContext(ctx)) }()
	waitForSSE(t, w.firstFlush)
	s.store.PublishEvent("dvb.stream.changed", "observed-channel", model.Stream{ID: "observed-channel", InputURL: "http://secret-input", OutputURL: "srt://host?passphrase=secret-output", Runtime: model.StreamRuntime{State: "running", LastError: "secret-error"}})
	waitForSSE(t, w.frame)
	cancel()
	waitForSSE(t, done)
	if strings.Contains(w.Body.String(), "secret-") || strings.Contains(w.Body.String(), "input_url") || strings.Contains(w.Body.String(), "output_url") {
		t.Fatalf("resource event leaked: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"state":"running"`) {
		t.Fatalf("runtime event lost: %s", w.Body.String())
	}
}
