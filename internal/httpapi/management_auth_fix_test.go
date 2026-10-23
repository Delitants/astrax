// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"astrax/internal/adminauth"
	"astrax/internal/cert"
	"astrax/internal/model"
	"astrax/internal/store"
)

func TestManagementAuthChunkedBodyRejectedBeforeAction(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	before := len(s.store.ListLogs(100))
	r := rawManagementRequest(http.MethodPost, "/api/v1/control/restart", strings.NewReader(strings.Repeat("x", maxManagementBody+1)))
	r.ContentLength = -1
	r = managementTestRequest(t, s, r)
	if got := serveManagement(s, r); got.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked restart = %d, want 413", got.Code)
	}
	if got := len(s.store.ListLogs(100)); got != before {
		t.Fatalf("restart action ran: logs %d -> %d", before, got)
	}
}

func pendingManagementFixture(t *testing.T) (*Server, *adminauth.Manager, string) {
	t.Helper()
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
	secret, err := os.ReadFile(adminauth.SetupSecretPath(path))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(st, os.DirFS(filepath.Join("..", "..")), cert.New(t.TempDir()), m)
	if err != nil {
		t.Fatal(err)
	}
	return s, m, strings.TrimSpace(string(secret))
}

func postSetupAttempt(t *testing.T, s *Server, source, forwarded, secret string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"secret": secret, "password": testAdminPassword})
	if err != nil {
		t.Fatal(err)
	}
	r := rawManagementRequest(http.MethodPost, "/api/v1/auth/setup", strings.NewReader(string(body)))
	r.RemoteAddr = source + ":4000"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8080")
	r.Header.Set("X-Forwarded-For", forwarded)
	return serveManagement(s, r)
}

func TestManagementAuthSetupAttemptsBoundedBySourceAndGlobally(t *testing.T) {
	t.Run("source and forged forwarding", func(t *testing.T) {
		s, m, secret := pendingManagementFixture(t)
		var firstBody string
		for i := 0; i < 5; i++ {
			w := postSetupAttempt(t, s, "192.0.2.10", fmt.Sprintf("203.0.113.%d", i+1), "wrong")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("wrong setup attempt %d = %d", i+1, w.Code)
			}
			if i == 0 {
				firstBody = w.Body.String()
			}
		}
		w := postSetupAttempt(t, s, "192.0.2.10", "203.0.113.99", secret)
		if w.Code != http.StatusUnauthorized || w.Body.String() != firstBody || !m.SetupPending() {
			t.Fatalf("source limit did not block valid secret: %d %s", w.Code, w.Body.String())
		}
		if w = postSetupAttempt(t, s, "192.0.2.11", "203.0.113.99", secret); w.Code != http.StatusOK {
			t.Fatalf("independent source cannot enroll: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("global", func(t *testing.T) {
		s, m, secret := pendingManagementFixture(t)
		for i := 0; i < 32; i++ {
			w := postSetupAttempt(t, s, fmt.Sprintf("198.51.100.%d", i+1), "203.0.113.1", "wrong")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("wrong setup attempt %d = %d", i+1, w.Code)
			}
		}
		w := postSetupAttempt(t, s, "192.0.2.20", "203.0.113.1", secret)
		if w.Code != http.StatusUnauthorized || !m.SetupPending() {
			t.Fatalf("global limit did not block valid secret: %d %s", w.Code, w.Body.String())
		}
	})
}

func TestManagementAuthChunkedTrailingJSONRejectedBeforeMutation(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	before := len(s.store.ListStreams())
	body := `{"name":"Demo","input_url":"udp://239.0.0.1:1234","output_url":"http://127.0.0.1:8000/demo.ts","protocol":"mpegts","enabled":false}` + strings.Repeat(" ", maxManagementBody)
	r := rawManagementRequest(http.MethodPost, "/api/v1/streams", strings.NewReader(body))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	r = managementTestRequest(t, s, r)
	if got := serveManagement(s, r); got.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked trailing JSON = %d, want 413", got.Code)
	}
	if got := len(s.store.ListStreams()); got != before {
		t.Fatalf("stream mutation ran: %d -> %d", before, got)
	}
}

func TestManagementCSRFRefererFallbackReachesDVBRoute(t *testing.T) {
	s, _, session := managementAuthFixture(t)
	r := rawManagementRequest(http.MethodPost, "/api/v1/dvb-groups", strings.NewReader(`{"name":"Referer group"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Referer", "http://127.0.0.1:8080/dvb-management.html")
	r.Header.Set(managementCSRFHeader, session.CSRFToken)
	r.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	if got := serveManagement(s, r); got.Code != http.StatusCreated {
		t.Fatalf("Referer-backed DVB mutation = %d, want 201: %s", got.Code, got.Body.String())
	}
	if got := s.store.ListDVBGroups(); len(got) != 1 || got[0].Name != "Referer group" {
		t.Fatalf("DVB group missing after Referer-backed mutation: %+v", got)
	}
	external := rawManagementRequest(http.MethodPost, "/api/v1/dvb-groups", strings.NewReader(`{"name":"External group"}`))
	external.Header.Set("Content-Type", "application/json")
	external.Header.Set("Referer", "http://127.0.0.1:8080/dvb-management.html")
	external.Header.Set(managementCSRFHeader, session.CSRFToken)
	external.AddCookie(&http.Cookie{Name: managementCookieName, Value: session.Token})
	w := httptest.NewRecorder()
	s.ExternalHandler().ServeHTTP(w, external)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("external cookie/Referer = %d, want 401", w.Code)
	}
	token := externalToken(t, s, model.ScopeAdmin)
	if got := externalRequest(s.ExternalHandler(), http.MethodPost, "/api/v1/dvb-groups", token, `{"name":"Bearer group"}`); got.Code != http.StatusCreated {
		t.Fatalf("external bearer = %d, want 201: %s", got.Code, got.Body.String())
	}
}
