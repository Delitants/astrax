// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"astrax/internal/adminauth"
	"astrax/internal/cert"
	"astrax/internal/httpapi"
	"astrax/internal/store"
)

func managementSettingsResponse(t *testing.T, path string, st *store.Store, method string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	auth, err := adminauth.Open(path, st.AdminAuthInitialized())
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	session, err := auth.Login("127.0.0.1", "Strong-unique-local-secret_2026!")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(st, os.DirFS("."), cert.New(filepath.Dir(path)), auth)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:18080/api/v1/settings", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18080}))
	r.AddCookie(&http.Cookie{Name: "astrax_admin", Value: session.Token})
	r.Header.Set("Origin", "http://127.0.0.1:18080")
	r.Header.Set("X-AstraX-CSRF", session.CSRFToken)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func TestManagementSettingsSaveThenPreflight(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withCert   bool
		patch      map[string]any
		wantHTTPS  string
		redirected bool
	}{
		{
			name:     "admitted HTTPS redirect and legacy HTTP wildcard",
			withCert: true,
			patch: map[string]any{
				"control_listen": "0.0.0.0:18080", "control_listen_https": "192.0.2.10:18443", "redirect_https": true,
			},
			wantHTTPS:  "192.0.2.10:18443",
			redirected: true,
		},
		{
			name: "default HTTPS wildcard without certificate",
			patch: map[string]any{
				"control_listen_https": "0.0.0.0:8443", "redirect_https": false,
			},
		},
		{
			name:     "default HTTPS wildcard remains inert after certificate setup",
			withCert: true,
			patch: map[string]any{
				"control_listen_https": "0.0.0.0:8443", "redirect_https": false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080"}`)
			enrollPreflight(t, path)
			if tc.withCert {
				if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"192.0.2.10"}, 30, "test"); err != nil {
					t.Fatal(err)
				}
			}
			st, err := store.NewWithOptions(path, store.Options{DisableRuntime: true})
			if err != nil {
				t.Fatal(err)
			}
			response := managementSettingsResponse(t, path, st, http.MethodPatch, tc.patch)
			st.Close()
			if response.Code != http.StatusOK {
				t.Fatalf("settings save = %d: %s", response.Code, response.Body.String())
			}
			prepared, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
				return &preflightListener{address: addr}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			if prepared.httpAddr != "127.0.0.1:18080" || prepared.httpsAddr != tc.wantHTTPS || prepared.redirectHTTPS != tc.redirected {
				t.Fatalf("saved settings not admitted on restart: HTTP=%q HTTPS=%q redirect=%v", prepared.httpAddr, prepared.httpsAddr, prepared.redirectHTTPS)
			}
		})
	}
}

func TestManagementSettingsRejectBeforePersistence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cert       bool
		method     string
		patch      map[string]any
		fullListen string
	}{
		{name: "plaintext LAN", method: http.MethodPatch, patch: map[string]any{"control_listen": "192.0.2.10:18080"}},
		{name: "HTTPS without certificate", method: http.MethodPatch, patch: map[string]any{"control_listen_https": "192.0.2.10:18443"}},
		{name: "HTTPS wildcard with certificate", cert: true, method: http.MethodPatch, patch: map[string]any{"control_listen_https": "0.0.0.0:18443"}},
		{name: "HTTPS certificate identity mismatch", cert: true, method: http.MethodPatch, patch: map[string]any{"control_listen_https": "192.0.2.10:18443"}},
		{name: "HTTP HTTPS listener collision", cert: true, method: http.MethodPatch, patch: map[string]any{"control_listen_https": "127.0.0.1:18080"}},
		{name: "redirect without HTTPS listener", method: http.MethodPatch, patch: map[string]any{"redirect_https": true}},
		{name: "redirect with default wildcard and no certificate", method: http.MethodPatch, patch: map[string]any{"control_listen_https": "0.0.0.0:8443", "redirect_https": true}},
		{name: "PUT plaintext LAN", method: http.MethodPut, fullListen: "192.0.2.10:18080"},
		{name: "PUT invalid TLS minimum", method: http.MethodPut},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080"}`)
			enrollPreflight(t, path)
			if tc.cert {
				if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"127.0.0.1"}, 30, "test"); err != nil {
					t.Fatal(err)
				}
			}
			st, err := store.NewWithOptions(path, store.Options{DisableRuntime: true})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			beforeSettings := st.Settings()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var payload any = tc.patch
			if tc.method == http.MethodPut {
				candidate := st.Settings()
				if tc.fullListen != "" {
					candidate.ControlListen = tc.fullListen
				} else {
					candidate.TLSMinVersion = "1.0"
				}
				payload = candidate
			}
			response := managementSettingsResponse(t, path, st, tc.method, payload)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid settings save = %d: %s", response.Code, response.Body.String())
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := st.Settings()
			if !bytes.Equal(after, before) || got.ControlListen != beforeSettings.ControlListen || got.ControlListenHTTPS != beforeSettings.ControlListenHTTPS || got.RedirectHTTPS != beforeSettings.RedirectHTTPS || got.TLSMinVersion != beforeSettings.TLSMinVersion {
				t.Fatal("rejected settings changed durable or in-memory management state")
			}
		})
	}
}
