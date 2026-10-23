// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"

	"astrax/internal/model"
)

func TestManagementCertificateMutationCannotInvalidateSavedHTTPS(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	if err := s.certMgr.GenerateSelfSigned([]string{"127.0.0.1"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := s.certMgr.Paths()
	beforeCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	settings := managementTestRequest(t, s, rawManagementRequest(http.MethodPatch, "/api/v1/settings", bytes.NewBufferString(`{"control_listen_https":"127.0.0.1:8443"}`)))
	if got := serveManagement(s, settings); got.Code != http.StatusOK {
		t.Fatalf("save HTTPS settings = %d: %s", got.Code, got.Body.String())
	}
	for _, tc := range []struct {
		path, body string
	}{
		{"/api/v1/certificates/delete", `{}`},
		{"/api/v1/certificates/generate", `{"hosts":["127.0.0.1"]}`},
		{"/api/v1/certificates/upload", `{"cert":"invalid","key":"invalid"}`},
	} {
		r := managementTestRequest(t, s, rawManagementRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body)))
		if got := serveManagement(s, r); got.Code != http.StatusConflict {
			t.Errorf("%s = %d, want 409: %s", tc.path, got.Code, got.Body.String())
		}
	}
	afterCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	afterKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeCert, afterCert) || !bytes.Equal(beforeKey, afterKey) {
		t.Fatal("rejected certificate mutation changed durable files")
	}
}

func TestManagementCertificateMutationCannotInvalidateRunningHTTPS(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	s.managementTransport.StartHTTPS = true
	r := managementTestRequest(t, s, rawManagementRequest(http.MethodPost, "/api/v1/certificates/generate", bytes.NewBufferString(`{"hosts":["127.0.0.1"]}`)))
	if got := serveManagement(s, r); got.Code != http.StatusConflict {
		t.Fatalf("running HTTPS certificate mutation = %d, want 409: %s", got.Code, got.Body.String())
	}
	if s.certMgr.Exists() {
		t.Fatal("rejected certificate generation wrote a pair")
	}
}

func TestManagementCertificateMutationCannotInvalidateExternalAPITLS(t *testing.T) {
	s, _, _ := managementAuthFixture(t)
	if err := s.certMgr.GenerateSelfSigned([]string{"127.0.0.1"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.store.CreateAPIToken(model.CreateAPITokenRequest{Name: "test", Scopes: []string{model.ScopeRead}}); err != nil {
		t.Fatal(err)
	}
	external := model.DefaultExternalAPISettings()
	external.Enabled, external.TLS = true, true
	if err := s.store.SetExternalAPISettings(external); err != nil {
		t.Fatal(err)
	}
	r := managementTestRequest(t, s, rawManagementRequest(http.MethodPost, "/api/v1/certificates/delete", bytes.NewBufferString(`{}`)))
	if got := serveManagement(s, r); got.Code != http.StatusConflict {
		t.Fatalf("configured external TLS certificate deletion = %d, want 409: %s", got.Code, got.Body.String())
	}
	if !s.certMgr.Exists() {
		t.Fatal("rejected certificate deletion removed the pair")
	}

	// A failed transition can leave an old TLS listener running after the
	// durable settings have already been disabled.
	external.Enabled = false
	if err := s.store.SetExternalAPISettings(external); err != nil {
		t.Fatal(err)
	}
	s.externalAPI = NewExternalAPIManager(nil, s.certMgr, s.store)
	t.Cleanup(func() { _ = s.externalAPI.Close(context.Background()) })
	s.externalAPI.mu.Lock()
	s.externalAPI.status = model.ExternalAPIStatus{Running: true, TLS: true}
	s.externalAPI.mu.Unlock()
	r = managementTestRequest(t, s, rawManagementRequest(http.MethodPost, "/api/v1/certificates/delete", bytes.NewBufferString(`{}`)))
	if got := serveManagement(s, r); got.Code != http.StatusConflict {
		t.Fatalf("running external TLS certificate deletion = %d, want 409: %s", got.Code, got.Body.String())
	}
	if !s.certMgr.Exists() {
		t.Fatal("rejected certificate deletion removed the pair")
	}
}
