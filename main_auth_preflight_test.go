// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"astrax/internal/adapters"
	"astrax/internal/adminauth"
	"astrax/internal/cert"
	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/store"
)

type preflightListener struct {
	address string
	closed  atomic.Bool
}

func (l *preflightListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *preflightListener) Close() error              { l.closed.Store(true); return nil }
func (l *preflightListener) Addr() net.Addr            { return preflightAddr(l.address) }

type preflightAddr string

func (a preflightAddr) Network() string { return "tcp" }
func (a preflightAddr) String() string  { return string(a) }

type preflightDetector struct{ calls *atomic.Int32 }

func (d preflightDetector) DetectRuntime() []model.Adapter { d.calls.Add(1); return nil }
func (d preflightDetector) DetectDVB(context.Context) ([]model.DVBCard, error) {
	d.calls.Add(1)
	return nil, nil
}

type preflightOpener struct{ calls *atomic.Int32 }

func (o preflightOpener) OpenSession(dvb.Config) (dvb.Session, error) {
	o.calls.Add(1)
	return nil, errors.New("unexpected DVB open")
}

var _ adapters.Detector = preflightDetector{}

func preflightConfig(t *testing.T, settings string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"schema_version":2,"settings":` + settings + `}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func enrollPreflight(t *testing.T, path string) {
	t.Helper()
	auth, err := adminauth.Open(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	secret, err := os.ReadFile(adminauth.SetupSecretPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Enroll(strings.TrimSpace(string(secret)), "Strong-unique-local-secret_2026!"); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedPreflightHasNoRuntimeEffects(t *testing.T) {
	for _, occupied := range []string{"127.0.0.1:18080", "192.0.2.10:18443"} {
		t.Run(occupied, func(t *testing.T) {
			path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"192.0.2.10:18443"}`)
			enrollPreflight(t, path)
			if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"192.0.2.10"}, 30, "test"); err != nil {
				t.Fatal(err)
			}
			var detector, opener, source atomic.Int32
			var first *preflightListener
			deps := managementDeps{
				storeOptions: store.Options{
					AdapterDetector: preflightDetector{&detector},
					DVBOpener:       preflightOpener{&opener},
					RuntimeFactory:  func(model.Settings) (store.RuntimeDependencies, error) { source.Add(1); return nil, nil },
				},
				listen: func(_, addr string) (net.Listener, error) {
					if addr == occupied {
						return nil, syscall.EADDRINUSE
					}
					l := &preflightListener{address: addr}
					if first == nil {
						first = l
					}
					return l, nil
				},
			}
			if prepared, err := prepareManagementWith(path, "", "", deps); err == nil || prepared != nil {
				t.Fatalf("occupied listener accepted: %v, %+v", err, prepared)
			}
			if occupied != "127.0.0.1:18080" && (first == nil || !first.closed.Load()) {
				t.Fatal("HTTP listener not closed after HTTPS reservation failed")
			}
			if detector.Load() != 0 || opener.Load() != 0 || source.Load() != 0 {
				t.Fatalf("runtime effects before admission: detector=%d opener=%d source=%d", detector.Load(), opener.Load(), source.Load())
			}
		})
	}
}

func TestManagementTransportRejectsRedirectBeforeEnrollment(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"192.0.2.10:18443","redirect_https":true}`)
	var binds atomic.Int32
	_, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		binds.Add(1)
		return &preflightListener{address: addr}, nil
	}})
	if err == nil || binds.Load() != 0 {
		t.Fatalf("unenrolled redirect accepted or bound: err=%v binds=%d", err, binds.Load())
	}
}

func TestManagementTransportRejectsMissingOrMalformedCertificate(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "malformed"}[malformed], func(t *testing.T) {
			path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"192.0.2.10:18443","redirect_https":true}`)
			enrollPreflight(t, path)
			if malformed {
				certPath, keyPath := cert.New(filepath.Dir(path)).Paths()
				if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(certPath, []byte("bad certificate"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, []byte("bad key"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var binds atomic.Int32
			_, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
				binds.Add(1)
				return &preflightListener{address: addr}, nil
			}})
			if err == nil || binds.Load() != 0 {
				t.Fatalf("invalid certificate accepted or bound: err=%v binds=%d", err, binds.Load())
			}
		})
	}
}

func TestManagementTransportRejectsPartialCertificate(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"0.0.0.0:8443"}`)
	enrollPreflight(t, path)
	certPath, _ := cert.New(filepath.Dir(path)).Paths()
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("orphaned certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	var binds atomic.Int32
	_, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		binds.Add(1)
		return &preflightListener{address: addr}, nil
	}})
	if err == nil || binds.Load() != 0 {
		t.Fatalf("partial certificate accepted or bound: err=%v binds=%d", err, binds.Load())
	}
}

func TestManagementTransportRejectsWildcardRedirect(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"0.0.0.0:19443","redirect_https":true}`)
	enrollPreflight(t, path)
	if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"127.0.0.1"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	var binds atomic.Int32
	_, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		binds.Add(1)
		return &preflightListener{address: addr}, nil
	}})
	if err == nil || binds.Load() != 0 {
		t.Fatalf("wildcard redirect accepted or bound: err=%v binds=%d", err, binds.Load())
	}
}

func TestManagementTransportKeepsDefaultHTTPSWildcardDormantWithoutRedirect(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"0.0.0.0:8443"}`)
	enrollPreflight(t, path)
	if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"127.0.0.1"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	var binds atomic.Int32
	prepared, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		binds.Add(1)
		return &preflightListener{address: addr}, nil
	}})
	if prepared != nil {
		defer prepared.Close()
	}
	if err != nil || prepared == nil || prepared.httpsAddr != "" || prepared.admission.StartHTTPS || binds.Load() != 1 {
		t.Fatalf("default wildcard HTTPS became active: prepared=%v err=%v binds=%d", prepared, err, binds.Load())
	}
}

func TestManagementTransportRejectsNonDefaultWildcardHTTPSWithoutRedirect(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"0.0.0.0:18443"}`)
	enrollPreflight(t, path)
	if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"management.example"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	var binds atomic.Int32
	prepared, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		binds.Add(1)
		return &preflightListener{address: addr}, nil
	}})
	if prepared != nil {
		defer prepared.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "concrete IP address") || prepared != nil || binds.Load() != 0 {
		t.Fatalf("non-default wildcard HTTPS accepted or bound: prepared=%v err=%v binds=%d", prepared, err, binds.Load())
	}
}

func TestManagementTransportRejectsUnsafeTLSMinimum(t *testing.T) {
	for _, version := range []string{"1.0", "1.1", "bogus"} {
		t.Run(version, func(t *testing.T) {
			path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"192.0.2.10:18443","tls_min_version":"`+version+`"}`)
			enrollPreflight(t, path)
			if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"192.0.2.10"}, 30, "test"); err != nil {
				t.Fatal(err)
			}
			var binds atomic.Int32
			_, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
				binds.Add(1)
				return &preflightListener{address: addr}, nil
			}})
			if err == nil || binds.Load() != 0 {
				t.Fatalf("TLS %s accepted or bound: err=%v binds=%d", version, err, binds.Load())
			}
		})
	}
}

func TestManagementTransportAdmitsLANHTTPSWithCertificate(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"192.0.2.10:18443","redirect_https":true}`)
	enrollPreflight(t, path)
	if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"192.0.2.10"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	var listeners []*preflightListener
	prepared, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		l := &preflightListener{address: addr}
		listeners = append(listeners, l)
		return l, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.httpsListener == nil || prepared.httpListener == nil || prepared.tlsConfig == nil || !prepared.store.AdminAuthInitialized() {
		t.Fatalf("incomplete admission: %+v", prepared)
	}
	prepared.Close()
	for _, l := range listeners {
		if !l.closed.Load() {
			t.Fatal("owned listener left open")
		}
	}
}

func TestManagementTransportMarksOnlyAfterDurableAuthOpen(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080"}`)
	if err := os.WriteFile(adminauth.StatePath(path), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	var binds atomic.Int32
	_, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		binds.Add(1)
		return &preflightListener{address: addr}, nil
	}})
	if err == nil || binds.Load() != 0 {
		t.Fatalf("invalid sidecar accepted or bound: err=%v binds=%d", err, binds.Load())
	}
	st, err := store.NewDormant(path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.AdminAuthInitialized() {
		t.Fatal("marker committed before durable auth state passed validation")
	}
}

func TestManagementTransportRedirectHasNoManagementExceptions(t *testing.T) {
	handler := redirectHandler("192.0.2.10:8443")
	for _, path := range []string{"/api/v1/events", "/api/v1/epg", "/api/v1/settings"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+path, nil))
		if recorder.Code != http.StatusPermanentRedirect || recorder.Header().Get("Location") != "https://192.0.2.10:8443"+path {
			t.Fatalf("%s escaped HTTPS redirect: code=%d location=%q", path, recorder.Code, recorder.Header().Get("Location"))
		}
	}
}

func TestManagementTransportDNSOnlyRedirectUsesCertificateName(t *testing.T) {
	path := preflightConfig(t, `{"control_listen":"127.0.0.1:18080","control_listen_https":"192.0.2.10:18443","redirect_https":true}`)
	enrollPreflight(t, path)
	if err := cert.New(filepath.Dir(path)).GenerateSelfSigned([]string{"astrax.example"}, 30, "test"); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareManagementWith(path, "", "", managementDeps{listen: func(_, addr string) (net.Listener, error) {
		return &preflightListener{address: addr}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.httpsAddr != "192.0.2.10:18443" || prepared.redirectAddr != "astrax.example:18443" {
		t.Fatalf("bind %q redirect %q", prepared.httpsAddr, prepared.redirectAddr)
	}
	w := httptest.NewRecorder()
	redirectHandler(prepared.redirectAddr).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/login", nil))
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://astrax.example:18443/login" {
		t.Fatalf("redirect = %d %q", w.Code, w.Header().Get("Location"))
	}
}
