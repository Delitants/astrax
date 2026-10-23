// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"astrax/internal/adminauth"
)

type firstFlushRecorder struct {
	*httptest.ResponseRecorder
	firstFlush chan struct{}
	once       sync.Once
}

func (w *firstFlushRecorder) Flush() {
	w.ResponseRecorder.Flush()
	w.once.Do(func() { close(w.firstFlush) })
}

func waitForSSE(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("SSE stream did not advance")
	}
}

func TestManagementSSEStopsAfterSessionRevocation(t *testing.T) {
	for _, path := range []string{"/api/v1/events", "/api/v1/events?snapshot=1"} {
		for _, revoke := range []string{"logout", "password change"} {
			t.Run(path+"/"+revoke, func(t *testing.T) {
				s, m, session := managementAuthFixture(t)
				r := managementTestRequest(t, s, rawManagementRequest(http.MethodGet, path, nil))
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				w := &firstFlushRecorder{ResponseRecorder: httptest.NewRecorder(), firstFlush: make(chan struct{})}
				done := make(chan struct{})
				go func() {
					defer close(done)
					s.Handler().ServeHTTP(w, r)
				}()
				waitForSSE(t, w.firstFlush)
				if revoke == "logout" {
					m.Logout(session.Token)
				} else if err := m.ChangePassword(session.Token, testAdminPassword, "Another-strong-password_2026!"); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(path, "snapshot=1") {
					s.store.AddLog("info", "after revocation")
				} else {
					s.store.PublishEvent("logs.created", "after-revocation", map[string]string{"message": "after revocation"})
				}
				waitForSSE(t, done)
				body := w.Body.String()
				if strings.Contains(body, "after-revocation") || strings.Contains(body, "after revocation") {
					t.Fatalf("revoked stream emitted an event: %s", body)
				}
			})
		}
	}
}

func TestManagementSSEChecksSessionBeforeKeepAlive(t *testing.T) {
	s, m, session := managementAuthFixture(t)
	r := managementTestRequest(t, s, rawManagementRequest(http.MethodGet, "/api/v1/events", nil))
	w := httptest.NewRecorder()
	events := make(chan struct{})
	ticks := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		streamEventChannelWithKeepAlive(w, r, events, func() bool {
			return m.SessionActive(session.Token)
		}, func() bool {
			return m.SessionValid(session.Token)
		}, func(struct{}) (bool, error) { return false, nil }, ticks)
	}()
	m.Logout(session.Token)
	ticks <- time.Now()
	waitForSSE(t, done)
	if strings.Contains(w.Body.String(), "keepalive") {
		t.Fatal("revoked stream emitted keepalive")
	}
}

func TestManagementSSEStopsForExternalDurableRevocation(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.json")
	m, session := enrollTestAdmin(t, config)
	if err := os.Chmod(adminauth.StatePath(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if !m.SessionActive(session.Token) {
		t.Fatal("external state change unexpectedly revoked the in-memory session")
	}

	w := httptest.NewRecorder()
	events := make(chan string, 1)
	events <- "denied"
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	streamEventChannelWithKeepAlive(w, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil), events,
		func() bool { return m.SessionActive(session.Token) },
		func() bool { return m.SessionValid(session.Token) },
		func(event string) (bool, error) {
			_, err := fmt.Fprintf(w, "data: %s\n\n", event)
			return false, err
		}, ticks)
	if strings.Contains(w.Body.String(), "denied") || strings.Contains(w.Body.String(), "keepalive") {
		t.Fatalf("durably revoked stream emitted a frame: %s", w.Body.String())
	}
}

func TestManagementSSEDueCheckCannotBeStarvedByEvents(t *testing.T) {
	for i := 0; i < 32; i++ {
		w := httptest.NewRecorder()
		events := make(chan string, 1)
		events <- "denied"
		ticks := make(chan time.Time, 1)
		ticks <- time.Now()
		streamEventChannelWithKeepAlive(w, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil), events,
			func() bool { return true }, func() bool { return false },
			func(event string) (bool, error) {
				_, err := fmt.Fprintf(w, "data: %s\n\n", event)
				return false, err
			}, ticks)
		if strings.Contains(w.Body.String(), "denied") {
			t.Fatalf("attempt %d emitted an event while durable check was due: %s", i, w.Body.String())
		}
	}
}

func TestManagementSSEDoesNotCheckDurableStatePerEvent(t *testing.T) {
	w := httptest.NewRecorder()
	events := make(chan int, 64)
	for i := 0; i < cap(events); i++ {
		events <- i
	}
	close(events)
	checks := 0
	streamEventChannelWithKeepAlive(w, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil), events,
		func() bool { return true }, func() bool { checks++; return true },
		func(int) (bool, error) { return false, nil }, make(chan time.Time))
	if checks != 0 {
		t.Fatalf("durable state checked %d times without a due interval", checks)
	}
}
