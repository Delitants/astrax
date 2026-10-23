// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func enrolledTestManager(t *testing.T) *Manager {
	t.Helper()
	_, m, secret := newTestManager(t)
	if err := m.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAdminSessionsLoginLogoutAndPasswordChange(t *testing.T) {
	m := enrolledTestManager(t)
	if _, err := m.Login("source", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	a, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Token) < 32 || len(a.CSRFToken) < 32 || a.Token == a.CSRFToken {
		t.Fatal("tokens are missing or not independent")
	}
	if found, ok := m.VerifySession(a.Token); !ok || found.CSRFToken != a.CSRFToken {
		t.Fatal("valid session did not verify")
	}
	b, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ChangePassword(a.Token, "wrong", "Another-strong-password_2026!"); err == nil {
		t.Fatal("wrong old password accepted")
	}
	if err := m.ChangePassword(a.Token, testPassword, "Another-strong-password_2026!"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{a.Token, b.Token} {
		if _, ok := m.VerifySession(token); ok {
			t.Fatal("password change retained a session")
		}
	}
	if _, err := m.Login("source", testPassword); err == nil {
		t.Fatal("old password survived change")
	}
	c, err := m.Login("source", "Another-strong-password_2026!")
	if err != nil {
		t.Fatal(err)
	}
	m.Logout(c.Token)
	if _, ok := m.VerifySession(c.Token); ok {
		t.Fatal("logout retained session")
	}
}

func TestAdminSessionsIdleAndAbsoluteExpiry(t *testing.T) {
	m := enrolledTestManager(t)
	base := time.Now().UTC()
	now := base
	m.now = func() time.Time { return now }
	a, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	now = base.Add(sessionIdleTTL + time.Second)
	if _, ok := m.VerifySession(a.Token); ok {
		t.Fatal("idle-expired session accepted")
	}
	now = base
	b, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	for now = base.Add(sessionIdleTTL / 2); now.Before(base.Add(sessionAbsoluteTTL)); now = now.Add(sessionIdleTTL / 2) {
		if _, ok := m.VerifySession(b.Token); !ok {
			t.Fatal("session expired before absolute lifetime")
		}
	}
	now = base.Add(sessionAbsoluteTTL + time.Second)
	if _, ok := m.VerifySession(b.Token); ok {
		t.Fatal("absolute-expired session accepted")
	}
}

func TestAdminSessionValidDoesNotRefreshIdleExpiry(t *testing.T) {
	m := enrolledTestManager(t)
	base := time.Now().UTC()
	now := base
	m.now = func() time.Time { return now }
	session, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	now = base.Add(sessionIdleTTL / 2)
	if !m.SessionActive(session.Token) || !m.SessionValid(session.Token) {
		t.Fatal("active session rejected")
	}
	now = base.Add(sessionIdleTTL)
	if m.SessionActive(session.Token) || m.SessionValid(session.Token) {
		t.Fatal("validity check extended idle lifetime")
	}
}

func TestAdminSessionActiveObservesRevocationAndEviction(t *testing.T) {
	m := enrolledTestManager(t)
	first, err := m.Login("first", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxSessions; i++ {
		if _, err := m.Login(fmt.Sprintf("source-%d", i), testPassword); err != nil {
			t.Fatal(err)
		}
	}
	if m.SessionActive(first.Token) {
		t.Fatal("evicted session accepted")
	}
	current, err := m.Login("current", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	m.Logout(current.Token)
	if m.SessionActive(current.Token) {
		t.Fatal("logged-out session accepted")
	}
}

func TestAdminSessionActiveRequiresPeriodicStateCheck(t *testing.T) {
	m := enrolledTestManager(t)
	session, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(StatePath(m.configPath), 0o644); err != nil {
		t.Fatal(err)
	}
	if !m.SessionActive(session.Token) {
		t.Fatal("in-memory check unexpectedly read the state file")
	}
	if m.SessionValid(session.Token) || m.SessionActive(session.Token) {
		t.Fatal("full state check did not fail closed")
	}
}

func TestAdminSessionsRateLimits(t *testing.T) {
	m := enrolledTestManager(t)
	for i := 0; i < sourceLoginLimit; i++ {
		m.Login("same", "wrong")
	}
	if _, err := m.Login("same", testPassword); err == nil {
		t.Fatal("source limit did not block correct password")
	}
	for i := 0; i < globalLoginLimit-sourceLoginLimit; i++ {
		m.Login(fmt.Sprintf("source-%d", i), "wrong")
	}
	if _, err := m.Login("fresh", testPassword); err == nil {
		t.Fatal("global limit did not block correct password")
	}
}

func TestAdminSetupAttemptsRateLimits(t *testing.T) {
	_, m, _ := newTestManager(t)
	base := time.Now().UTC()
	now := base
	m.now = func() time.Time { return now }
	for i := 0; i < sourceLoginLimit; i++ {
		if !m.AllowSetupAttempt("same") {
			t.Fatalf("setup source rejected before limit at %d", i)
		}
	}
	if m.AllowSetupAttempt("same") {
		t.Fatal("setup source limit did not reject")
	}
	now = base.Add(loginWindow + time.Second)
	if !m.AllowSetupAttempt("same") {
		t.Fatal("setup source limit did not reset")
	}

	_, other, _ := newTestManager(t)
	for i := 0; i < globalLoginLimit; i++ {
		if !other.AllowSetupAttempt(fmt.Sprintf("source-%d", i)) {
			t.Fatalf("setup global rejected before limit at %d", i)
		}
	}
	if other.AllowSetupAttempt("fresh") {
		t.Fatal("setup global limit did not reject")
	}
}

func TestAdminSessionsBoundedAndConcurrent(t *testing.T) {
	m := enrolledTestManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := m.Login(fmt.Sprintf("client-%d", i), testPassword)
			if err == nil {
				m.VerifySession(s.Token)
				m.Logout(s.Token)
			}
		}(i)
	}
	wg.Wait()
	advanced := time.Now().Add(loginWindow + time.Second)
	m.now = func() time.Time { return advanced }
	var first Session
	for i := 0; i < maxSessions+8; i++ {
		s, err := m.Login(fmt.Sprintf("bulk-%d", i), testPassword)
		if err != nil && i < maxSessions {
			t.Fatalf("admission failed before capacity: %v", err)
		}
		if i == 0 {
			first = s
		}
	}
	if len(m.sessions) != maxSessions {
		t.Fatal("session count did not stay at capacity")
	}
	if _, ok := m.VerifySession(first.Token); ok {
		t.Fatal("oldest session was not evicted")
	}
}

func TestAdminSessionsEvictsOldestAtCapacity(t *testing.T) {
	m := enrolledTestManager(t)
	frozen := time.Now().UTC()
	m.now = func() time.Time { return frozen }
	var first Session
	for i := 0; i < maxSessions+1; i++ {
		s, err := m.Login(fmt.Sprintf("source-%d", i), testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = s
		}
	}
	if _, ok := m.VerifySession(first.Token); ok {
		t.Fatal("oldest session survived capacity eviction")
	}
}

func TestAdminSessionsFailClosedOnStateTamper(t *testing.T) {
	config, m, secret := newTestManager(t)
	if err := m.Enroll(secret, testPassword); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login("source", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(StatePath(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.VerifySession(session.Token); ok {
		t.Fatal("session survived insecure state")
	}
	if _, err := m.Login("source", testPassword); err == nil {
		t.Fatal("login accepted insecure state")
	}
}
