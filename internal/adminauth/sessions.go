// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

const (
	sessionIdleTTL     = 30 * time.Minute
	sessionAbsoluteTTL = 12 * time.Hour
	loginWindow        = 5 * time.Minute
	sourceLoginLimit   = 5
	globalLoginLimit   = 32
	maxSessions        = 16
)

// Session carries the opaque browser credential and its derived CSRF value.
type Session struct {
	Token         string
	CSRFToken     string
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
}

type sessionRecord struct {
	sequence      uint64
	issuedAt      time.Time
	idleExpiresAt time.Time
	expiresAt     time.Time
}

func randomToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func tokenDigest(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (m *Manager) csrfToken(token string) string {
	mac := hmac.New(sha256.New, m.csrfKey[:])
	mac.Write([]byte("astrax-admin-csrf:"))
	mac.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) allowLogin(source string, now time.Time) bool {
	return allowAttempt(source, now, &m.windowStart, &m.globalAttempts, m.sourceAttempts)
}

func allowAttempt(source string, now time.Time, windowStart *time.Time, globalAttempts *int, sourceAttempts map[string]int) bool {
	if windowStart.IsZero() || !now.Before(windowStart.Add(loginWindow)) {
		*windowStart = now
		*globalAttempts = 0
		clear(sourceAttempts)
	}
	if len(source) > 128 {
		source = source[:128]
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	if *globalAttempts >= globalLoginLimit || sourceAttempts[source] >= sourceLoginLimit {
		return false
	}
	(*globalAttempts)++
	sourceAttempts[source]++
	return true
}

// AllowSetupAttempt applies independent per-source and global bounds before
// checking the one-use setup credential over HTTP.
func (m *Manager) AllowSetupAttempt(source string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stateCurrentLocked() && m.state.Phase == "pending" && allowAttempt(source, m.now(), &m.setupWindow, &m.setupAttempts, m.setupSources)
}

// Login authenticates the sole administrator and issues a bounded memory-only session.
func (m *Manager) Login(source, password string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stateCurrentLocked() || m.state.Phase != "enrolled" || !m.allowLogin(source, m.now()) {
		return Session{}, errCredentials
	}
	if !verifySecret(password, m.state.PasswordSalt, m.state.PasswordHash) {
		return Session{}, errCredentials
	}
	token, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	now := m.now().UTC()
	for key, record := range m.sessions {
		if !now.Before(record.idleExpiresAt) || !now.Before(record.expiresAt) {
			delete(m.sessions, key)
		}
	}
	if len(m.sessions) >= maxSessions {
		var oldestKey [32]byte
		var oldest uint64
		for key, record := range m.sessions {
			if oldest == 0 || record.sequence < oldest {
				oldestKey, oldest = key, record.sequence
			}
		}
		delete(m.sessions, oldestKey)
	}
	m.nextSessionSeq++
	record := sessionRecord{sequence: m.nextSessionSeq, issuedAt: now, idleExpiresAt: now.Add(sessionIdleTTL), expiresAt: now.Add(sessionAbsoluteTTL)}
	m.sessions[tokenDigest(token)] = record
	return Session{Token: token, CSRFToken: m.csrfToken(token), IdleExpiresAt: record.idleExpiresAt, ExpiresAt: record.expiresAt}, nil
}

func (m *Manager) sessionRecordLocked(token string, now time.Time) ([32]byte, sessionRecord, bool) {
	if m.closed || len(token) != 43 {
		return [32]byte{}, sessionRecord{}, false
	}
	key := tokenDigest(token)
	record, ok := m.sessions[key]
	if !ok {
		return [32]byte{}, sessionRecord{}, false
	}
	if !now.Before(record.idleExpiresAt) || !now.Before(record.expiresAt) {
		delete(m.sessions, key)
		return [32]byte{}, sessionRecord{}, false
	}
	return key, record, true
}

func (m *Manager) sessionLocked(token string, refresh bool) (Session, bool) {
	now := m.now().UTC()
	key, record, ok := m.sessionRecordLocked(token, now)
	if !ok {
		return Session{}, false
	}
	if refresh {
		record.idleExpiresAt = now.Add(sessionIdleTTL)
		if record.idleExpiresAt.After(record.expiresAt) {
			record.idleExpiresAt = record.expiresAt
		}
		m.sessions[key] = record
	}
	return Session{Token: token, CSRFToken: m.csrfToken(token), IdleExpiresAt: record.idleExpiresAt, ExpiresAt: record.expiresAt}, true
}

func (m *Manager) verifySessionLocked(token string) (Session, bool) {
	if !m.stateCurrentLocked() {
		return Session{}, false
	}
	return m.sessionLocked(token, true)
}

// VerifySession refreshes the idle lifetime without extending its absolute lifetime.
func (m *Manager) VerifySession(token string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verifySessionLocked(token)
}

// SessionValid checks durable state, revocation, and expiry without idle refresh.
func (m *Manager) SessionValid(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.stateCurrentLocked() {
		return false
	}
	_, ok := m.sessionLocked(token, false)
	return ok
}

// SessionActive checks in-memory revocation and expiry without disk I/O or idle refresh.
// Streaming callers must also use SessionValid periodically to detect state-file changes.
func (m *Manager) SessionActive(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _, ok := m.sessionRecordLocked(token, m.now().UTC())
	return ok
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenDigest(token))
}

// ChangePassword persists the new verifier before revoking every session.
func (m *Manager) ChangePassword(token, oldPassword, newPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.verifySessionLocked(token); !ok || !strongPassword(newPassword) {
		return errCredentials
	}
	lock, err := lockState(m.configPath)
	if err != nil {
		return err
	}
	defer unlockState(lock)
	current, err := loadCurrentState(m.configPath)
	if err != nil || current != m.state || !verifySecret(oldPassword, current.PasswordSalt, current.PasswordHash) {
		return errCredentials
	}
	salt, err := randomSalt()
	if err != nil {
		return err
	}
	next := authState{Version: stateVersion, Phase: "enrolled", PasswordSalt: encode(salt), PasswordHash: encode(hashSecret(newPassword, salt))}
	if err := persistState(m.configPath, next); err != nil {
		return err
	}
	m.state = next
	clear(m.sessions)
	return nil
}
