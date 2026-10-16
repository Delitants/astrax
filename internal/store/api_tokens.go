// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"astrax/internal/model"
	"golang.org/x/text/cases"
)

var (
	ErrInvalidToken        = errors.New("invalid API token")
	ErrInsufficientScope   = errors.New("insufficient API token scope")
	ErrAPITokenNameExists  = errors.New("API token name already exists")
	ErrAPITokenNotFound    = errors.New("API token not found")
	ErrAPITokenPersistence = errors.New("API token persistence failed")
)

type apiTokenPersistence struct {
	lastAttempt       map[string]time.Time
	pendingRevocation map[string]bool
	dirty             bool
}

func generateAPIToken() (plaintext, prefix, digest string, err error) {
	raw := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, raw); err != nil {
		return "", "", "", errors.New("generate API token failed")
	}
	plaintext = "ax_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, plaintext[:11], hex.EncodeToString(sum[:]), nil
}

func (s *Store) CreateAPIToken(in model.CreateAPITokenRequest) (model.APITokenView, string, error) {
	end, err := s.admitRuntime()
	if err != nil {
		return model.APITokenView{}, "", err
	}
	defer end()
	if err := in.Validate(); err != nil {
		return model.APITokenView{}, "", err
	}
	name := strings.TrimSpace(in.Name)
	folded := cases.Fold().String(name)
	raw, prefix, digest, err := generateAPIToken()
	if err != nil {
		return model.APITokenView{}, "", err
	}
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return model.APITokenView{}, "", errors.New("generate API token identity failed")
	}
	id := "api_" + hex.EncodeToString(idBytes)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.config.APITokens {
		if cases.Fold().String(strings.TrimSpace(token.Name)) == folded {
			return model.APITokenView{}, "", ErrAPITokenNameExists
		}
		if token.ID == id {
			return model.APITokenView{}, "", errors.New("API token identity collision")
		}
	}
	record := model.APITokenRecord{
		ID: id, Name: name, Prefix: prefix, Hash: digest,
		Scopes: slices.Clone(in.Scopes), CreatedAt: s.now().UTC(),
	}
	before := s.config.APITokens
	s.config.APITokens = append(slices.Clone(before), record)
	if err := s.saveLocked(); err != nil {
		s.config.APITokens = before
		return model.APITokenView{}, "", fmt.Errorf("%w: %w", ErrAPITokenPersistence, err)
	}
	return record.View(), raw, nil
}

func (s *Store) ListAPITokens() []model.APITokenView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	views := make([]model.APITokenView, 0, len(s.config.APITokens))
	for _, token := range s.config.APITokens {
		views = append(views, token.View())
	}
	return views
}

func (s *Store) RevokeAPIToken(id string) error {
	end, err := s.admitRuntime()
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.apiTokenIndexLocked(id)
	if index < 0 {
		return ErrAPITokenNotFound
	}
	record := &s.config.APITokens[index]
	if record.RevokedAt != nil && !s.apiTokens.pendingRevocation[id] {
		return nil
	}
	if record.RevokedAt == nil {
		now := s.now().UTC()
		record.RevokedAt = &now
	}
	if s.apiTokens.pendingRevocation == nil {
		s.apiTokens.pendingRevocation = make(map[string]bool)
	}
	s.apiTokens.pendingRevocation[id] = true
	s.apiTokens.dirty = true
	// Fail closed in this process if disk persistence fails. A repeat revoke or
	// terminal flush retries durability; the returned error must not be hidden.
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("%w: %w", ErrAPITokenPersistence, err)
	}
	return nil
}

func (s *Store) apiTokenIndexLocked(id string) int {
	for i := range s.config.APITokens {
		if s.config.APITokens[i].ID == id {
			return i
		}
	}
	return -1
}

func tokenDigestMatches(encoded string, digest [sha256.Size]byte) bool {
	if len(encoded) != hex.EncodedLen(sha256.Size) {
		return false
	}
	stored, err := hex.DecodeString(encoded)
	return err == nil && subtle.ConstantTimeCompare(stored, digest[:]) == 1
}

func (s *Store) AuthenticateAPIToken(raw string, required ...string) (model.APITokenView, error) {
	end, err := s.admitRuntime()
	if err != nil {
		return model.APITokenView{}, err
	}
	defer end()
	if len(raw) != 46 || !strings.HasPrefix(raw, "ax_") {
		return model.APITokenView{}, ErrInvalidToken
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw[3:])
	if err != nil || len(decoded) != 32 {
		return model.APITokenView{}, ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(raw))
	s.mu.RLock()
	// Record fields are immutable after publication except timestamps, which
	// are replaced (never edited through their pointers) under the Store lock.
	records := slices.Clone(s.config.APITokens)
	s.mu.RUnlock()
	id, matches := "", 0
	for _, record := range records {
		if tokenDigestMatches(record.Hash, digest) {
			id = record.ID
			matches++
		}
	}
	if matches != 1 || id == "" {
		return model.APITokenView{}, ErrInvalidToken
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.apiTokenIndexLocked(id)
	if index < 0 {
		return model.APITokenView{}, ErrInvalidToken
	}
	record := &s.config.APITokens[index]
	// Revocation may have committed while the digest was checked outside mu.
	if record.RevokedAt != nil || !tokenDigestMatches(record.Hash, digest) {
		return model.APITokenView{}, ErrInvalidToken
	}
	if err := (model.CreateAPITokenRequest{Name: record.Name, Scopes: record.Scopes}).Validate(); err != nil {
		return model.APITokenView{}, ErrInvalidToken
	}
	for _, scope := range required {
		if !slices.Contains(record.Scopes, scope) {
			return model.APITokenView{}, ErrInsufficientScope
		}
	}
	now := s.now().UTC()
	if s.apiTokens.lastAttempt == nil {
		s.apiTokens.lastAttempt = make(map[string]time.Time)
	}
	attempt, tracked := s.apiTokens.lastAttempt[id]
	if !tracked {
		if record.LastUsedAt != nil {
			attempt = *record.LastUsedAt
		}
		// Anchor to the loaded timestamp once, not the advancing in-memory use.
		s.apiTokens.lastAttempt[id] = attempt
	}
	if record.LastUsedAt == nil || now.After(*record.LastUsedAt) {
		record.LastUsedAt = &now
		s.apiTokens.dirty = true
	}
	if s.apiTokens.dirty && (attempt.IsZero() || now.Sub(attempt) >= time.Minute) {
		s.apiTokens.lastAttempt[id] = now
		if err := s.saveLocked(); err != nil {
			// Last-use metadata is not authorization state. Avoid denying valid
			// requests or logging secrets when this best-effort write fails.
			s.appendLogLocked("warn", "API token last-use persistence failed")
		}
	}
	return record.View(), nil
}

func (s *Store) flushAPITokensLocked() error {
	if !s.apiTokens.dirty {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		return fmt.Errorf("%w: %w", ErrAPITokenPersistence, err)
	}
	return nil
}
