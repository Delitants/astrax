// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"astrax/internal/model"
)

func (s *Store) ExternalAPISettings() model.ExternalAPISettings {
	return s.Settings().ExternalAPI
}

// ValidateExternalAPISettings is a preflight; the setter repeats it under the
// persistence lock so concurrent token revocation cannot bypass admission.
func (s *Store) ValidateExternalAPISettings(in model.ExternalAPISettings) error {
	end, err := s.admitRuntime()
	if err != nil {
		return err
	}
	defer end()
	normalized, err := in.Normalized()
	if err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.validateExternalAPILocked(normalized)
}

func (s *Store) validateExternalAPILocked(in model.ExternalAPISettings) error {
	if !in.Enabled {
		return nil
	}
	if err := externalAPIPortConflict(in.Port, s.config.Settings); err != nil {
		return err
	}
	ids, hashes := map[string]int{}, map[string]int{}
	for _, token := range s.config.APITokens {
		ids[token.ID]++
		hashes[strings.ToLower(token.Hash)]++
	}
	for _, token := range s.config.APITokens {
		digest, err := hex.DecodeString(token.Hash)
		valid := (model.CreateAPITokenRequest{Name: token.Name, Scopes: token.Scopes}).Validate() == nil
		if token.RevokedAt == nil && token.ID != "" && ids[token.ID] == 1 && hashes[strings.ToLower(token.Hash)] == 1 && err == nil && len(digest) == 32 && valid {
			return nil
		}
	}
	return errors.New("create an active API token before enabling the external listener")
}

func externalAPIPortConflict(port int, settings model.Settings) error {
	if port == settings.HTTPPlayPort || port == settings.SRTPlayPort {
		return errors.New("external API port conflicts with a playback port")
	}
	addresses := []string{settings.ControlListen, settings.ControlListenHTTPS}
	defaults := []string{model.DefaultSettings().ControlListen, model.DefaultSettings().ControlListenHTTPS}
	for i, address := range addresses {
		if address == "" {
			address = defaults[i]
		}
		_, p, err := net.SplitHostPort(address)
		number, lookupErr := net.LookupPort("tcp", p)
		if err == nil && lookupErr == nil && number == port {
			return errors.New("external API port conflicts with a management port")
		}
	}
	return nil
}

// SetExternalAPISettings persists only the independent listener settings. The
// manager must bind its candidate before calling this method.
func (s *Store) SetExternalAPISettings(in model.ExternalAPISettings) error {
	end, err := s.admitRuntime()
	if err != nil {
		return err
	}
	defer end()
	normalized, err := in.Normalized()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateExternalAPILocked(normalized); err != nil {
		return err
	}
	before := s.config.Settings.ExternalAPI
	s.config.Settings.ExternalAPI = normalized
	if err := s.saveLocked(); err != nil {
		s.config.Settings.ExternalAPI = before
		return fmt.Errorf("persist external API settings: %w", err)
	}
	s.appendLogLocked("info", "external API settings updated")
	return nil
}
