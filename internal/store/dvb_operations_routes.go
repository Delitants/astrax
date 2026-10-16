// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"fmt"
	"strings"

	"astrax/internal/model"
	"astrax/internal/streamer"
)

// The caller holds Store.mu and its existing stream lifecycle gate. The
// tentative runtime namespace claim spans save/rollback, not runtime I/O.
func (s *Store) saveStreamOutputLocked(stream model.Stream) error {
	if s.streamer != nil {
		release, err := s.streamer.ReserveConfiguredOutput(stream)
		if err != nil {
			if errors.Is(err, streamer.ErrStreamPathConflict) {
				return fmt.Errorf("output route duplicates runtime claim: %w", err)
			}
			return err
		}
		defer release()
	}
	return s.saveLocked()
}

// All public configured-output writers call this under s.mu, before saving.
// Disabled rows claim routes too. Syntax errors retain the existing caller's
// validation policy (Import validates syntax, ordinary edits are persistence-first).
func (s *Store) validateConfiguredOutputLocked(stream model.Stream) error {
	output := strings.TrimSpace(stream.OutputURL)
	route, _ := streamer.ValidateOutputPath(output)
	for _, current := range s.config.Streams {
		if current.ID == stream.ID && stream.ID != "" {
			continue
		}
		if strings.TrimSpace(current.OutputURL) == output {
			return fmt.Errorf("output_url duplicates stream %s", current.ID)
		}
		other, _ := streamer.ValidateOutputPath(current.OutputURL)
		if streamer.OutputPathsConflict(route, other) {
			return fmt.Errorf("output route %q duplicates stream %s", route, current.ID)
		}
	}
	return nil
}
