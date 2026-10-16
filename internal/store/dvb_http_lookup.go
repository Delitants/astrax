// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"

	"astrax/internal/model"
)

var ErrDVBStreamNotFound = errors.New("DVB stream not found")

// DVBStream returns an owned snapshot without exposing external streams through
// the DVB management API. streamByID uses the existing exact-ID index.
func (s *Store) DVBStream(id string) (model.Stream, error) {
	stream, err := s.streamByID(id)
	if err != nil || stream.DVB == nil {
		return model.Stream{}, ErrDVBStreamNotFound
	}
	return stream, nil
}

func (s *Store) DVBGroupCounts() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := make(map[string]int, len(s.groupStreamIDs)+1)
	counts[""] = 0
	for id, streams := range s.groupStreamIDs {
		counts[id] = len(streams)
	}
	return counts
}
