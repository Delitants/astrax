// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import "astrax/internal/model"

// Queue while the accepted state is locked; deliver observers only after unlock.
// Callers keep their lifecycle admission until emit returns.
type dvbEventBatch []model.ResourceEvent

func (b *dvbEventBatch) add(s *Store, kind, id string, payload any) {
	if event, ok := s.queueEvent(kind, id, payload); ok {
		*b = append(*b, event)
	}
}

func (b dvbEventBatch) emit(s *Store) {
	for _, event := range b {
		s.emitQueuedEvent(event)
	}
}

func (b *dvbEventBatch) streamLocked(s *Store, id string) {
	idx, exists := s.streamIndexByID[id]
	if !exists || idx < 0 || idx >= len(s.config.Streams) || s.config.Streams[idx].DVB == nil {
		b.add(s, "dvb.stream.removed", id, nil)
		return
	}
	stream := cloneStream(s.config.Streams[idx])
	if runtime, ok := s.runtime[id]; ok {
		stream.Runtime = cloneStreamRuntime(runtime)
	} else if stream.Enabled {
		stream.Runtime = model.StreamRuntime{State: "starting"}
	} else {
		stream.Runtime = model.StreamRuntime{State: "stopped"}
	}
	projectDescramblingRuntime(&stream)
	b.add(s, "dvb.stream.changed", id, stream)
}

func (b *dvbEventBatch) membershipLocked(s *Store) {
	b.add(s, "dvb.collection.changed", "", model.DVBInvalidation{Streams: true, Groups: true})
}
