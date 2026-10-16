// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"fmt"
	"sync"

	"astrax/internal/model"
)

// SetConfiguredOutputs mirrors committed Store configuration, including disabled
// rows. The Store serializes calls with its mutation lock. Runtime reservations
// and published owners remain separate and are never retired by this update.
func (st *Streamer) SetConfiguredOutputs(streams []model.Stream) {
	paths := make(map[string]string, len(streams))
	for _, stream := range streams {
		if path, err := ValidateOutputPath(stream.OutputURL); err == nil && path != "" {
			paths[stream.ID] = path
		}
	}
	st.mu.Lock()
	if !st.closed {
		st.configuredOutputs = paths
	}
	st.mu.Unlock()
}

func (st *Streamer) configuredOutputConflictLocked(path, id string) string {
	for owner, configured := range st.configuredOutputs {
		if owner != id && OutputPathsConflict(path, configured) {
			return owner
		}
	}
	return ""
}

// ReserveConfiguredOutput fences a prospective Store save without holding a
// Streamer mutex across filesystem I/O. Call while holding the Store mutation
// lock; on success mirror the committed configuration before releasing. The
// release must run on failed saves too, and before executing runtime actions.
func (st *Streamer) ReserveConfiguredOutput(stream model.Stream) (func(), error) {
	path, err := ValidateOutputPath(stream.OutputURL)
	if err != nil || path == "" {
		// Ordinary Store edits retain their existing malformed-output policy.
		return func() {}, nil
	}
	if err := st.beginOperation(); err != nil {
		return nil, err
	}
	st.mu.Lock()
	if st.closing || st.closed {
		st.mu.Unlock()
		st.endOperation()
		return nil, ErrStreamerClosed
	}
	// Never wait for callbacks or source cleanup while the caller holds Store.mu.
	// Taking the existing gate non-blockingly also prevents a same-ID foreign
	// generation from appearing between the exact-owner check and persistence.
	if st.streamGates[stream.ID] != nil || st.reservations[stream.ID] != nil {
		st.mu.Unlock()
		st.endOperation()
		return nil, fmt.Errorf("%w: %s", ErrStreamReserved, stream.ID)
	}
	gate := &streamOperationGate{refs: 1}
	gate.mu.Lock()
	st.streamGates[stream.ID] = gate
	end := func() {
		gate.mu.Unlock()
		st.releaseStreamGate(stream.ID, gate)
		st.endOperation()
	}
	prior := st.streams[stream.ID]
	conflict := st.configuredOutputConflictLocked(path, stream.ID)
	if conflict == "" {
		// Only this exact, gate-protected published generation is exempt.
		// No reservation is exempt, even if its string ID happens to match.
		conflict = st.pathConflictLocked(path, prior)
	}
	if conflict != "" {
		st.mu.Unlock()
		end()
		return nil, fmt.Errorf("%w: %s is owned by %s", ErrStreamPathConflict, path, conflict)
	}
	generation, err := st.allocateGenerationLocked(stream.ID)
	if err != nil {
		st.mu.Unlock()
		end()
		return nil, err
	}
	reservation := &registrationReservation{id: stream.ID, generation: generation, path: path, prior: prior, valid: true}
	if prior != nil {
		reservation.priorGeneration = prior.generation
	}
	st.reservations[stream.ID] = reservation
	st.pathReservations[path] = reservation
	st.reservedPaths.add(path, pathPublication{streamID: stream.ID, generation: generation})
	st.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			st.releaseRegistrationReservation(reservation)
			end()
		})
	}, nil
}
