// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"astrax/internal/model"
	"errors"
	"fmt"
	"sort"
)

func (s *dvbScheduler) Reconcile(input []model.Stream, idle map[string]sinkRegistrationToken) []dvbReconcileResult {
	end, admissionErr := s.admit()
	if end != nil {
		defer end()
	}
	s.mu.Lock()
	health := s.health
	// One existing-ID traversal per batch, not one graph walk per row.
	union := make(map[string]struct{}, len(input)+len(s.attachments)+len(idle))
	currentDemand := make(map[string]bool)
	for id, a := range s.attachments {
		union[id] = struct{}{}
		if a != nil {
			currentDemand[id] = a.stream.OnDemand
		}
		if s.counters != nil {
			s.counters.AttachmentVisits++
		}
	}
	s.mu.Unlock()
	for id, token := range idle {
		if validStreamID(id) == nil && token.StreamID == id && token.Generation != 0 {
			union[id] = struct{}{}
			currentDemand[id] = true
		}
	}
	desired := make(map[string]model.Stream, len(input))
	first := make(map[string]int)
	duplicates := make(map[string]bool)
	var results []dvbReconcileResult
	for i, row := range input {
		if row.ID == "" {
			result := dvbReconcileResult{InputIndex: i, Action: dvbReconcileError, Err: errors.New("empty stream ID")}
			if row.OnDemand {
				state := absentOnDemand()
				result.OnDemand = &state
			}
			results = append(results, result)
			continue
		}
		union[row.ID] = struct{}{}
		if _, ok := first[row.ID]; ok {
			duplicates[row.ID] = true
			currentDemand[row.ID] = currentDemand[row.ID] || row.OnDemand
			continue
		}
		first[row.ID] = i
		desired[row.ID] = cloneStream(row)
		currentDemand[row.ID] = currentDemand[row.ID] || row.OnDemand
	}
	ids := make([]string, 0, len(union))
	for id := range union {
		ids = append(ids, id)
	}
	comparisons := uint64(0)
	sort.Slice(ids, func(i, j int) bool { comparisons++; return ids[i] < ids[j] })
	s.mu.Lock()
	if s.counters != nil {
		s.counters.Sorts++
		s.counters.Comparisons += comparisons
	}
	s.mu.Unlock()
	for _, id := range ids {
		index, exists := first[id]
		if !exists {
			index = -1
		}
		row := dvbReconcileResult{StreamID: id, InputIndex: index, Action: dvbReconcileNoop}
		result := absentOnDemand()
		var token *sinkRegistrationToken
		if t, ok := idle[id]; ok && t.StreamID == id && t.Generation != 0 {
			copy := t
			token = &copy
		}
		s.mu.Lock()
		result = s.stateLocked(id, token)
		s.mu.Unlock()
		err := admissionErr
		if err == nil {
			err = health
		}
		if err == nil && duplicates[id] {
			err = fmt.Errorf("duplicate stream ID %q", id)
		}
		if supplied, ok := idle[id]; err == nil && ok && (supplied.StreamID != id || supplied.Generation == 0) {
			err = schedulerError(ErrDVBSchedulerOwnership, "malformed idle placeholder token")
		}
		if err == nil {
			unlock, gateErr := s.gate(id)
			err = gateErr
			if err == nil {
				row.Action, result, err = s.reconcileOne(id, desired[id], exists, token)
				unlock()
			}
		}
		if err != nil {
			row.Action = dvbReconcileError
			row.Err = err
		}
		if currentDemand[id] {
			copy := result
			row.OnDemand = &copy
		}
		results = append(results, row)
	}
	return results
}
func (s *dvbScheduler) reconcileOne(id string, input model.Stream, exists bool, idle *sinkRegistrationToken) (dvbReconcileAction, dvbOnDemandResult, error) {
	s.mu.Lock()
	state := s.stateLocked(id, idle)
	health := s.health
	active := s.attachments[id] != nil
	s.mu.Unlock()
	if health != nil {
		return dvbReconcileError, state, health
	}
	if err := validStreamID(id); err != nil {
		return dvbReconcileError, state, err
	}
	if active && idle != nil {
		return dvbReconcileError, state, schedulerError(ErrDVBSchedulerOwnership, "active attachment cannot also have Store-owned idle state")
	}
	if !exists || !input.Enabled {
		if !active {
			if idle != nil {
				// Stop is the removal decision, not permission for ID-only removal.
				// Store still owns this exact token and must finalize under its reservation.
				return dvbReconcileStop, state, nil
			}
			return dvbReconcileNoop, state, nil
		}
		result, err := s.detach(id, sinkDetachRemove)
		return dvbReconcileStop, result, err
	}
	st, err := s.prepareStream(input)
	if err != nil {
		return dvbReconcileError, state, err
	}
	if st.OnDemand && !active {
		if idle == nil {
			return dvbReconcileError, absentOnDemand(), schedulerError(ErrDVBSchedulerOwnership, "idle on-demand row requires exact Store token")
		}
		return dvbReconcileNoop, placeholderOnDemand(idle), nil
	}
	if !active {
		if idle != nil {
			return dvbReconcileError, state, schedulerError(ErrDVBSchedulerOwnership, "Store must remove idle placeholder before always-on start")
		}
		result, err := s.startPrepared(st, nil, nil)
		return dvbReconcileStart, result, err
	}
	return s.replacePrepared(st, false)
}
