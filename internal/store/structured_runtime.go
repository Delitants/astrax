// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"astrax/internal/model"
	"astrax/internal/streamer"
)

type structuredRuntime struct {
	sampledAt        time.Time
	generation       uint64
	configGeneration uint64
	applied          model.Stream
	idle             *sinkRegistrationToken
	active           bool
}
type structuredReservation struct {
	desired                             model.Stream
	exists                              bool
	fingerprint                         tuningKey
	configGeneration, runtimeGeneration uint64
	previous                            structuredRuntime
	done                                chan struct{}
}
type structuredRuntimeState struct {
	inflight     map[string]int
	batchIDs     map[string]bool
	batchDone    chan struct{}
	batch        sync.Mutex
	owners       map[string]structuredRuntime
	configs      map[string]uint64
	reservations map[string]*structuredReservation
	generation   uint64
	batches      uint64
}

func (s *Store) initStructuredLocked() {
	if s.structured.owners == nil {
		s.structured.inflight = make(map[string]int)
		s.structured.owners = make(map[string]structuredRuntime)
		s.structured.configs = make(map[string]uint64)
		s.structured.reservations = make(map[string]*structuredReservation)
	}
}
func (s *Store) bumpStructuredConfigLocked(id string) {
	s.initStructuredLocked()
	s.structured.generation++
	s.structured.configs[id] = s.structured.generation
	// Metadata-only persistence changes no sink ownership, but its new config
	// generation must still be authoritative for an idle first-client callback.
	if owner, ok := s.structured.owners[id]; ok {
		if row, exists := s.currentStructuredLocked(id); exists && owner.applied.Enabled == row.Enabled && sameStructuredApplied(owner.applied, row) {
			owner.applied = cloneStream(row)
			owner.configGeneration = s.structured.configs[id]
			s.structured.owners[id] = owner
		}
	}
}
func desiredFingerprint(st model.Stream) tuningKey {
	st = cloneStream(st)
	st.Runtime = model.StreamRuntime{}
	data, _ := json.Marshal(st)
	return sha256.Sum256(data)
}
func sameStructuredApplied(a, b model.Stream) bool {
	if a.DVB == nil || b.DVB == nil {
		return false
	}
	a = cloneStream(a)
	b = cloneStream(b)
	a.DVB.Normalize()
	b.DVB.Normalize()
	a.DVB.Adapter = placementPolicy(a)
	b.DVB.Adapter = placementPolicy(b)
	return reflect.DeepEqual(a.DVB, b.DVB) && pipelineFingerprint(a) == pipelineFingerprint(b)
}
func (s *Store) lockStructuredIDs(ids []string) func() {
	unique := make(map[string]bool)
	order := make([]string, 0, len(ids))
	for _, id := range ids {
		if !unique[id] {
			unique[id] = true
			order = append(order, id)
		}
	}
	sort.Strings(order)
	for {
		releases := make([]func(), 0, len(order))
		for _, id := range order {
			releases = append(releases, s.dvbStreamLifecycleGates.Lock(id))
		}
		release := func() {
			for i := len(releases) - 1; i >= 0; i-- {
				releases[i]()
			}
		}
		var waiting <-chan struct{}
		s.mu.Lock()
		s.initStructuredLocked()
		for _, id := range order {
			if r := s.structured.reservations[id]; r != nil {
				waiting = r.done
				break
			}
			if s.structured.batchDone != nil && !s.structured.batchIDs[id] {
				waiting = s.structured.batchDone
				break
			}
		}
		if waiting == nil {
			for _, id := range order {
				s.structured.inflight[id]++
			}
			s.mu.Unlock()
			return func() {
				s.mu.Lock()
				for _, id := range order {
					s.structured.inflight[id]--
					if s.structured.inflight[id] == 0 {
						delete(s.structured.inflight, id)
					}
				}
				s.mu.Unlock()
				release()
			}
		}
		s.mu.Unlock()
		release()
		<-waiting
	}
}
func (s *Store) currentStructuredLocked(id string) (model.Stream, bool) {
	idx := s.findStreamIndexLocked(id)
	if idx < 0 || !isStructuredDVBStream(s.config.Streams[idx]) {
		return model.Stream{}, false
	}
	return cloneStream(s.config.Streams[idx]), true
}
func (s *Store) installStructuredResult(id string, st model.Stream, exists bool, previous structuredRuntime, result dvbOnDemandResult, freshAttachment bool, err error) {
	placement, active := s.scheduler.Placement(id)
	s.mu.Lock()
	before := cloneStreamRuntime(s.runtime[id])
	defer func() {
		if exists {
			row := st
			row.Runtime = s.runtime[id]
			projectDescramblingRuntime(&row)
			s.runtime[id] = row.Runtime
		}
		after := cloneStreamRuntime(s.runtime[id])
		var events dvbEventBatch
		if !exists {
			events.add(s, "dvb.stream.removed", id, nil)
		} else if !reflect.DeepEqual(before, after) {
			events.add(s, "dvb.stream.changed", id, after)
		}
		s.mu.Unlock()
		events.emit(s)
	}()
	s.initStructuredLocked()
	owner := previous
	s.structured.generation++
	owner.generation = s.structured.generation
	owner.active = active
	owner.idle = nil
	if result.State == dvbOnDemandPlaceholder && result.Placeholder != nil {
		token := *result.Placeholder
		owner.idle = &token
	}
	if err == nil || owner.idle != nil && (previous.idle == nil || *owner.idle != *previous.idle) {
		owner.applied = cloneStream(st)
		owner.configGeneration = s.structured.configs[id]
	}
	if !active && owner.idle == nil {
		delete(s.structured.owners, id)
	} else {
		s.structured.owners[id] = owner
	}
	if !exists {
		delete(s.runtime, id)
		return
	}
	rt := s.runtime[id]
	if !active || freshAttachment {
		rt.Descrambling = nil
	}
	// Only a confirmed new attachment invalidates per-attachment samples.
	// Metadata/no-op adoption and retained preparation errors keep their evidence.
	if active && err == nil && freshAttachment {
		rt.State = "tuning"
		rt.Signal = nil
		rt.Packets = 0
		rt.BitrateKbps = 0
		owner.sampledAt = time.Time{}
		s.structured.owners[id] = owner
	}
	rt.Placement = nil
	switch {
	case active:
		rt.Placement = &placement
		if rt.State != "running" && rt.State != "locked" {
			rt.State = "tuning"
		}
	case owner.idle != nil:
		rt.State = "on-demand"
		rt.Signal = nil
		rt.Packets = 0
		rt.BitrateKbps = 0
	case !st.Enabled:
		rt.State = "stopped"
		rt.Signal = nil
		rt.Packets = 0
		rt.BitrateKbps = 0
	default:
		rt.State = "error"
	}
	rt.LastError = ""
	if err != nil {
		rt.LastError = err.Error()
		if descramblingEnabled(st) && !active {
			rt.Descrambling = descramblingErrorRuntime(err)
		}
		if !active && owner.idle == nil {
			rt.State = "error"
		}
	}
	if rt.Since.IsZero() {
		rt.Since = s.now().UTC()
	}
	s.runtime[id] = rt
}
func (s *Store) executeStructuredActionUnderGate(action dvbStreamRuntimeAction) {
	if s.scheduler == nil || s.runtimeSink == nil || s.runtimeClosing() {
		return
	}
	s.mu.Lock()
	s.initStructuredLocked()
	st, exists := s.currentStructuredLocked(action.ID)
	previous := s.structured.owners[action.ID]
	s.mu.Unlock()
	result := absentOnDemand()
	if previous.active {
		result = dvbOnDemandResult{State: dvbOnDemandActive}
	} else if previous.idle != nil {
		result = placeholderOnDemand(previous.idle)
	}
	var err error
	freshAttachment := false
	if !exists || !st.Enabled {
		if previous.idle != nil {
			err = s.runtimeSink.RemoveStream(*previous.idle)
			result = absentOnDemand()
		} else {
			err = s.scheduler.Stop(action.ID)
			result = absentOnDemand()
		}
	} else if _, prepErr := s.scheduler.prepareStream(st); prepErr != nil {
		err = prepErr
	} else if st.OnDemand {
		switch {
		case previous.active && !previous.applied.OnDemand:
			err = s.scheduler.Stop(st.ID)
			result = absentOnDemand()
			if err == nil {
				var token sinkRegistrationToken
				token, err = s.runtimeSink.RegisterStream(st, nil, nil)
				if token.Generation != 0 {
					result = placeholderOnDemand(&token)
				}
			}
		case previous.active:
			if action.Action == "restart" || !sameStructuredApplied(previous.applied, st) {
				result, err = s.scheduler.RestartOnDemand(st)
				freshAttachment = err == nil && result.State == dvbOnDemandActive
			}
		case previous.idle != nil:
			if action.Action == "restart" || !sameStructuredApplied(previous.applied, st) {
				var token sinkRegistrationToken
				token, err = s.runtimeSink.ReplacePlaceholder(*previous.idle, st)
				if token.Generation != 0 {
					result = placeholderOnDemand(&token)
				}
			}
		default:
			var token sinkRegistrationToken
			token, err = s.runtimeSink.RegisterStream(st, nil, nil)
			if token.Generation != 0 {
				result = placeholderOnDemand(&token)
			}
		}
	} else {
		if previous.idle != nil {
			err = s.runtimeSink.RemoveStream(*previous.idle)
			result = absentOnDemand()
		}
		if err == nil {
			if previous.active {
				if action.Action == "restart" || !sameStructuredApplied(previous.applied, st) {
					err = s.scheduler.Restart(st)
					freshAttachment = err == nil
				}
			} else {
				err = s.scheduler.Start(st)
				freshAttachment = err == nil
			}
		}
	}
	s.installStructuredResult(action.ID, st, exists, previous, result, freshAttachment, err)
}

// A batch is built only from live, gate-bound reservations, not its caller's
// earlier candidate slice. Waiters release every ID gate before waiting.
func (s *Store) reconcileStructuredRuntime() {
	if s.scheduler == nil || s.runtimeSink == nil {
		return
	}
	end, err := s.admitRuntime()
	if err != nil {
		return
	}
	defer end()
	s.structured.batch.Lock()
	defer s.structured.batch.Unlock()
	if s.runtimeClosing() {
		return
	}
	s.mu.Lock()
	s.initStructuredLocked()
	ids := make(map[string]bool)
	for _, id := range s.dvbStreamIDs {
		ids[id] = true
	}
	for id := range s.structured.owners {
		ids[id] = true
	}
	for id := range s.structured.inflight {
		ids[id] = true
	}
	s.structured.batchIDs = ids
	s.structured.batchDone = make(chan struct{})
	s.mu.Unlock()
	order := make([]string, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Strings(order)
	records := make(map[string]*structuredReservation, len(order))
	defer func() {
		s.mu.Lock()
		for id, r := range records {
			if s.structured.reservations[id] == r {
				delete(s.structured.reservations, id)
				close(r.done)
			}
		}
		close(s.structured.batchDone)
		s.structured.batchDone = nil
		s.structured.batchIDs = nil
		s.mu.Unlock()
	}()

	desired := make([]model.Stream, 0, len(order))
	idle := make(map[string]sinkRegistrationToken)
	setupErrors := make(map[string]error)
	blockedPolicies := make(map[string]bool)
	for _, id := range order {
		if s.testHookBeforeStructuredReservation != nil {
			s.testHookBeforeStructuredReservation(id)
		}
		release := s.lockStructuredIDs([]string{id})
		s.mu.Lock()
		st, exists := s.currentStructuredLocked(id)
		var policyErr error
		if exists && st.Enabled && descramblingEnabled(st) {
			policyErr = s.validateDVBDescramblingLocked(st)
		}
		if s.structured.configs[id] == 0 {
			s.bumpStructuredConfigLocked(id)
		}
		old := s.structured.owners[id]
		r := &structuredReservation{desired: st, exists: exists, fingerprint: desiredFingerprint(st), configGeneration: s.structured.configs[id], runtimeGeneration: old.generation, previous: old, done: make(chan struct{})}
		s.structured.reservations[id] = r
		s.mu.Unlock()
		records[id] = r
		if policyErr != nil {
			setupErrors[id] = policyErr
			blockedPolicies[id] = true
		}
		if exists && st.Enabled && policyErr == nil {
			if _, err := s.scheduler.prepareStream(st); err == nil {
				if st.OnDemand && !old.active && old.idle == nil {
					token, e := s.runtimeSink.RegisterStream(st, nil, nil)
					setupErrors[id] = e
					if token.Generation != 0 {
						old.idle = &token
						old.applied = cloneStream(st)
						r.previous = old
					}
				}
				if !st.OnDemand && old.idle != nil {
					setupErrors[id] = s.runtimeSink.RemoveStream(*old.idle)
					old.idle = nil
					r.previous = old
				}
			}
		}
		if exists {
			runtimeIntent := cloneStream(r.desired)
			// A loaded invalid policy must retire only its own runtime, not open
			// a frontend while waiting for registry acquisition to reject it.
			if blockedPolicies[id] {
				runtimeIntent.Enabled = false
			}
			desired = append(desired, runtimeIntent)
		}
		if old.idle != nil {
			idle[id] = *old.idle
		}
		release()
	}
	s.mu.Lock()
	s.structured.batches++
	s.mu.Unlock()
	results := s.scheduler.Reconcile(desired, idle)
	for _, row := range results {
		r := records[row.StreamID]
		if r == nil {
			continue
		}
		release := s.dvbStreamLifecycleGates.Lock(row.StreamID)
		s.mu.RLock()
		current, exists := s.currentStructuredLocked(row.StreamID)
		owner := s.structured.owners[row.StreamID]
		valid := s.structured.reservations[row.StreamID] == r && s.structured.configs[row.StreamID] == r.configGeneration && owner.generation == r.runtimeGeneration && exists == r.exists && desiredFingerprint(current) == r.fingerprint
		s.mu.RUnlock()
		result := absentOnDemand()
		if row.OnDemand != nil {
			result = *row.OnDemand
		}
		row.Err = errors.Join(setupErrors[row.StreamID], row.Err)
		if valid {
			if result.Placeholder != nil {
				if !r.exists || !r.desired.Enabled || blockedPolicies[row.StreamID] {
					row.Err = errors.Join(row.Err, s.runtimeSink.RemoveStream(*result.Placeholder))
					result = absentOnDemand()
				} else if row.Err == nil && !sameStructuredApplied(r.previous.applied, r.desired) {
					token, e := s.runtimeSink.ReplacePlaceholder(*result.Placeholder, r.desired)
					row.Err = errors.Join(row.Err, e)
					if token.Generation != 0 {
						result = placeholderOnDemand(&token)
					}
				}
			}
			freshAttachment := row.Action == dvbReconcileStart || row.Action == dvbReconcileRefresh
			s.installStructuredResult(row.StreamID, r.desired, r.exists, r.previous, result, freshAttachment, row.Err)
		} else if result.Placeholder != nil {
			s.recordRuntimeCleanup(s.runtimeSink.RemoveStream(*result.Placeholder))
		}
		s.mu.Lock()
		if s.structured.reservations[row.StreamID] == r {
			delete(s.structured.reservations, row.StreamID)
			close(r.done)
		}
		s.mu.Unlock()
		release()
	}
}

func (s *Store) structuredOnDemandUnderGate(st model.Stream, expected *streamer.RegistrationToken, start bool) {
	if s.scheduler == nil || s.runtimeSink == nil || expected == nil || s.runtimeClosing() {
		return
	}
	s.mu.RLock()
	previous := s.structured.owners[st.ID]
	configGeneration := s.structured.configs[st.ID]
	s.mu.RUnlock()
	result := absentOnDemand()
	var err error
	if start {
		if previous.active || previous.idle == nil || *previous.idle != (sinkRegistrationToken{StreamID: expected.StreamID, Generation: expected.Generation}) || previous.configGeneration != configGeneration || !sameStructuredApplied(previous.applied, st) {
			return
		}
		result, err = s.scheduler.StartOnDemand(st, *previous.idle)
	} else {
		if previous.idle != nil {
			return
		}
		if !previous.active {
			return
		}
		result, err = s.scheduler.SuspendOnDemand(st.ID)
	}
	s.installStructuredResult(st.ID, st, true, previous, result, start && result.State == dvbOnDemandActive, err)
}
func (s *Store) onDemandCallbackCurrent(token streamer.RegistrationToken, start bool) bool {
	if s.runtimeDeps != nil {
		return s.runtimeDeps.OnDemandCallbackCurrent(token, start)
	}
	return s.streamer != nil && s.streamer.OnDemandCallbackCurrent(token, start)
}

func hashRuntimeValue(value any) tuningKey {
	data, _ := json.Marshal(value)
	return sha256.Sum256(data)
}

// Persisting desired configuration must not fabricate a runtime transition.
// The exact runtime owner/result decides whether sampled state was retained.
func (s *Store) prepareStructuredRuntimeLocked(id string, st model.Stream, now time.Time) {
	if s.scheduler != nil {
		if _, exists := s.runtime[id]; exists {
			return
		}
	}
	s.runtime[id] = newDVBStreamRuntime(st, now)
}
