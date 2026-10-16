// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"math"

	"astrax/internal/model"
	"astrax/internal/softcam"
	"astrax/internal/streamer"
)

const runtimeApplicationFailed = "runtime_application_failed"

type CommittedRuntimeError struct{ cause error }

func (e *CommittedRuntimeError) Error() string {
	return "settings were saved but runtime application failed; prior worker may remain active until recovered"
}
func (e *CommittedRuntimeError) Unwrap() error { return e.cause }

func initialSoftcamRuntime(profile model.Softcam, state string) model.SoftcamRuntime {
	rt := model.SoftcamRuntime{State: state}
	if normalizeSoftcamType(profile.Type) == "cccam" {
		no, zero := false, 0
		rt.Authenticated = &no
		descrambling := false
		rt.DescramblingSupported = &descrambling
		rt.CardsObserved = &zero
	}
	return rt
}

// Persistence must be acknowledged before calling this under s.mu. Preparation
// performs no I/O; the caller applies its immutable command after unlocking.
func (s *Store) prepareSoftcamLocked(profile model.Softcam, action softcam.RuntimeAction) (*softcam.RuntimeCommand, error) {
	if !s.disableRuntime {
		if s.softcam == nil {
			return nil, errors.New("softcam manager unavailable")
		}
		command, err := s.softcam.Prepare(profile, action)
		if err != nil {
			return nil, err
		}
		s.softGenerations[profile.ID] = command.Generation()
		return command, nil
	}
	if s.softGenerations[profile.ID] == math.MaxUint64 {
		return nil, errors.New("softcam generation exhausted")
	}
	s.softGenerations[profile.ID]++
	return nil, nil
}
func (s *Store) softcamApplicationFailedLocked(profile model.Softcam, removed bool, cause error) error {
	s.softGenerations[profile.ID] = 0
	if !removed {
		rt := initialSoftcamRuntime(profile, "error")
		rt.Since = s.now().UTC()
		rt.ErrorCode = runtimeApplicationFailed
		rt.LastError = (&CommittedRuntimeError{}).Error()
		s.softRuntime[profile.ID] = rt
	}
	return &CommittedRuntimeError{cause: cause}
}
func (s *Store) applySoftcamCommand(profile model.Softcam, command *softcam.RuntimeCommand, removed bool, preparedErr error) error {
	// Prepare already revoked the old native identity. This scan cannot revoke
	// a newer healthy binding, even when a delayed command is now a no-op.
	if s.scheduler != nil {
		s.scheduler.revokeStaleDescramblingProfile(profile.ID)
	}
	err := preparedErr
	if err == nil && command != nil {
		err = command.Apply()
	}
	if err == nil {
		return nil
	}
	s.mu.Lock()
	// A newer acknowledged intent must not be invalidated by a delayed failure.
	if preparedErr == nil && command != nil && s.softGenerations[profile.ID] == command.Generation() {
		s.softcamApplicationFailedLocked(profile, removed, err)
	}
	s.mu.Unlock()
	s.broadcast()
	return &CommittedRuntimeError{cause: err}
}

func (s *Store) prepareSoftcamStateLocked(profile model.Softcam, action softcam.RuntimeAction, removed bool) (*softcam.RuntimeCommand, error) {
	command, err := s.prepareSoftcamLocked(profile, action)
	if err != nil {
		return nil, s.softcamApplicationFailedLocked(profile, removed, err)
	}
	if !removed {
		state := "starting"
		if action == softcam.ActionStop || !profile.Enabled {
			state = "stopped"
		}
		rt := initialSoftcamRuntime(profile, state)
		rt.Since = s.now().UTC()
		s.softRuntime[profile.ID] = rt
	}
	return command, nil
}

// Recover only on a new ready connection, not on uptime heartbeats. The native
// registry still decides authority; an event never grants access to ECM/keys.
func (s *Store) recoverDescramblingProfile(profile string, generation uint64) {
	if s.scheduler == nil {
		return
	}
	s.mu.RLock()
	var ids []string
	for _, st := range s.config.Streams {
		if st.Enabled && isStructuredDVBStream(st) && descramblingEnabled(st) && st.SoftcamID == profile {
			ids = append(ids, st.ID)
		}
	}
	s.mu.RUnlock()
	for _, id := range ids {
		release := s.lockStructuredIDs([]string{id})
		s.mu.RLock()
		st, exists := s.currentStructuredLocked(id)
		valid := exists && st.Enabled && descramblingEnabled(st) && st.SoftcamID == profile && s.softGenerations[profile] == generation && s.softRuntime[profile].State == "running"
		previous := s.structured.owners[id]
		s.mu.RUnlock()
		if valid {
			retired, activeToken := s.scheduler.descramblingSourceRetired(id)
			if st.OnDemand {
				var token streamer.RegistrationToken
				start := previous.idle != nil
				if start {
					token = streamer.RegistrationToken{StreamID: previous.idle.StreamID, Generation: previous.idle.Generation}
				} else {
					token = streamer.RegistrationToken{StreamID: activeToken.StreamID, Generation: activeToken.Generation}
				}
				if (start || retired) && s.onDemandCallbackCurrent(token, start) {
					s.structuredOnDemandUnderGate(st, &token, start)
				}
			} else if !previous.active || retired {
				s.runDVBStreamRuntimeActionsUnderGate([]dvbStreamRuntimeAction{{ID: id, Stream: st, Action: "restart"}})
			}
		}
		release()
	}
}

func cloneSoftcamSnapshot(snapshot model.StateSnapshot) model.StateSnapshot {
	profiles := make([]model.Softcam, len(snapshot.Softcams))
	copy(profiles, snapshot.Softcams)
	for i := range profiles {
		profiles[i].Runtime = profiles[i].Runtime.Clone()
	}
	snapshot.Softcams = profiles
	return snapshot
}
