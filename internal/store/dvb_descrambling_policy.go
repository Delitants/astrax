// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"sort"
	"strings"

	"astrax/internal/csa"
	"astrax/internal/model"
)

func dvbPolicyError(field, code string) error {
	return &model.DVBDescramblingError{Field: field, Code: code}
}

func descramblingEnabled(stream model.Stream) bool {
	return stream.DVBDescrambling != nil && stream.DVBDescrambling.Enabled
}

func exactPolicyHex(value string, width int) bool {
	if len(value) != width {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func normalizeDVBDescrambling(in model.Stream) (model.Stream, error) {
	out := cloneStream(in)
	p := out.DVBDescrambling
	if p == nil {
		return out, nil
	}
	p.Algorithm = strings.TrimSpace(p.Algorithm)
	p.CAID = strings.TrimSpace(p.CAID)
	p.Provider = strings.TrimSpace(p.Provider)
	if p.CAID != "" && !exactPolicyHex(p.CAID, 4) {
		return model.Stream{}, dvbPolicyError("dvb_descrambling.caid", "invalid_caid")
	}
	if p.Provider != "" && !exactPolicyHex(p.Provider, 6) {
		return model.Stream{}, dvbPolicyError("dvb_descrambling.provider", "invalid_provider")
	}
	p.CAID = strings.ToUpper(p.CAID)
	p.Provider = strings.ToUpper(p.Provider)
	return out, nil
}

func validateDVBDescrambling(stream model.Stream, profile model.Softcam, backendAvailable bool) error {
	p := stream.DVBDescrambling
	if p == nil || !p.Enabled {
		return nil
	}
	if p.Algorithm != "dvb-csa" {
		return dvbPolicyError("dvb_descrambling.algorithm", "unsupported_algorithm")
	}
	if !exactPolicyHex(p.CAID, 4) {
		return dvbPolicyError("dvb_descrambling.caid", "invalid_caid")
	}
	if !exactPolicyHex(p.Provider, 6) {
		return dvbPolicyError("dvb_descrambling.provider", "invalid_provider")
	}
	if p.ECMPID != nil && (*p.ECMPID <= 0 || *p.ECMPID >= 8191) {
		return dvbPolicyError("dvb_descrambling.ecm_pid", "invalid_ecm_pid")
	}
	if stream.SoftcamID == "" || profile.ID == "" || profile.ID != stream.SoftcamID {
		return dvbPolicyError("softcam_id", "profile_missing")
	}
	if !profile.Enabled {
		return dvbPolicyError("softcam_id", "profile_disabled")
	}
	if kind := normalizeSoftcamType(profile.Type); kind != "cccam" && kind != "newcamd" {
		return dvbPolicyError("softcam_id", "profile_unsupported")
	}
	if !backendAvailable {
		return dvbPolicyError("dvb_descrambling", "backend_unavailable")
	}
	if stream.DVB == nil {
		return dvbPolicyError("dvb_descrambling", "unsupported_input")
	}
	return nil
}

func (s *Store) validateDVBDescramblingLocked(stream model.Stream) error {
	var profile model.Softcam
	if idx := s.findSoftcamIndexLocked(stream.SoftcamID); idx >= 0 {
		profile = s.config.Softcams[idx]
	}
	available, _ := csa.Capability()
	return validateDVBDescrambling(stream, profile, available)
}

// Legacy and incomplete runtimes never enter an ordinary FTA pipeline for an
// enabled policy. Complete structured runtimes use scheduler admission instead.
func descramblingRuntimeGate(stream model.Stream) error {
	if !descramblingEnabled(stream) {
		return nil
	}
	if available, _ := csa.Capability(); !available {
		return dvbPolicyError("dvb_descrambling", "backend_unavailable")
	}
	return dvbPolicyError("dvb_descrambling", "pipeline_unavailable")
}

func (s *Store) blockDescramblingRuntimeUnderGate(stream model.Stream) bool {
	if !stream.Enabled || !descramblingEnabled(stream) {
		return false
	}
	if !s.streamSnapshotIsCurrent(stream) {
		return true
	}
	if s.engine != nil {
		s.quiesceEngineOwnership(stream.ID)
	}
	if s.streamer != nil {
		s.streamer.UnregisterStream(stream.ID)
	}
	s.mu.Lock()
	if s.streamSnapshotIsCurrentLocked(stream) {
		rt := newDVBStreamRuntime(stream, s.now().UTC())
		if err := s.validateDVBDescramblingLocked(stream); err != nil {
			rt.State, rt.LastError = "error", err.Error()
		}
		s.runtime[stream.ID] = rt
	}
	s.mu.Unlock()
	return true
}

// Retire only this row's ordinary attachment. An offline policy is held, never
// submitted to the FTA scheduler or registered as an on-demand placeholder.
func (s *Store) holdDescramblingActionUnderGate(action dvbStreamRuntimeAction) bool {
	s.mu.Lock()
	st, exists := s.currentStructuredLocked(action.ID)
	previous := s.structured.owners[action.ID]
	if !exists || !st.Enabled || !descramblingEnabled(st) {
		s.mu.Unlock()
		return false
	}
	validationErr := s.validateDVBDescramblingLocked(st)
	if validationErr == nil && s.scheduler != nil && s.runtimeSink != nil {
		validationErr = s.scheduler.descramblingAdmissionError(st)
		if validationErr == nil {
			s.mu.Unlock()
			return false
		}
	}
	s.mu.Unlock()
	if s.scheduler == nil || s.runtimeSink == nil {
		s.mu.Lock()
		rt := newDVBStreamRuntime(st, s.now().UTC())
		if validationErr != nil {
			rt.State, rt.LastError = "error", validationErr.Error()
		}
		s.runtime[st.ID] = rt
		s.mu.Unlock()
		return true
	}
	cleanupErr := s.scheduler.Stop(st.ID)
	result := absentOnDemand()
	if previous.idle != nil {
		if err := s.runtimeSink.RemoveStream(*previous.idle); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			result = placeholderOnDemand(previous.idle)
		}
	}
	holdErr := validationErr
	if holdErr == nil {
		holdErr = descramblingRuntimeGate(st)
	}
	s.installStructuredResult(st.ID, st, true, previous, result, false, errors.Join(holdErr, cleanupErr))
	if validationErr == nil && cleanupErr == nil {
		// Only a genuine backend can reach this offline held state. Task 7 owns
		// the eventual PSI/service context; no attachment is created here.
		s.mu.Lock()
		rt := newDVBStreamRuntime(st, s.now().UTC())
		s.runtime[st.ID] = rt
		s.mu.Unlock()
	}
	return true
}

// Cancellation uses the same per-ID owners, inflight counts and reservation
// completion channels as lockStructuredIDs. It adds no admission class or quota.
func (s *Store) lockStructuredIDsContext(ctx context.Context, ids []string) (func(), error) {
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
		release := func() {
			for i := len(releases) - 1; i >= 0; i-- {
				releases[i]()
			}
		}
		for _, id := range order {
			unlock, err := s.dvbStreamLifecycleGates.LockContext(ctx, id)
			if err != nil {
				release()
				return nil, err
			}
			releases = append(releases, unlock)
		}
		if err := s.mu.LockContext(ctx); err != nil {
			release()
			return nil, err
		}
		s.initStructuredLocked()
		var waiting <-chan struct{}
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
			}, nil
		}
		s.mu.Unlock()
		release()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waiting:
		}
	}
}

func (s *Store) admitDVBMutation(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	end, err := s.admitRuntime()
	if err != nil {
		return nil, nil, err
	}
	linked, cancel := context.WithCancel(ctx)
	s.runtimeLifecycle.mu.Lock()
	stop := context.AfterFunc(s.runtimeLifecycle.context, cancel)
	s.runtimeLifecycle.mu.Unlock()
	return linked, func() { stop(); cancel(); end() }, nil
}
