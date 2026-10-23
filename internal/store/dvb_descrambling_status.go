// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"astrax/internal/csa"
	"astrax/internal/model"
	"astrax/internal/mpegts"
	"astrax/internal/packetbudget"
	"astrax/internal/softcam"
)

// Native capability is probed only during runtime activation, never at package
// initialization or while projecting a dormant Store snapshot.
var descramblingBuildBackend atomic.Value
var descramblingBuildBackendOnce sync.Once

func activateDescramblingBuildBackend() {
	descramblingBuildBackendOnce.Do(func() {
		available, reason := csa.Capability()
		descramblingBuildBackend.Store(model.DVBDescramblingBackend{Available: available, Reason: reason})
	})
}

func cachedDescramblingBuildBackend() model.DVBDescramblingBackend {
	if value := descramblingBuildBackend.Load(); value != nil {
		return value.(model.DVBDescramblingBackend)
	}
	return model.DVBDescramblingBackend{Reason: "backend_unavailable"}
}

func (s *Store) DVBDescramblingStatus(id string) (model.DVBDescramblingStatus, error) {
	end, err := s.admitRuntime()
	if err != nil {
		return model.DVBDescramblingStatus{}, err
	}
	defer end()
	st, err := s.DVBStream(id)
	if err != nil {
		return model.DVBDescramblingStatus{}, err
	}
	return s.descramblingStatusForStream(st), nil
}

func descramblingBaseRuntime(st model.Stream) *model.DVBDescramblingRuntime {
	rt := &model.DVBDescramblingRuntime{State: "waiting_psi", Reason: "catalog_unavailable"}
	if !st.Enabled {
		rt.State, rt.Reason = "stopped", "stream_stopped"
	} else if !descramblingEnabled(st) {
		rt.State, rt.Reason = "stopped", "policy_disabled"
	}
	return rt
}

func projectDescramblingRuntime(st *model.Stream) {
	if st.DVB == nil || st.DVBDescrambling == nil {
		st.Runtime.Descrambling = nil
		return
	}
	if !st.Enabled || !descramblingEnabled(*st) || st.Runtime.Descrambling == nil {
		st.Runtime.Descrambling = descramblingBaseRuntime(*st)
		if st.Enabled && descramblingEnabled(*st) {
			if !cachedDescramblingBuildBackend().Available {
				st.Runtime.Descrambling.State, st.Runtime.Descrambling.Reason = "unsupported", "backend_unavailable"
			}
		}
	}
}

// Only scalar metadata crosses this boundary. In particular this interface
// cannot grant packet publication, acquire keys, or submit ECM requests.
type descramblingStatusReader interface {
	DescramblingStatus() (softcam.DescramblingStatusSnapshot, bool)
}

func (source *dvbDescramblingSource) DescramblingStatus() (softcam.DescramblingStatusSnapshot, bool) {
	closed := softcam.DescramblingStatusSnapshot{DescramblingPipelineStatus: softcam.DescramblingPipelineStatus{State: "closed"}}
	if source.closing.Load() || !source.tap.active.Load() {
		return closed, true
	}
	if service, ok := source.tap.service.(interface{ Revoked() bool }); ok && service.Revoked() {
		return closed, true
	}
	if reader, ok := source.output.(descramblingStatusReader); ok {
		return reader.DescramblingStatus()
	}
	return softcam.DescramblingStatusSnapshot{DescramblingPipelineStatus: softcam.DescramblingPipelineStatus{State: "waiting_keys"}}, false
}

func descramblingCandidates(service mpegts.Service) ([]model.DVBDescramblingCandidate, bool) {
	out := make([]model.DVBDescramblingCandidate, 0)
	type route struct{ caid, pid uint16 }
	index := make(map[route]int)
	for _, ca := range service.CADescriptors {
		if ca.ECMPID == 0 || ca.ECMPID >= 8191 || ca.Scope != mpegts.CAProgram && ca.Scope != mpegts.CAElementary {
			return nil, false
		}
		key := route{ca.CAID, ca.ECMPID}
		i, found := index[key]
		if !found {
			if len(out) == 16 {
				return nil, false
			}
			i = len(out)
			index[key] = i
			out = append(out, model.DVBDescramblingCandidate{CAID: fmt.Sprintf("%04X", ca.CAID), ECMPID: ca.ECMPID, ESPIDs: []uint16{}})
		}
		if ca.Scope == mpegts.CAProgram {
			out[i].ProgramLevel = true
		} else if !slices.Contains(out[i].ESPIDs, ca.ESPID) {
			if len(out[i].ESPIDs) == 64 {
				return nil, false
			}
			out[i].ESPIDs = append(out[i].ESPIDs, ca.ESPID)
		}
	}
	for i := range out {
		slices.Sort(out[i].ESPIDs)
	}
	slices.SortFunc(out, func(a, b model.DVBDescramblingCandidate) int {
		if a.CAID < b.CAID {
			return -1
		}
		if a.CAID > b.CAID {
			return 1
		}
		return int(a.ECMPID) - int(b.ECMPID)
	})
	return out, true
}

func (s *Store) descramblingStatusForStream(st model.Stream) model.DVBDescramblingStatus {
	base := descramblingBaseRuntime(st)
	status := model.DVBDescramblingStatus{Backend: cachedDescramblingBuildBackend(), Candidates: []model.DVBDescramblingCandidate{}, Policy: st.DVBDescrambling.Clone(), State: base.State, Reason: base.Reason}
	if st.Runtime.Descrambling != nil {
		switch st.Runtime.Descrambling.State {
		case "unsupported", "capacity", "waiting_route":
			status.State, status.Reason = st.Runtime.Descrambling.State, st.Runtime.Descrambling.Reason
		}
	}
	s.mu.RLock()
	var profile model.Softcam
	if i := s.findSoftcamIndexLocked(st.SoftcamID); i >= 0 {
		profile = s.config.Softcams[i]
	}
	s.mu.RUnlock()
	if st.Enabled && s.scheduler != nil {
		s.scheduler.describeDescrambling(st, &status, time.Now())
	}
	if !st.Enabled || !descramblingEnabled(st) {
		status.State, status.Reason = base.State, base.Reason
	} else if err := validateDVBDescrambling(st, profile, true); err != nil {
		status.State, status.Reason = "unsupported", "policy_invalid"
		if profile.ID == "" || !profile.Enabled || normalizeSoftcamType(profile.Type) != "cccam" && normalizeSoftcamType(profile.Type) != "newcamd" {
			status.Reason = "profile_unavailable"
		}
	} else if !status.Backend.Available && status.Reason != "catalog_stale" && status.Reason != "catalog_missing" && status.Reason != "input_closed" {
		status.State, status.Reason = "unsupported", "backend_unavailable"
	}
	if !s.streamSnapshotIsCurrent(st) {
		status.Identity = nil
		status.Candidates = []model.DVBDescramblingCandidate{}
		status.State, status.Reason = "waiting_psi", "stale_attachment"
		status.Metrics = model.DVBDescramblingMetrics{SampleStale: true}
	}
	return status
}

func (s *dvbScheduler) describeDescrambling(st model.Stream, status *model.DVBDescramblingStatus, now time.Time) {
	end, err := s.admit()
	if err != nil {
		status.Reason = "input_closed"
		return
	}
	defer end()
	s.mu.Lock()
	a := s.attachments[st.ID]
	if a == nil || a.retiring || a.session.runtime == nil || !sameStructuredApplied(a.stream, st) || !a.session.runtime.ready || a.session.runtime.closing || a.session.runtime.retiring {
		s.mu.Unlock()
		return
	}
	r := a.session.runtime
	catalog, inputID, generation, output := r.catalog, a.session.id, r.inputGeneration, a.outputSource
	s.mu.Unlock()
	if catalog == nil {
		return
	}
	service, stamp, state := catalog.MetadataSnapshot(uint16(st.DVB.ServiceID), now)
	switch state {
	case "missing":
		status.State, status.Reason = "waiting_psi", "catalog_missing"
	case "stale":
		status.State, status.Reason = "waiting_psi", "catalog_stale"
	case "closed":
		status.State, status.Reason = "waiting_psi", "input_closed"
	case "ready":
		status.Identity = &model.DVBDescramblingIdentity{InputID: inputID, InputGeneration: generation, ONID: service.ONID, TSID: service.TSID, ServiceID: service.SID}
		var valid bool
		status.Candidates, valid = descramblingCandidates(service)
		if !valid {
			status.Candidates = []model.DVBDescramblingCandidate{}
			status.State, status.Reason = "waiting_route", "unsupported_ca_layout"
		} else if len(status.Candidates) == 0 {
			status.State, status.Reason = "waiting_route", "no_ca_descriptors"
		} else if descramblingEnabled(st) {
			if _, err := mpegts.ResolveRoute(service, *st.DVBDescrambling); err != nil {
				status.State, status.Reason = "waiting_route", "unsupported_ca_layout"
			} else if reader, ok := output.(descramblingStatusReader); ok {
				sample, fresh := reader.DescramblingStatus()
				status.Metrics = model.DVBDescramblingMetrics{Queued: sample.Queued, OutputQueued: sample.OutputQueued, Processed: sample.Processed, Dropped: sample.Dropped, SampleStale: !fresh, SampleAgeMS: sample.SampleAgeMS}
				switch sample.State {
				case "waiting_keys", "keys_ready":
					status.State, status.Reason = "waiting_keys", "waiting_keys"
				case "key_expired", "partial_clear", "payload_processed":
					status.State, status.Reason = sample.State, sample.State
				case "closed":
					status.State, status.Reason = "stopped", "input_closed"
				case "cipher_failed":
					status.State, status.Reason = "unsupported", "cipher_failed"
				default:
					status.State, status.Reason = "unsupported", "pipeline_unavailable"
				}
			} else {
				status.State, status.Reason = "unsupported", "pipeline_unavailable"
			}
		}
	}
	// Never associate a sample with a replacement input or output owner.
	s.mu.Lock()
	current := s.attachments[st.ID] == a && !a.retiring && a.session.runtime == r && r.ready && !r.retiring && !r.closing && a.outputSource == output
	s.mu.Unlock()
	if state == "ready" {
		current = current && catalog.Current(stamp, time.Now())
		if source, ok := output.(*dvbDescramblingSource); ok {
			current = current && source.tap.stamp == stamp
		}
	}
	if !current {
		status.Identity = nil
		status.Candidates = []model.DVBDescramblingCandidate{}
		status.State, status.Reason = "waiting_psi", "stale_attachment"
		status.Metrics = model.DVBDescramblingMetrics{SampleStale: true}
	}
}

func descramblingErrorRuntime(err error) *model.DVBDescramblingRuntime {
	if err == nil {
		return nil
	}
	state, reason := "unsupported", "pipeline_unavailable"
	var policy *model.DVBDescramblingError
	var ecm *softcam.ECMError
	switch {
	case errors.Is(err, mpegts.ErrCapacity), errors.Is(err, packetbudget.ErrCapacity):
		state, reason = "capacity", "capacity"
	case errors.Is(err, mpegts.ErrUnsupportedCALayout):
		state, reason = "waiting_route", "unsupported_ca_layout"
	case errors.As(err, &ecm):
		switch ecm.Code {
		case "ecm_capacity":
			state, reason = "capacity", "capacity"
		case "ecm_no_route", "ca_policy_conflict":
			state, reason = "waiting_route", "unsupported_ca_layout"
		case "ecm_session_unavailable":
			reason = "profile_unavailable"
		}
	case errors.As(err, &policy):
		switch policy.Code {
		case "ca_policy_conflict":
			state, reason = "waiting_route", "unsupported_ca_layout"
		case "waiting_psi":
			state, reason = "waiting_psi", "catalog_missing"
		case "backend_unavailable", "pipeline_unavailable", "sink_unavailable", "unsupported_descrambling_output":
			reason = policy.Code
		default:
			reason = "policy_invalid"
		}
	}
	return &model.DVBDescramblingRuntime{State: state, Reason: reason}
}
