// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"astrax/internal/dvb"
	"astrax/internal/epg"
	"astrax/internal/model"
)

type sessionRuntimeJobs struct {
	settingsGeneration uint64
	snapshot           dvbSessionSnapshot
	signal, eit        bool
	nextEIT            time.Time
	mapping            tuningKey
}
type sessionRuntimeWorkers struct {
	mu   sync.Mutex
	jobs map[dvbEPGContributionKey]*sessionRuntimeJobs
}
type storeAttachmentSample struct {
	stream                              model.Stream
	configGeneration, runtimeGeneration uint64
}

func (s *Store) captureAttachmentSamples(snapshot dvbSessionSnapshot) []storeAttachmentSample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]storeAttachmentSample, 0, len(snapshot.Attachments))
	for _, a := range snapshot.Attachments {
		row, exists := s.currentStructuredLocked(a.ID)
		owner := s.structured.owners[a.ID]
		if exists && row.Enabled && owner.active && sameStructuredApplied(row, a.Stream) {
			out = append(out, storeAttachmentSample{row, s.structured.configs[a.ID], owner.generation})
		}
	}
	return out
}
func (s *Store) sampleCurrentLocked(sample storeAttachmentSample) bool {
	owner := s.structured.owners[sample.stream.ID]
	return owner.active && owner.generation == sample.runtimeGeneration && s.structured.configs[sample.stream.ID] == sample.configGeneration
}
func (s *Store) updateStructuredSessionWorkers() {
	if s.scheduler == nil || s.runtimeDeps == nil || s.runtimeClosing() {
		return
	}
	s.mu.RLock()
	settings := s.config.Settings
	settingsGeneration := s.epgSettingsGeneration
	s.mu.RUnlock()
	snapshots := s.scheduler.sessionSnapshots()
	for _, snapshot := range snapshots {
		samples := s.captureAttachmentSamples(snapshot)
		key := dvbEPGContributionKey{SessionID: snapshot.SessionID, Generation: snapshot.Generation}
		w := &s.sessionWorkers
		w.mu.Lock()
		if w.jobs == nil {
			w.jobs = make(map[dvbEPGContributionKey]*sessionRuntimeJobs)
		}
		job := w.jobs[key]
		if job == nil {
			job = &sessionRuntimeJobs{}
			w.jobs[key] = job
		}
		job.snapshot = snapshot
		signal := !job.signal
		if signal {
			job.signal = true
		}
		// Mapping changes, including new attachments, trigger a fresh contribution.
		rows := make([]model.Stream, 0, len(samples))
		for _, sample := range samples {
			rows = append(rows, sample.stream)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		mapping := sessionEPGMapping(rows)
		eit := settings.EPGFromDVB && !job.eit && (settingsGeneration != job.settingsGeneration || mapping != job.mapping || !s.now().Before(job.nextEIT))
		if eit {
			job.eit = true
			job.mapping = mapping
			job.settingsGeneration = settingsGeneration
		}
		w.mu.Unlock()
		if signal {
			err := s.scheduler.launchSessionWorker(snapshot, func(ctx context.Context, snapshot dvbSessionSnapshot) {
				defer func() { w.mu.Lock(); job.signal = false; w.mu.Unlock() }()
				if ctx.Err() != nil {
					return
				}
				s.sampleSessionSignal(snapshot, samples)
			})
			if err != nil {
				w.mu.Lock()
				job.signal = false
				w.mu.Unlock()
				s.reportSessionWorkerError(snapshot, err)
			}
		}
		if eit {
			err := s.scheduler.launchSessionWorker(snapshot, func(ctx context.Context, snapshot dvbSessionSnapshot) {
				defer func() {
					w.mu.Lock()
					job.eit = false
					interval := time.Duration(settings.EPGDVBIntervalSec) * time.Second
					if interval <= 0 {
						interval = 15 * time.Minute
					}
					job.nextEIT = s.now().Add(interval)
					w.mu.Unlock()
				}()
				if ctx.Err() != nil {
					return
				}
				s.collectSessionEIT(snapshot, samples, settings.EPGDVBDepth, settingsGeneration)
			})
			if err != nil {
				w.mu.Lock()
				job.eit = false
				w.mu.Unlock()
				s.reportSessionWorkerError(snapshot, err)
			}
		}
	}
}
func sessionEPGMapping(rows []model.Stream) tuningKey {
	// Exclude sampled Runtime and time-varying metadata from collector scheduling.
	for i := range rows {
		rows[i].Runtime = model.StreamRuntime{}
		rows[i].UpdatedAt = time.Time{}
	}
	return hashRuntimeValue(rows)
}
func (s *Store) sampleSessionSignal(snapshot dvbSessionSnapshot, samples []storeAttachmentSample) {
	var signal dvb.Signal
	pollErr := s.scheduler.withSessionCall(snapshot, func(frontend dvb.Session) error { var err error; signal, err = frontend.Poll(); return err })
	if errors.Is(pollErr, ErrDVBSchedulerSuperseded) || errors.Is(pollErr, ErrDVBSchedulerClosed) {
		return
	}
	if errors.Is(pollErr, ErrDVBSchedulerCorrupt) {
		s.reportSessionWorkerError(snapshot, pollErr)
		return
	}
	packets := make(map[string]uint64, len(samples))
	descrambling := make(map[string]*model.DVBDescramblingRuntime)
	for _, sample := range samples {
		packets[sample.stream.ID] = s.runtimeSink.StreamPackets(sample.stream.ID)
		if sample.stream.DVBDescrambling != nil {
			descrambling[sample.stream.ID] = s.descramblingStatusForStream(sample.stream).Runtime()
		}
	}
	var events dvbEventBatch
	err := s.scheduler.publishSessionSnapshot(snapshot, func() error {
		now := s.now().UTC()
		sig := &model.DVBSignal{Locked: signal.Locked, SignalPercent: signal.SignalPercent, SNRPercent: signal.SNRPercent, BER: signal.BER, UncorrectedBlocks: signal.UncorrectedBlocks, StatusBits: signal.StatusBits}
		diagnostic := ""
		if pollErr != nil {
			diagnostic = pollErr.Error()
			sig = nil
		}
		ownership := dvbCardOwnership{CurrentTransport: cloneDVBStreamConfig(snapshot.Transport), ActiveSessions: 1, ActiveStreams: len(snapshot.Attachments), Signal: sig, LastError: diagnostic}
		s.mu.Lock()
		if u, ok := s.cardApplications[snapshot.Card.ID]; ok {
			ownership.Application = cloneDVBCard(model.DVBCard{Application: &u.application}).Application
		}
		s.dvbOwnership[snapshot.Card.DeviceKey] = cloneDVBCardOwnership(ownership)
		s.queueCardOwnershipLocked(&events, snapshot.Card.ID, ownership)
		for _, sample := range samples {
			if !s.sampleCurrentLocked(sample) {
				continue
			}
			id := sample.stream.ID
			rt := s.runtime[id]
			old := cloneStreamRuntime(rt)
			count := packets[id]
			delta := uint64(0)
			if count >= rt.Packets {
				delta = count - rt.Packets
			}
			owner := s.structured.owners[id]
			seconds := now.Sub(owner.sampledAt).Seconds()
			if owner.sampledAt.IsZero() || seconds <= 0 {
				seconds = .5
			}
			rt.Signal = cloneDVBSignal(sig)
			rt.Descrambling = descrambling[id].Clone()
			rt.Packets = count
			rt.BitrateKbps = int(float64(delta*188*8) / 1000 / seconds)
			rt.LastError = diagnostic
			switch {
			case pollErr != nil:
				rt.State = "error"
			case !signal.Locked:
				rt.State = "tuning"
				rt.LastError = "frontend has no lock"
			case delta > 0:
				rt.State = "running"
			default:
				rt.State = "locked"
			}
			if old.State != rt.State {
				rt.Since = now
			}
			owner.sampledAt = now
			s.structured.owners[id] = owner
			s.runtime[id] = rt
			if !reflect.DeepEqual(old, rt) {
				events.add(s, "dvb.stream.changed", id, cloneStreamRuntime(rt))
			}
		}
		s.mu.Unlock()

		return nil
	})
	events.emit(s)
	s.reportSessionWorkerError(snapshot, err)
}
func mapSessionEPG(samples []storeAttachmentSample, programmes []epg.Programme) ([]epg.Channel, []epg.Programme) {
	ordered := append([]storeAttachmentSample(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].stream.ID < ordered[j].stream.ID })
	byService := make(map[string][]model.Stream)
	channels := make([]epg.Channel, 0, len(samples))
	seen := make(map[string]bool)
	for _, sample := range ordered {
		st := sample.stream
		if st.XMLTVChannelID == "" {
			continue
		}
		sid := fmt.Sprintf("0x%04X", st.DVB.ServiceID)
		byService[sid] = append(byService[sid], st)
		if !seen[st.XMLTVChannelID] {
			seen[st.XMLTVChannelID] = true
			channels = append(channels, epg.Channel{ID: st.XMLTVChannelID, DisplayName: []epg.DisplayName{{Value: st.Name}}})
		}
	}
	mapped := make([]epg.Programme, 0, len(programmes))
	for _, programme := range programmes {
		for _, st := range byService[programme.Channel] {
			p := programme
			p.Channel = st.XMLTVChannelID
			mapped = append(mapped, p)
		}
	}
	return channels, mapped
}
func (s *Store) collectSessionEIT(snapshot dvbSessionSnapshot, samples []storeAttachmentSample, depth string, settingsGeneration uint64) {
	if depth == "" {
		depth = "present_following"
	}
	var programmes []epg.Programme
	var err error
	if len(samples) != 0 {
		err = s.scheduler.withSessionCall(snapshot, func(frontend dvb.Session) error {
			var err error
			programmes, err = s.runtimeDeps.CollectEIT(frontend, depth)
			return err
		})
	}
	if err != nil {
		s.reportSessionWorkerError(snapshot, err)
		return
	}
	channels, mapped := mapSessionEPG(samples, programmes)
	err = s.scheduler.publishSessionSnapshot(snapshot, func() error {
		s.mu.RLock()
		valid := s.config.Settings.EPGFromDVB && s.epgSettingsGeneration == settingsGeneration
		for _, sample := range samples {
			if !s.sampleCurrentLocked(sample) {
				valid = false
				break
			}
		}
		s.mu.RUnlock()
		if !valid {
			return ErrDVBSchedulerSuperseded
		}
		return s.runtimeDeps.UpsertDVBContribution(dvbEPGContributionKey{SessionID: snapshot.SessionID, Generation: snapshot.Generation}, channels, mapped)
	})
	s.reportSessionWorkerError(snapshot, err)
}
func (s *Store) reportSessionWorkerError(snapshot dvbSessionSnapshot, err error) {
	if err == nil || errors.Is(err, ErrDVBSchedulerSuperseded) || errors.Is(err, ErrDVBSchedulerClosed) {
		return
	}
	s.AddLog("error", fmt.Sprintf("DVB session %s generation %d: %v", snapshot.SessionID, snapshot.Generation, err))
}
func (s *Store) removeSessionPublication(id string, generation uint64) error {
	key := dvbEPGContributionKey{SessionID: id, Generation: generation}
	w := &s.sessionWorkers
	w.mu.Lock()
	job := w.jobs[key]
	delete(w.jobs, key)
	w.mu.Unlock()
	if job != nil {
		var events dvbEventBatch
		s.mu.Lock()
		if _, exists := s.dvbOwnership[job.snapshot.Card.DeviceKey]; exists {
			delete(s.dvbOwnership, job.snapshot.Card.DeviceKey)
			s.queueCardOwnershipLocked(&events, job.snapshot.Card.ID, dvbCardOwnership{})
		}
		for _, a := range job.snapshot.Attachments {
			rt := s.runtime[a.ID]
			if rt.Placement != nil && rt.Placement.TuningSessionID == id {
				rt.Signal = nil
				rt.Placement = nil
				rt.State = "stopped"
				rt.Packets = 0
				rt.BitrateKbps = 0
				s.runtime[a.ID] = rt
				if s.findStreamIndexLocked(a.ID) >= 0 {
					events.add(s, "dvb.stream.changed", a.ID, cloneStreamRuntime(rt))
				}
			}
		}
		s.mu.Unlock()
		events.emit(s)
	}
	return s.runtimeDeps.RemoveDVBContribution(key)
}
