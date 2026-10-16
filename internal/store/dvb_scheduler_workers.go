// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"context"
	"fmt"

	"astrax/internal/dvb"
	"astrax/internal/model"
	"astrax/internal/mpegts"
)

type dvbAttachmentSnapshot struct {
	ID           string
	Generation   uint64
	Stream       model.Stream
	baseSource   *streamPacketSource
	outputSource model.PacketSource
}
type dvbSessionSnapshot struct {
	Card                     model.DVBCard
	Transport                *model.DVBStreamConfig
	SessionID                string
	Generation, CardRevision uint64
	InputGeneration          uint64
	catalog                  *mpegts.Catalog
	Attachments              []dvbAttachmentSnapshot
	session                  *tuningSession
}

func (s *dvbScheduler) sessionSnapshots() []dvbSessionSnapshot {
	end, err := s.admit()
	if err != nil {
		return nil
	}
	defer end()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health != nil {
		return nil
	}
	out := make([]dvbSessionSnapshot, 0, len(s.sessions))
	for _, session := range s.sessions {
		r := session.runtime
		if r == nil || !r.ready || r.retiring || r.closing || !session.healthy {
			continue
		}
		snapshot := dvbSessionSnapshot{Card: cloneDVBCard(session.card), Transport: cloneDVBStreamConfig(r.transport), SessionID: session.id, Generation: r.generation, CardRevision: r.cardRevision, InputGeneration: r.inputGeneration, catalog: r.catalog, session: session}
		application := s.cardApplicationViewLocked(session.cardID).application
		snapshot.Card.Application = &application
		snapshot.Attachments = make([]dvbAttachmentSnapshot, 0, len(r.attachments))
		for _, a := range r.attachments {
			if s.counters != nil {
				s.counters.AttachmentVisits++
			}
			if !a.retiring {
				snapshot.Attachments = append(snapshot.Attachments, dvbAttachmentSnapshot{ID: a.id, Generation: a.generation, Stream: cloneStream(a.stream), baseSource: a.baseSource, outputSource: a.outputSource})
			}
		}
		out = append(out, snapshot)
	}
	return out
}
func (s *dvbScheduler) validateWorkerSnapshotLocked(snapshot dvbSessionSnapshot) error {
	if s.health != nil {
		return s.health
	}
	session := snapshot.session
	if session == nil || session.runtime == nil || s.isClosing() {
		return ErrDVBSchedulerSuperseded
	}
	r := session.runtime
	if s.sessions[snapshot.SessionID] != session || !r.ready || r.retiring || r.closing ||
		r.generation != snapshot.Generation || r.cardRevision != snapshot.CardRevision ||
		r.inputGeneration != snapshot.InputGeneration || r.catalog != snapshot.catalog {
		return ErrDVBSchedulerSuperseded
	}
	// A retired/replaced lease is ordinary staleness. Once its primary owner and
	// generations still match, broken reverse indexes are current corruption.
	if !s.sessionValidLocked(session) {
		return s.latchCorruptLocked(fmt.Errorf("current worker session %q ownership mismatch", session.id))
	}
	for _, entry := range snapshot.Attachments {
		a, owned := s.attachments[entry.ID], r.attachments[entry.ID]
		if s.counters != nil {
			s.counters.AttachmentVisits++
		}
		current := a != nil && !a.retiring && a.session == session && a.generation == entry.Generation &&
			a.baseSource == entry.baseSource && a.outputSource == entry.outputSource
		ownedCurrent := owned != nil && !owned.retiring && owned.session == session && owned.generation == entry.Generation
		if a != owned && (current || ownedCurrent) {
			return s.latchCorruptLocked(fmt.Errorf("current worker attachment %q indexes disagree", entry.ID))
		}
		if !current {
			return ErrDVBSchedulerSuperseded
		}
		if !s.attachmentCoherentLocked(a) {
			return s.latchCorruptLocked(fmt.Errorf("current worker attachment %q ownership mismatch", entry.ID))
		}
	}
	return nil
}

// Calls are synchronous leases, not cancellable goroutine wrappers around context-free I/O.
func (s *dvbScheduler) withSessionCall(snapshot dvbSessionSnapshot, call func(dvb.Session) error) error {
	end, err := s.admit()
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	if err := s.validateWorkerSnapshotLocked(snapshot); err != nil {
		s.mu.Unlock()
		return err
	}
	r := snapshot.session.runtime
	r.workMu.Lock()
	if r.workStopped {
		r.workMu.Unlock()
		s.mu.Unlock()
		return ErrDVBSchedulerSuperseded
	}
	r.workCalls++
	frontend := r.frontend
	r.workMu.Unlock()
	s.mu.Unlock()
	defer func() {
		r.workMu.Lock()
		r.workCalls--
		if r.workCalls == 0 {
			r.workCond.Broadcast()
		}
		r.workMu.Unlock()
	}()
	return call(frontend)
}

// A stable reference is retained before waiting for the gate. No scheduler lock
// is held while a publisher or removal callback executes.
func (s *dvbScheduler) publishSessionSnapshot(snapshot dvbSessionSnapshot, publish func() error) error {
	end, err := s.admit()
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	if err := s.validateWorkerSnapshotLocked(snapshot); err != nil {
		s.mu.Unlock()
		return err
	}
	r := snapshot.session.runtime
	r.publicationRefs++
	s.mu.Unlock()
	r.publicationMu.Lock()
	defer func() { r.publicationMu.Unlock(); s.mu.Lock(); r.publicationRefs--; s.mu.Unlock() }()
	s.mu.Lock()
	validErr := s.validateWorkerSnapshotLocked(snapshot)
	s.mu.Unlock()
	if validErr != nil {
		return validErr
	}
	return publish()
}
func (s *dvbScheduler) launchSessionWorker(snapshot dvbSessionSnapshot, run func(context.Context, dvbSessionSnapshot)) error {
	end, err := s.admit()
	if err != nil {
		return err
	}
	defer end()
	s.mu.Lock()
	if err := s.validateWorkerSnapshotLocked(snapshot); err != nil {
		s.mu.Unlock()
		return err
	}
	r := snapshot.session.runtime
	r.workMu.Lock()
	if r.workStopped {
		r.workMu.Unlock()
		s.mu.Unlock()
		return ErrDVBSchedulerSuperseded
	}
	r.workers.Add(1)
	r.workMu.Unlock()
	s.mu.Unlock()
	go func() { defer r.workers.Done(); run(r.ctx, snapshot) }()
	return nil
}
func waitSessionCalls(session *tuningSession, stop bool) {
	r := session.runtime
	r.workMu.Lock()
	if stop {
		r.workStopped = true
		r.cancel()
	}
	for r.workCalls != 0 {
		r.workCond.Wait()
	}
	r.workMu.Unlock()
	if stop {
		r.workers.Wait()
	}
}
