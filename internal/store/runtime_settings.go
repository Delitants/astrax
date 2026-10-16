// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

// Settings invalidate collectors before waiting on the same per-session
// publication barriers. Empty upsert clears data without tombstoning a session
// that may collect again after re-enabling DVB EPG.
func (s *Store) clearDisabledDVBContributions() {
	if s.runtimeDeps == nil {
		return
	}
	if s.scheduler != nil {
		for _, snapshot := range s.scheduler.sessionSnapshots() {
			err := s.scheduler.publishSessionSnapshot(snapshot, func() error {
				return s.runtimeDeps.UpsertDVBContribution(dvbEPGContributionKey{SessionID: snapshot.SessionID, Generation: snapshot.Generation}, nil, nil)
			})
			s.reportSessionWorkerError(snapshot, err)
		}
	}
	s.mu.RLock()
	workers := make([]*adapterMonitorWorker, 0, len(s.adapterWork))
	for _, w := range s.adapterWork {
		workers = append(workers, w)
	}
	s.mu.RUnlock()
	for _, w := range workers {
		w.epgPublishMu.Lock()
		s.mu.RLock()
		generation := w.generation
		current := s.adapterWork[w.profile.ID] == w && !nilDVBSession(w.session)
		s.mu.RUnlock()
		if current && generation != 0 {
			if err := s.runtimeDeps.UpsertDVBContribution(dvbEPGContributionKey{SessionID: "legacy:" + w.profile.ID, Generation: generation}, nil, nil); err != nil {
				s.AddLog("error", "clear legacy EPG: "+err.Error())
			}
		}
		w.epgPublishMu.Unlock()
	}
}
