// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"reflect"

	"astrax/internal/model"
)

// Notifications are synchronous, joined by the initiating lifecycle admission,
// and ordered independently of configuration publication. No callback runs with
// Store.mu, scheduler.mu or the card configuration gate held.
func (s *Store) installCardApplications(updates []dvbCardApplicationUpdate) {
	if len(updates) == 0 {
		return
	}
	s.mu.Lock()
	if s.cardApplications == nil {
		s.cardApplications = make(map[string]dvbCardApplicationUpdate)
	}
	var events dvbEventBatch
	for _, u := range updates {
		old, exists := s.cardApplications[u.id]
		if exists && old.serial >= u.serial {
			continue
		}
		s.cardApplications[u.id] = u
		if !exists || !reflect.DeepEqual(old.application, u.application) || !reflect.DeepEqual(old.card, u.card) {
			s.queueCardApplicationLocked(&events, u.id)
		}
	}
	s.dvbRefreshStateMu.Lock()
	s.dvbLastSummary = summarizeDVBCards(s.mergeDVBCardsLocked())
	s.dvbRefreshStateMu.Unlock()
	s.mu.Unlock()
	events.emit(s)
}

// Store.mu orders the snapshot and its resource revision with every metadata
// and ownership commit. Observers must not run until the caller releases locks.
func (s *Store) queueCardApplicationLocked(events *dvbEventBatch, id string) {
	for _, row := range s.mergeDVBCardsLocked() {
		if row.card.ID == id {
			events.add(s, "dvb.card.changed", id, cloneDVBCard(row.card))
			return
		}
	}
	events.add(s, "dvb.card.removed", id, nil)
}

func (s *Store) queueCardOwnershipLocked(events *dvbEventBatch, id string, ownership dvbCardOwnership) {
	ownership = cloneDVBCardOwnership(ownership)
	for _, row := range s.mergeDVBCardsLocked() {
		if row.card.ID == id {
			ownership.Application = cloneDVBCard(row.card).Application
			break
		}
	}
	events.add(s, "dvb.card.changed", id, ownership)
}

func (s *Store) queueCardInventoryLocked(events *dvbEventBatch, before, after []mergedDVBCard) {
	old := make(map[string]model.DVBCard, len(before))
	for _, row := range before {
		old[row.card.ID] = row.card
	}
	changed := false
	for _, row := range after {
		previous, exists := old[row.card.ID]
		if !exists || !reflect.DeepEqual(previous, row.card) {
			events.add(s, "dvb.card.changed", row.card.ID, cloneDVBCard(row.card))
			changed = true
		}
		delete(old, row.card.ID)
	}
	// Keep detected/configuration order, including cards absent from the new view.
	for _, row := range before {
		if _, removed := old[row.card.ID]; removed {
			events.add(s, "dvb.card.removed", row.card.ID, nil)
			changed = true
		}
	}
	if changed {
		events.add(s, "dvb.collection.changed", "", model.DVBInvalidation{Cards: true})
	}
}
